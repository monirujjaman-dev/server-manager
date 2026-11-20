package modules

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/internal/command"
)

// The privileged helper manages exactly one swapfile, at a fixed path. Swap devices it
// did not create are reported but never changed.
//
// It writes only inside its own state directory. The package ships the systemd swap
// unit (/usr/lib/systemd/system/var-lib-smswap-swapfile.swap, conditional on the file
// existing) and /etc/sysctl.d/90-sm-swappiness.conf as a symlink into the state
// directory. The helper enables and starts the unit over D-Bus, so systemd performs
// swapon and writes the enablement symlink; the helper needs neither CAP_SYS_ADMIN nor
// write access to /etc.
const (
	ManagedSwapDir  = "/var/lib/smswap"
	ManagedSwapFile = ManagedSwapDir + "/swapfile"
	// SwapUnit is the systemd unit for ManagedSwapFile; its name is the escaped path.
	SwapUnit = "var-lib-smswap-swapfile.swap"
	// swappinessConf is in the state directory; /etc/sysctl.d links to it.
	swappinessConf = "swappiness.conf"
	sysctlService  = "systemd-sysctl.service"
)

// SwapStatus implements swap.status from /proc.
func (h Host) SwapStatus() (*agentv1.SwapStatusResult, error) {
	b, err := os.ReadFile(h.proc("swaps"))
	if err != nil {
		return nil, err
	}
	out := &agentv1.SwapStatusResult{Devices: parseSwaps(b), ManagedPath: ManagedSwapFile}
	out.Swappiness, _ = h.swappiness()
	for _, d := range out.GetDevices() {
		if d.GetPath() == ManagedSwapFile {
			out.ManagedActive, out.ManagedSizeBytes = true, d.GetSizeBytes()
		}
	}
	if !out.GetManagedActive() {
		if fi, err := os.Stat(ManagedSwapFile); err == nil {
			out.ManagedSizeBytes = uint64(fi.Size()) //nolint:gosec // file sizes are non-negative
		}
	}
	return out, nil
}

func (h Host) swappiness() (uint32, error) {
	v, err := os.ReadFile(h.proc("sys", "vm", "swappiness"))
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(v)), 10, 32)
	return uint32(n), err
}

// parseSwaps reads /proc/swaps: "Filename Type Size(KiB) Used(KiB) Priority".
func parseSwaps(b []byte) []*agentv1.SwapDevice {
	var out []*agentv1.SwapDevice
	sc := bufio.NewScanner(bytes.NewReader(b))
	for first := true; sc.Scan(); first = false {
		f := strings.Fields(sc.Text())
		if first || len(f) < 5 {
			continue
		}
		size, _ := strconv.ParseUint(f[2], 10, 64)
		used, _ := strconv.ParseUint(f[3], 10, 64)
		prio, _ := strconv.ParseInt(f[4], 10, 32)
		out = append(out, &agentv1.SwapDevice{
			Path: unescapeMount(f[0]), Type: f[1], SizeBytes: size << 10, UsedBytes: used << 10, Priority: int32(prio),
		})
	}
	return out
}

// UnitManager is the part of systemd swap management needs; tests provide a fake.
type UnitManager interface {
	Control(ctx context.Context, unit string, op agentv1.ServiceOperation) error
	Reload(ctx context.Context) error
}

// Swapper performs swap changes as root. Operations are serialised: the agent runs
// several commands at once and two swap changes must never interleave.
type Swapper struct {
	Host  Host
	Units UnitManager
	// Dir holds the swapfile and the swappiness setting. Tests use a temporary directory.
	Dir string
	// AnyFilesystem skips the ext4/xfs check (tests only).
	AnyFilesystem bool
	// MinReserveBytes and ReservePercent set the free space that must remain on the
	// filesystem after creating the swapfile: the larger of the two.
	MinReserveBytes uint64
	ReservePercent  uint64

	mu sync.Mutex
}

// NewSwapper returns a Swapper for the real system.
func NewSwapper(h Host, units UnitManager) *Swapper {
	return &Swapper{Host: h, Units: units, Dir: ManagedSwapDir, MinReserveBytes: 1 << 30, ReservePercent: 10}
}

func (s *Swapper) file() string { return filepath.Join(s.Dir, "swapfile") }

// managed reports whether the swapfile exists. Anything but "does not exist" is an
// error, and an existing file must be a root-controlled regular file before it is
// turned off, replaced or deleted.
func (s *Swapper) managed() (bool, error) {
	fi, err := os.Lstat(s.file())
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 {
		return false, fmt.Errorf("%s is not a regular file with mode 0600; fix or remove it by hand", s.file())
	}
	return true, nil
}

// Configure implements swap.configure.
func (s *Swapper) Configure(ctx context.Context, req *agentv1.SwapConfigureRequest) (*agentv1.SwapStatusResult, error) {
	if err := command.Validate(&agentv1.ActionRequest{Action: &agentv1.ActionRequest_SwapConfigure{SwapConfigure: req}}); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exists, err := s.managed()
	if err != nil {
		return nil, err
	}
	size := uint64(req.GetSizeMib()) << 20
	switch req.GetOperation() {
	case agentv1.SwapOperation_SWAP_OPERATION_CREATE:
		if exists {
			return nil, errors.New("the managed swapfile already exists; resize or remove it")
		}
		if err := s.checkSpace(size, 0); err != nil {
			return nil, err
		}
		if err := s.createAndActivate(ctx, size); err != nil {
			return nil, err
		}
	case agentv1.SwapOperation_SWAP_OPERATION_RESIZE:
		if !exists {
			return nil, errors.New("there is no managed swapfile to resize; create one")
		}
		// Check before anything is torn down; the old file's space comes back.
		fi, err := os.Stat(s.file())
		if err != nil {
			return nil, err
		}
		if err := s.checkSpace(size, uint64(fi.Size())); err != nil { //nolint:gosec // non-negative
			return nil, err
		}
		if err := s.deactivate(ctx); err != nil {
			return nil, err
		}
		if err := removeSynced(s.file()); err != nil {
			return nil, err
		}
		if err := s.createAndActivate(ctx, size); err != nil {
			return nil, err
		}
	case agentv1.SwapOperation_SWAP_OPERATION_REMOVE:
		if !exists {
			return nil, errors.New("there is no managed swapfile")
		}
		if err := s.deactivate(ctx); err != nil {
			return nil, err
		}
		if err := s.Units.Control(ctx, SwapUnit, agentv1.ServiceOperation_SERVICE_OPERATION_DISABLE); err != nil {
			return nil, fmt.Errorf("disable %s: %w", SwapUnit, err)
		}
		if err := removeSynced(s.file()); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("invalid swap operation")
	}
	return s.status()
}

// SetSwappiness implements swap.set_swappiness: it saves the value where
// /etc/sysctl.d/90-sm-swappiness.conf points, re-runs systemd-sysctl (the helper's
// sandbox keeps /proc/sys read-only) and checks the running value.
func (s *Swapper) SetSwappiness(ctx context.Context, req *agentv1.SwapSetSwappinessRequest) (*agentv1.SwapStatusResult, error) {
	want := req.GetSwappiness()
	if want > 100 {
		return nil, errors.New("swappiness must be 0-100")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	conf := filepath.Join(s.Dir, swappinessConf)
	content := fmt.Sprintf("# Managed by Server Manager (smctl swap swappiness).\nvm.swappiness = %d\n", want)
	if err := writeFileAtomic(conf, []byte(content), 0o644); err != nil {
		return nil, err
	}
	applyErr := s.Units.Control(ctx, sysctlService, agentv1.ServiceOperation_SERVICE_OPERATION_RESTART)
	if got, err := s.Host.swappiness(); err != nil || got != want {
		why := "another file in /etc/sysctl.d or /etc/sysctl.conf may set vm.swappiness later"
		if applyErr != nil {
			why = "applying failed: " + applyErr.Error()
		}
		return nil, fmt.Errorf("vm.swappiness = %d is saved and applies at boot, but the running value is %d (%s)", want, got, why)
	}
	return s.status()
}

func (s *Swapper) status() (*agentv1.SwapStatusResult, error) {
	st, err := s.Host.SwapStatus()
	if err != nil {
		return nil, err
	}
	st.ManagedPath, st.ManagedSizeBytes = s.file(), 0
	for _, d := range st.GetDevices() {
		if d.GetPath() == s.file() {
			st.ManagedSizeBytes = d.GetSizeBytes()
		}
	}
	if fi, err := os.Stat(s.file()); err == nil && !st.GetManagedActive() {
		st.ManagedSizeBytes = uint64(fi.Size()) //nolint:gosec // non-negative
	}
	return st, nil
}

// checkSpace refuses a swapfile that would leave less than the reserve free. freed is
// space that becomes available first (the old file on resize).
func (s *Swapper) checkSpace(size, freed uint64) error {
	if err := os.MkdirAll(s.Dir, 0o755); err != nil { //nolint:gosec // the file inside is 0600
		return err
	}
	fs, err := statfs(s.Dir)
	if err != nil {
		return err
	}
	if !s.AnyFilesystem && fs.fsType != fsMagicExt4 && fs.fsType != fsMagicXFS {
		return errors.New("swapfiles are only supported on ext4 and xfs here (btrfs and others need special handling)")
	}
	reserve := max(s.MinReserveBytes, fs.total/100*s.ReservePercent)
	if avail := fs.avail + freed; avail < size+reserve {
		return fmt.Errorf("not enough free space in %s: %d MiB available, %d MiB needed (%d MiB must stay free)",
			s.Dir, avail>>20, (size+reserve)>>20, reserve>>20)
	}
	return nil
}

// createAndActivate creates the swapfile and starts its unit. On failure it undoes what
// it did, so the next attempt starts clean.
func (s *Swapper) createAndActivate(ctx context.Context, size uint64) error {
	if err := s.create(size); err != nil {
		return err
	}
	err := s.Units.Control(ctx, SwapUnit, agentv1.ServiceOperation_SERVICE_OPERATION_ENABLE)
	if err == nil {
		err = s.Units.Control(ctx, SwapUnit, agentv1.ServiceOperation_SERVICE_OPERATION_START)
	}
	if err == nil {
		return nil
	}
	_ = s.Units.Control(ctx, SwapUnit, agentv1.ServiceOperation_SERVICE_OPERATION_STOP)
	_ = s.Units.Control(ctx, SwapUnit, agentv1.ServiceOperation_SERVICE_OPERATION_DISABLE)
	_ = removeSynced(s.file())
	return fmt.Errorf("activate %s (undone): %w", SwapUnit, err)
}

// deactivate turns the managed swapfile off if it is in use, refusing when the
// swapped-out memory would not fit in RAM (swapoff would push the system into the OOM
// killer).
func (s *Swapper) deactivate(ctx context.Context) error {
	st, err := s.Host.SwapStatus()
	if err != nil {
		return err
	}
	for _, d := range st.GetDevices() {
		if d.GetPath() != s.file() {
			continue
		}
		if d.GetUsedBytes() > 0 {
			info, err := s.Host.SystemInfo()
			if err != nil {
				return err
			}
			if need := d.GetUsedBytes() + 256<<20; info.GetMemoryAvailableBytes() < need {
				return fmt.Errorf("%d MiB are swapped out to %s but only %d MiB of memory are available; free memory first",
					d.GetUsedBytes()>>20, s.file(), info.GetMemoryAvailableBytes()>>20)
			}
		}
		if err := s.Units.Control(ctx, SwapUnit, agentv1.ServiceOperation_SERVICE_OPERATION_STOP); err != nil {
			return fmt.Errorf("stop %s: %w", SwapUnit, err)
		}
	}
	return nil
}

// create allocates the swapfile (no holes, mode 0600) and writes the swap header.
func (s *Swapper) create(size uint64) error {
	tmp := s.file() + ".new"
	// A leftover from an interrupted run; the directory is root-only and the operation
	// lock is held, so nobody else is writing it.
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // fixed path
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err := allocate(f, size); err != nil {
		return fmt.Errorf("allocate %d MiB: %w", size>>20, err)
	}
	if _, err := f.WriteAt(SwapHeader(size, os.Getpagesize()), 0); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	if err := os.Rename(tmp, s.file()); err != nil {
		return err
	}
	return syncDir(s.Dir)
}

// SwapHeader builds the first page of a version-1 Linux swap area of size bytes, as
// mkswap writes it: info at offset 1024 (version, last page, no bad pages, a random
// UUID) and the "SWAPSPACE2" signature at the end of the page.
func SwapHeader(size uint64, pageSize int) []byte {
	page := make([]byte, pageSize)
	pages := size / uint64(pageSize) //nolint:gosec // page size is positive
	binary.NativeEndian.PutUint32(page[1024:], 1)
	binary.NativeEndian.PutUint32(page[1028:], uint32(min(pages-1, 1<<32-1)))
	binary.NativeEndian.PutUint32(page[1032:], 0)
	_, _ = rand.Read(page[1036:1052])
	page[1036+6] = page[1036+6]&0x0f | 0x40 // UUID version 4
	page[1036+8] = page[1036+8]&0x3f | 0x80 // RFC 4122 variant
	copy(page[pageSize-10:], "SWAPSPACE2")
	return page
}

// writeFileAtomic writes through an exclusively created temporary file, fsyncs it,
// renames it into place and fsyncs the directory.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func removeSynced(path string) error {
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // our own directory
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return syncDirErr(err)
	}
	return nil
}
