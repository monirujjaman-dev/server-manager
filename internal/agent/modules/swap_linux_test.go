package modules

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
)

func testSwapper(t *testing.T, swaps string, u UnitManager) *Swapper {
	t.Helper()
	return &Swapper{Host: fakeSwapProc(t, swaps), Units: u, Dir: t.TempDir(), AnyFilesystem: true}
}

func configure(s *Swapper, o agentv1.SwapOperation, mib uint32) error {
	_, err := s.Configure(context.Background(), &agentv1.SwapConfigureRequest{Operation: o, SizeMib: mib})
	return err
}

func TestSwapLifecycle(t *testing.T) {
	u := &fakeUnits{}
	s := testSwapper(t, "", u)
	if err := configure(s, agentv1.SwapOperation_SWAP_OPERATION_RESIZE, 64); err == nil {
		t.Fatal("resize without a swapfile accepted")
	}
	if err := configure(s, agentv1.SwapOperation_SWAP_OPERATION_CREATE, 64); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(s.file())
	if err != nil || fi.Size() != 64<<20 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("swapfile %v, %v", fi, err)
	}
	if got := strings.Join(u.ops, ","); got != SwapUnit+" SERVICE_OPERATION_ENABLE,"+SwapUnit+" SERVICE_OPERATION_START" {
		t.Fatalf("ops %s", got)
	}
	if err := configure(s, agentv1.SwapOperation_SWAP_OPERATION_CREATE, 64); err == nil {
		t.Fatal("second create accepted")
	}
	u.ops = nil
	if err := configure(s, agentv1.SwapOperation_SWAP_OPERATION_RESIZE, 128); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(s.file()); fi.Size() != 128<<20 {
		t.Fatalf("resized to %d", fi.Size())
	}
	u.ops = nil
	if err := configure(s, agentv1.SwapOperation_SWAP_OPERATION_REMOVE, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.file()); err == nil {
		t.Fatal("swapfile left behind")
	}
	// Not in /proc/swaps (fake), so there is nothing to stop; only disable.
	if got := strings.Join(u.ops, ","); got != SwapUnit+" SERVICE_OPERATION_DISABLE" {
		t.Fatalf("remove ops %s", got)
	}
}

func TestSwapStopsActiveFileBeforeChanging(t *testing.T) {
	u := &fakeUnits{}
	dir := t.TempDir()
	s := &Swapper{Host: fakeSwapProc(t, filepath.Join(dir, "swapfile")+" file 65532 0 -2\n"), Units: u, Dir: dir, AnyFilesystem: true}
	if err := os.WriteFile(s.file(), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := configure(s, agentv1.SwapOperation_SWAP_OPERATION_REMOVE, 0); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(u.ops, ","); got != SwapUnit+" SERVICE_OPERATION_STOP,"+SwapUnit+" SERVICE_OPERATION_DISABLE" {
		t.Fatalf("ops %s", got)
	}
}

// failingUnits fails one operation.
type failingUnits struct {
	fakeUnits
	fail agentv1.ServiceOperation
}

func (f *failingUnits) Control(ctx context.Context, unit string, op agentv1.ServiceOperation) error {
	_ = f.fakeUnits.Control(ctx, unit, op)
	if op == f.fail {
		return errors.New("boom")
	}
	return nil
}

func TestSwapCreateIsUndoneWhenActivationFails(t *testing.T) {
	for _, op := range []agentv1.ServiceOperation{agentv1.ServiceOperation_SERVICE_OPERATION_ENABLE, agentv1.ServiceOperation_SERVICE_OPERATION_START} {
		t.Run(op.String(), func(t *testing.T) {
			u := &failingUnits{fail: op}
			s := testSwapper(t, "", u)
			err := configure(s, agentv1.SwapOperation_SWAP_OPERATION_CREATE, 64)
			if err == nil || !strings.Contains(err.Error(), "undone") {
				t.Fatalf("error = %v", err)
			}
			if entries, _ := os.ReadDir(s.Dir); len(entries) != 0 {
				t.Fatalf("left behind: %v", entries)
			}
			if !strings.Contains(strings.Join(u.ops, ","), SwapUnit+" SERVICE_OPERATION_DISABLE") {
				t.Fatalf("unit not disabled again: %v", u.ops)
			}
			// A clean retry works.
			u.fail = 0
			if err := configure(s, agentv1.SwapOperation_SWAP_OPERATION_CREATE, 64); err != nil {
				t.Fatalf("retry: %v", err)
			}
		})
	}
}

func TestSwapConcurrentCreatesSerialise(t *testing.T) {
	s := testSwapper(t, "", &fakeUnits{})
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = configure(s, agentv1.SwapOperation_SWAP_OPERATION_CREATE, 64)
		}()
	}
	wg.Wait()
	var ok int
	for _, err := range errs {
		if err == nil {
			ok++
		} else if !strings.Contains(err.Error(), "already exists") {
			t.Errorf("unexpected error: %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d creates succeeded, want exactly 1", ok)
	}
	if fi, err := os.Stat(s.file()); err != nil || fi.Size() != 64<<20 {
		t.Fatalf("swapfile %v, %v", fi, err)
	}
}

func TestSwapRefusesWhenSpaceIsShort(t *testing.T) {
	u := &fakeUnits{}
	s := testSwapper(t, "", u)
	if err := configure(s, agentv1.SwapOperation_SWAP_OPERATION_CREATE, 64); err != nil {
		t.Fatal(err)
	}
	u.ops = nil
	s.MinReserveBytes = 1 << 62
	err := configure(s, agentv1.SwapOperation_SWAP_OPERATION_RESIZE, 64)
	if err == nil || !strings.Contains(err.Error(), "not enough free space") {
		t.Fatalf("resize without space: %v", err)
	}
	// Checked before anything was torn down: the old swapfile is untouched.
	if fi, err := os.Stat(s.file()); err != nil || fi.Size() != 64<<20 || len(u.ops) != 0 {
		t.Fatalf("old swapfile %v, %v; ops %v", fi, err, u.ops)
	}
	if err := configure(s, agentv1.SwapOperation_SWAP_OPERATION_REMOVE, 0); err != nil {
		t.Fatal(err)
	}
	if err := configure(s, agentv1.SwapOperation_SWAP_OPERATION_CREATE, 64); err == nil {
		t.Fatal("create without space accepted")
	}
	if entries, _ := os.ReadDir(s.Dir); len(entries) != 0 {
		t.Fatalf("files left behind: %v", entries)
	}
}

func TestSwapRefusesUnexpectedFiles(t *testing.T) {
	s := testSwapper(t, "", &fakeUnits{})
	target := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, s.file()); err != nil {
		t.Fatal(err)
	}
	for _, op := range []agentv1.SwapOperation{agentv1.SwapOperation_SWAP_OPERATION_CREATE, agentv1.SwapOperation_SWAP_OPERATION_REMOVE} {
		if err := configure(s, op, map[bool]uint32{true: 64}[op == agentv1.SwapOperation_SWAP_OPERATION_CREATE]); err == nil ||
			!strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("%s with a symlinked swapfile: %v", op, err)
		}
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" { //nolint:gosec // test file
		t.Fatal("symlink target changed")
	}
}

func TestSwapRefusesSwapoffThatWouldNotFit(t *testing.T) {
	u := &fakeUnits{}
	dir := t.TempDir()
	// 512 MiB swapped out to the managed file, 100 MB available (see fakeSwapProc).
	s := &Swapper{Host: fakeSwapProc(t, filepath.Join(dir, "swapfile")+" file 1048572 524288 -2\n"), Units: u, Dir: dir, AnyFilesystem: true}
	if err := os.WriteFile(s.file(), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := configure(s, agentv1.SwapOperation_SWAP_OPERATION_REMOVE, 0)
	if err == nil || !strings.Contains(err.Error(), "swapped out") || len(u.ops) != 0 {
		t.Fatalf("remove under memory pressure: %v, ops %v", err, u.ops)
	}
}

func TestSwapRefusesUnsupportedFilesystem(t *testing.T) {
	s := &Swapper{Host: fakeSwapProc(t, ""), Units: &fakeUnits{}, Dir: "/proc"}
	err := configure(s, agentv1.SwapOperation_SWAP_OPERATION_CREATE, 64)
	if err == nil || !strings.Contains(err.Error(), "ext4 and xfs") {
		t.Fatalf("procfs accepted: %v", err)
	}
}
