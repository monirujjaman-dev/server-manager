// Package modules implements the agent's typed actions. Read-only actions run in the
// unprivileged agent; actions that change the system run in the privileged helper.
package modules

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
)

// Host gives modules access to the host's /proc so tests can use a fake tree.
type Host struct {
	// ProcRoot is normally "/proc".
	ProcRoot string
}

// DefaultHost reads the real system.
func DefaultHost() Host { return Host{ProcRoot: "/proc"} }

func (h Host) proc(parts ...string) string {
	return filepath.Join(append([]string{h.ProcRoot}, parts...)...)
}

// Filesystem types worth reporting; pseudo filesystems are skipped.
var realFS = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true,
	"vfat": true, "f2fs": true, "jfs": true, "reiserfs": true, "nfs": true, "nfs4": true,
	"cifs": true, "overlay": true, "fuseblk": true, "bcachefs": true,
}

// SystemInfo reports uptime, load, memory, swap and mounted filesystems.
func (h Host) SystemInfo() (*agentv1.SystemInfoResult, error) {
	r := &agentv1.SystemInfoResult{CpuCount: uint32(runtime.NumCPU())} //nolint:gosec // CPU count fits
	if name, err := os.Hostname(); err == nil {
		r.Hostname = name
	}
	if b, err := os.ReadFile(h.proc("uptime")); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if up, err := strconv.ParseFloat(f[0], 64); err == nil {
				r.UptimeSeconds = uint64(up)
			}
		}
	}
	if b, err := os.ReadFile(h.proc("loadavg")); err == nil {
		f := strings.Fields(string(b))
		if len(f) >= 3 {
			r.Load1, _ = strconv.ParseFloat(f[0], 64)
			r.Load5, _ = strconv.ParseFloat(f[1], 64)
			r.Load15, _ = strconv.ParseFloat(f[2], 64)
		}
	}
	if b, err := os.ReadFile(h.proc("meminfo")); err == nil {
		m := parseMeminfo(b)
		r.MemoryTotalBytes = m["MemTotal"]
		r.MemoryAvailableBytes = m["MemAvailable"]
		r.SwapTotalBytes = m["SwapTotal"]
		r.SwapFreeBytes = m["SwapFree"]
	}
	if b, err := os.ReadFile(h.proc("self", "mounts")); err == nil {
		r.Filesystems = filesystems(b)
	}
	return r, nil
}

// parseMeminfo returns /proc/meminfo values in bytes.
func parseMeminfo(b []byte) map[string]uint64 {
	out := make(map[string]uint64)
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			continue
		}
		n, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			continue
		}
		if len(f) > 1 && f[1] == "kB" {
			n *= 1024
		}
		out[k] = n
	}
	return out
}

func filesystems(mounts []byte) []*agentv1.Filesystem {
	var out []*agentv1.Filesystem
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(mounts))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || !realFS[f[2]] || seen[f[1]] {
			continue
		}
		mount := unescapeMount(f[1])
		seen[f[1]] = true
		fs := &agentv1.Filesystem{MountPoint: mount, Device: f[0], FsType: f[2]}
		var st unix.Statfs_t
		if err := unix.Statfs(mount, &st); err == nil {
			bs := uint64(st.Bsize) //nolint:gosec // block size is positive
			fs.TotalBytes = st.Blocks * bs
			fs.AvailableBytes = st.Bavail * bs
			fs.InodesTotal = st.Files
			fs.InodesFree = st.Ffree
		}
		out = append(out, fs)
	}
	return out
}

// unescapeMount decodes the octal escapes (\040 for space) used in /proc/mounts.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
