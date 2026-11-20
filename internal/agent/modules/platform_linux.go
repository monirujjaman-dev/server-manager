package modules

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
)

type fsUsage struct {
	total, avail, inodes, inodesFree uint64
	fsType                           int64 // statfs f_type magic
}

func statfs(path string) (fsUsage, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return fsUsage{}, err
	}
	bs := uint64(st.Bsize) //nolint:gosec // block size is positive
	return fsUsage{total: st.Blocks * bs, avail: st.Bavail * bs, inodes: st.Files, inodesFree: st.Ffree, fsType: int64(st.Type)}, nil //nolint:unconvert // Type is int32 on some arches
}

func fileUID(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

var signals = map[agentv1.Signal]syscall.Signal{
	agentv1.Signal_SIGNAL_TERM: syscall.SIGTERM, agentv1.Signal_SIGNAL_KILL: syscall.SIGKILL,
	agentv1.Signal_SIGNAL_HUP: syscall.SIGHUP, agentv1.Signal_SIGNAL_INT: syscall.SIGINT,
	agentv1.Signal_SIGNAL_QUIT: syscall.SIGQUIT, agentv1.Signal_SIGNAL_USR1: syscall.SIGUSR1,
	agentv1.Signal_SIGNAL_USR2: syscall.SIGUSR2,
}

// Kill sends a signal to a process.
func Kill(pid int, sig syscall.Signal) error { return syscall.Kill(pid, sig) }
