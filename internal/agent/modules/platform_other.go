//go:build !linux

// The agent runs on Linux only (see docs/ARCHITECTURE.md). These stubs keep the rest of
// the repository building on Windows and macOS, where the control plane and smctl run.
package modules

import (
	"errors"
	"os"
	"syscall"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
)

var errNotLinux = errors.New("only supported on Linux")

type fsUsage struct {
	total, avail, inodes, inodesFree uint64
	fsType                           int64
}

func statfs(string) (fsUsage, error) { return fsUsage{}, errNotLinux }

func fileUID(os.FileInfo) (uint32, bool) { return 0, false }

var signals = map[agentv1.Signal]syscall.Signal{}

// Kill is not supported outside Linux.
func Kill(int, syscall.Signal) error { return errNotLinux }
