package agent

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

// maxAgentFile bounds files read from the agent's directory by root.
const maxAgentFile = 64 << 10

// readAgentFile reads a small regular file from a directory the agent controls, as root:
// it does not follow a symlink (O_NOFOLLOW), does not block on a FIFO (O_NONBLOCK), and
// refuses anything that is not a regular file or is larger than 64 KiB.
func readAgentFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // fixed paths; opened defensively
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxAgentFile {
		return nil, fmt.Errorf("%s: not a regular file of at most %d bytes", path, maxAgentFile)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxAgentFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxAgentFile {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, maxAgentFile)
	}
	return b, nil
}
