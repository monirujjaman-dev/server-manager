//go:build !linux

package agent

import (
	"fmt"
	"io"
	"os"
)

const maxAgentFile = 64 << 10

// readAgentFile is the portable version of the Linux one: it refuses symlinks and
// non-regular or large files, without O_NOFOLLOW. `sm-agent migrate-trust` only runs on
// Linux; this exists for builds and tests elsewhere.
func readAgentFile(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxAgentFile {
		return nil, fmt.Errorf("%s: not a regular file of at most %d bytes", path, maxAgentFile)
	}
	f, err := os.Open(path) //nolint:gosec // checked above
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, maxAgentFile))
}
