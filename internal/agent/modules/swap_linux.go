package modules

import (
	"os"

	"golang.org/x/sys/unix"
)

// statfs f_type values for the filesystems swapfiles are supported on.
const (
	fsMagicExt4 = 0xEF53     // ext2/3/4
	fsMagicXFS  = 0x58465342 // "XFSB"
)

// allocate reserves size bytes with no holes, as swapon requires.
func allocate(f *os.File, size uint64) error {
	return unix.Fallocate(int(f.Fd()), 0, 0, int64(size)) //nolint:gosec // fd and size fit
}

// syncDirErr reports a failed directory fsync.
func syncDirErr(err error) error { return err }
