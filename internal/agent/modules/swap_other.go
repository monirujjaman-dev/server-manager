//go:build !linux

package modules

import "os"

const (
	fsMagicExt4 = 0xEF53
	fsMagicXFS  = 0x58465342
)

func allocate(*os.File, uint64) error { return errNotLinux }

// syncDirErr ignores directory fsync errors: Windows and macOS builds only exist for
// tests and tooling, and Windows cannot fsync a directory.
func syncDirErr(error) error { return nil }
