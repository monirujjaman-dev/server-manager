//go:build !linux

package privd

import "os"

// fileOwner is only implemented on Linux; elsewhere every trust file is refused, so
// the helper fails closed.
func fileOwner(os.FileInfo) (uint32, bool) { return 0, false }
