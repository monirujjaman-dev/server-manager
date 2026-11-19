// Package version holds build information injected at link time.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Set with -ldflags "-X github.com/monirujjaman-dev/server-manager/internal/pkg/version.Version=v0.1.0 ...".
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// Info describes the running binary.
type Info struct {
	Version   string
	Commit    string
	Date      string
	GoVersion string
	Platform  string
}

// Get returns build information, falling back to VCS data embedded by the Go toolchain.
func Get() Info {
	info := Info{
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if info.Commit == "" {
					info.Commit = s.Value
				}
			case "vcs.time":
				if info.Date == "" {
					info.Date = s.Value
				}
			}
		}
	}
	if info.Commit == "" {
		info.Commit = "unknown"
	}
	if info.Date == "" {
		info.Date = "unknown"
	}
	return info
}

// String renders a one-line version string for a binary name.
func String(binary string) string {
	i := Get()
	commit := i.Commit
	if len(commit) > 12 {
		commit = commit[:12]
	}
	return fmt.Sprintf("%s %s (commit %s, built %s, %s, %s)", binary, i.Version, commit, i.Date, i.GoVersion, i.Platform)
}
