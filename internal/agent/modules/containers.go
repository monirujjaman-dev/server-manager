package modules

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Running Docker containers are visible in cgroupfs without touching the Docker socket
// (which is root-equivalent and off limits to the unprivileged agent): each one has a
// cgroup named after its 64-hex ID, and the cgroup exists only while it runs.
var containerCgroupRe = regexp.MustCompile(`^(docker-)?[0-9a-f]{64}(\.scope)?$`)

// cgroupLayout is one place Docker puts container cgroups.
type cgroupLayout struct {
	marker      string // exists when Docker uses this layout
	parent      string // directory holding one cgroup per container
	memFile     string // memory usage in bytes
	inactiveKey string // memory.stat key for reclaimable page cache
}

var cgroupLayouts = []cgroupLayout{
	// cgroup v2, systemd driver (the default on current distributions).
	{marker: "system.slice/docker.service", parent: "system.slice", memFile: "memory.current", inactiveKey: "inactive_file"},
	// cgroup v2, cgroupfs driver.
	{marker: "docker", parent: "docker", memFile: "memory.current", inactiveKey: "inactive_file"},
	// cgroup v1.
	{marker: "memory/system.slice/docker.service", parent: "memory/system.slice", memFile: "memory.usage_in_bytes", inactiveKey: "total_inactive_file"},
	{marker: "memory/docker", parent: "memory/docker", memFile: "memory.usage_in_bytes", inactiveKey: "total_inactive_file"},
}

// containerStats counts running Docker containers and their memory use excluding page
// cache. ok is false when Docker's cgroups are not found (Docker not installed).
func (h Host) containerStats() (running uint32, memory uint64, ok bool) {
	if h.CgroupRoot == "" {
		return 0, 0, false
	}
	for _, l := range cgroupLayouts {
		if _, err := os.Stat(filepath.Join(h.CgroupRoot, l.marker)); err != nil {
			continue
		}
		ok = true
		entries, err := os.ReadDir(filepath.Join(h.CgroupRoot, l.parent))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() || !containerCgroupRe.MatchString(e.Name()) {
				continue
			}
			running++
			dir := filepath.Join(h.CgroupRoot, l.parent, e.Name())
			used := readUint(filepath.Join(dir, l.memFile))
			if inactive := memStat(filepath.Join(dir, "memory.stat"), l.inactiveKey); inactive < used {
				used -= inactive
			}
			memory += used
		}
	}
	return running, memory, ok
}

func readUint(path string) uint64 {
	b, err := os.ReadFile(path) //nolint:gosec // fixed cgroupfs paths
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return n
}

func memStat(path, key string) uint64 {
	b, err := os.ReadFile(path) //nolint:gosec // fixed cgroupfs paths
	if err != nil {
		return 0
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), " ")
		if k == key {
			n, _ := strconv.ParseUint(v, 10, 64)
			return n
		}
	}
	return 0
}
