package modules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestContainerStatsFromCgroups(t *testing.T) {
	root := t.TempDir()
	id1, id2 := strings.Repeat("a", 64), strings.Repeat("b", 64)
	// cgroup v2 with the systemd driver: two running containers, plus look-alikes.
	writeFile(t, filepath.Join(root, "system.slice/docker.service/cgroup.procs"), "")
	writeFile(t, filepath.Join(root, "system.slice/docker-"+id1+".scope/memory.current"), "1000\n")
	writeFile(t, filepath.Join(root, "system.slice/docker-"+id1+".scope/memory.stat"), "anon 600\ninactive_file 300\n")
	writeFile(t, filepath.Join(root, "system.slice/docker-"+id2+".scope/memory.current"), "500\n")
	writeFile(t, filepath.Join(root, "system.slice/docker-short.scope/memory.current"), "99999\n")
	writeFile(t, filepath.Join(root, "system.slice/sshd.service/memory.current"), "99999\n")

	n, mem, ok := Host{CgroupRoot: root}.containerStats()
	if !ok || n != 2 || mem != 700+500 {
		t.Fatalf("containerStats = %d, %d, %v; want 2, 1200, true", n, mem, ok)
	}

	// Docker installed but nothing running: zero, not "no Docker".
	empty := t.TempDir()
	writeFile(t, filepath.Join(empty, "docker/cgroup.procs"), "")
	if n, _, ok := (Host{CgroupRoot: empty}).containerStats(); !ok || n != 0 {
		t.Fatalf("idle docker = %d, %v", n, ok)
	}
	if _, _, ok := (Host{CgroupRoot: t.TempDir()}).containerStats(); ok {
		t.Fatal("reported Docker on a host without it")
	}
	if _, _, ok := (Host{}).containerStats(); ok {
		t.Fatal("reported Docker with no cgroup root")
	}
}
