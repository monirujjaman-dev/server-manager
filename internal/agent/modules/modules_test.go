//go:build linux

package modules

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
)

// fakeProc writes /proc/<pid>/stat files. flags is stat field 9, start is field 22.
func fakeProc(t *testing.T, procs map[int32]string) Host {
	t.Helper()
	root := t.TempDir()
	for pid, stat := range procs {
		dir := filepath.Join(root, itoa(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return Host{ProcRoot: root}
}

func itoa(n int32) string { return strconv.Itoa(int(n)) }

// stat builds a minimal stat line: pid (name) state ppid ... flags ... utime stime ... threads ... start rss
func stat(pid int32, name string, flags, start string) string {
	f := make([]string, 50)
	for i := range f {
		f[i] = "0"
	}
	f[0] = "S"    // field 3
	f[1] = "1"    // ppid
	f[6] = flags  // field 9
	f[11] = "10"  // utime
	f[12] = "5"   // stime
	f[17] = "3"   // threads
	f[19] = start // starttime
	f[21] = "256" // rss pages
	return itoa(pid) + " (" + name + ") " + strings.Join(f, " ")
}

func TestReadStatTrickyName(t *testing.T) {
	h := fakeProc(t, map[int32]string{42: stat(42, "my (weird) proc", "0", "777")})
	st, err := h.readStat(42)
	if err != nil {
		t.Fatal(err)
	}
	if st.name != "my (weird) proc" || st.startTicks != 777 || st.threads != 3 || st.cpuTicks != 15 || st.ppid != 1 {
		t.Fatalf("parsed %+v", st)
	}
}

func TestSignalProcessSafety(t *testing.T) {
	h := fakeProc(t, map[int32]string{
		100: stat(100, "nginx", "0", "500"),
		2:   stat(2, "kthreadd", "2097152", "1"),
		300: stat(300, "sm-agent", "0", "9"),
	})
	var killed []int
	kill := func(pid int, _ syscall.Signal) error { killed = append(killed, pid); return nil }
	req := func(pid int32, start uint64) *agentv1.ProcessSignalRequest {
		return &agentv1.ProcessSignalRequest{Pid: pid, Signal: agentv1.Signal_SIGNAL_TERM, StartTicks: start}
	}
	for name, r := range map[string]*agentv1.ProcessSignalRequest{
		"pid 1":         req(1, 0),
		"kernel thread": req(2, 0),
		"protected":     req(300, 0),
		"missing":       req(999, 0),
		"pid reused":    req(100, 499),
	} {
		if err := h.SignalProcess(r, []int32{300}, kill); err == nil {
			t.Errorf("%s: signal allowed", name)
		}
	}
	if len(killed) != 0 {
		t.Fatalf("kill called for %v", killed)
	}
	if err := h.SignalProcess(req(100, 500), []int32{300}, kill); err != nil || len(killed) != 1 || killed[0] != 100 {
		t.Fatalf("valid signal: %v, killed %v", err, killed)
	}
}

func TestListProcessesReal(t *testing.T) {
	res, err := DefaultHost().ListProcesses(context.Background(), &agentv1.ProcessListRequest{Sort: agentv1.ProcessSort_PROCESS_SORT_PID, Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	self := int32(os.Getpid())
	found := false
	for _, p := range res.GetProcesses() {
		if p.GetPid() == self {
			found = p.GetCommandLine() != "" && p.GetRssBytes() > 0 && p.GetUser() != ""
		}
	}
	if !found {
		t.Fatalf("own process missing or incomplete among %d", len(res.GetProcesses()))
	}
}

func TestSystemInfoReal(t *testing.T) {
	r, err := DefaultHost().SystemInfo()
	if err != nil {
		t.Fatal(err)
	}
	if r.GetMemoryTotalBytes() == 0 || r.GetCpuCount() == 0 || r.GetUptimeSeconds() == 0 {
		t.Fatalf("incomplete: %+v", r)
	}
}

func TestParseMeminfoAndMounts(t *testing.T) {
	m := parseMeminfo([]byte("MemTotal:       2048 kB\nMemAvailable:   1024 kB\nHugePages_Total: 0\n"))
	if m["MemTotal"] != 2048*1024 || m["MemAvailable"] != 1024*1024 || m["HugePages_Total"] != 0 {
		t.Fatalf("meminfo %v", m)
	}
	fs := filesystems([]byte("proc /proc proc rw 0 0\n/dev/sda1 / ext4 rw 0 0\n/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 /mnt/my\\040disk xfs rw 0 0\n"))
	if len(fs) != 2 || fs[0].GetMountPoint() != "/" || fs[1].GetMountPoint() != "/mnt/my disk" {
		t.Fatalf("filesystems %v", fs)
	}
}

type fakeSystemd struct {
	units map[string]*agentv1.ServiceUnit
	ops   []string
}

func (f *fakeSystemd) ListServices(context.Context) ([]*agentv1.ServiceUnit, error) {
	var out []*agentv1.ServiceUnit
	for _, u := range f.units {
		out = append(out, u)
	}
	return out, nil
}

func (f *fakeSystemd) Unit(_ context.Context, name string) (*agentv1.ServiceUnit, error) {
	if u, ok := f.units[name]; ok {
		return u, nil
	}
	return &agentv1.ServiceUnit{Name: name, LoadState: "not-found"}, nil
}

func (f *fakeSystemd) Control(_ context.Context, unit string, op agentv1.ServiceOperation) error {
	f.ops = append(f.ops, unit+":"+op.String())
	if op == agentv1.ServiceOperation_SERVICE_OPERATION_STOP {
		f.units[unit].ActiveState = "inactive"
	}
	return nil
}

func TestServices(t *testing.T) {
	sd := &fakeSystemd{units: map[string]*agentv1.ServiceUnit{
		"nginx.service": {Name: "nginx.service", LoadState: "loaded", ActiveState: "active"},
		"ssh.service":   {Name: "ssh.service", LoadState: "loaded", ActiveState: "active"},
	}}
	ctx := context.Background()
	list, err := ListServices(ctx, sd, &agentv1.ServiceListRequest{Filter: "NGI"})
	if err != nil || len(list.GetUnits()) != 1 || list.GetUnits()[0].GetName() != "nginx.service" {
		t.Fatalf("filtered list %v, %v", list, err)
	}
	res, err := ControlService(ctx, sd, &agentv1.ServiceControlRequest{Unit: "nginx.service", Operation: agentv1.ServiceOperation_SERVICE_OPERATION_STOP})
	if err != nil || res.GetUnit().GetActiveState() != "inactive" {
		t.Fatalf("stop: %v, %v", res, err)
	}
	if _, err := ControlService(ctx, sd, &agentv1.ServiceControlRequest{Unit: "nope.service", Operation: agentv1.ServiceOperation_SERVICE_OPERATION_START}); err == nil {
		t.Fatal("unknown unit accepted")
	}
	if len(sd.ops) != 1 {
		t.Fatalf("ops %v", sd.ops)
	}
}
