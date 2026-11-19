package modules

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
)

const (
	cpuSampleInterval = 300 * time.Millisecond
	clockTicks        = 100 // USER_HZ on all supported Linux architectures
	pfKthread         = 0x00200000
	maxCmdline        = 512
)

type procStat struct {
	pid, ppid  int32
	name       string
	state      string
	cpuTicks   uint64
	startTicks uint64
	threads    uint32
	flags      uint64
	rssPages   int64
}

// readStat parses /proc/<pid>/stat. The command name is in parentheses and may itself
// contain spaces and parentheses, so parsing starts after the last ')'.
func (h Host) readStat(pid int32) (procStat, error) {
	b, err := os.ReadFile(h.proc(strconv.Itoa(int(pid)), "stat"))
	if err != nil {
		return procStat{}, err
	}
	s := string(b)
	open, closeIdx := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if open < 0 || closeIdx < open {
		return procStat{}, errors.New("malformed stat")
	}
	f := strings.Fields(s[closeIdx+1:])
	// f[0] is field 3 (state); field N is f[N-3].
	if len(f) < 22 {
		return procStat{}, errors.New("short stat")
	}
	num := func(i int) uint64 { n, _ := strconv.ParseUint(f[i], 10, 64); return n }
	ppid, _ := strconv.ParseInt(f[1], 10, 32)
	rss, _ := strconv.ParseInt(f[21], 10, 64)
	return procStat{
		pid: pid, ppid: int32(ppid), name: s[open+1 : closeIdx], state: f[0],
		flags: num(6), cpuTicks: num(11) + num(12), threads: uint32(num(17)), //nolint:gosec // thread count fits
		startTicks: num(19), rssPages: rss,
	}, nil
}

func (h Host) pids() ([]int32, error) {
	entries, err := os.ReadDir(h.ProcRoot)
	if err != nil {
		return nil, err
	}
	var out []int32
	for _, e := range entries {
		if n, err := strconv.ParseInt(e.Name(), 10, 32); err == nil {
			out = append(out, int32(n))
		}
	}
	return out, nil
}

func (h Host) owner(pid int32) string {
	fi, err := os.Stat(h.proc(strconv.Itoa(int(pid))))
	if err != nil {
		return ""
	}
	n, ok := fileUID(fi)
	if !ok {
		return ""
	}
	uid := strconv.FormatUint(uint64(n), 10)
	if u, err := user.LookupId(uid); err == nil {
		return u.Username
	}
	return uid
}

func (h Host) cmdline(pid int32) string {
	b, err := os.ReadFile(h.proc(strconv.Itoa(int(pid)), "cmdline"))
	if err != nil {
		return ""
	}
	if len(b) > maxCmdline {
		b = b[:maxCmdline]
	}
	return strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
}

// ListProcesses samples CPU time twice to compute CPU usage and returns the top
// processes by the requested order.
func (h Host) ListProcesses(ctx context.Context, req *agentv1.ProcessListRequest) (*agentv1.ProcessListResult, error) {
	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = 50
	}
	pids, err := h.pids()
	if err != nil {
		return nil, err
	}
	first := make(map[int32]procStat, len(pids))
	for _, pid := range pids {
		if st, err := h.readStat(pid); err == nil {
			first[pid] = st
		}
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(cpuSampleInterval):
	}
	page := int64(os.Getpagesize())
	var procs []*agentv1.Process
	for pid, a := range first {
		b, err := h.readStat(pid)
		if err != nil || b.startTicks != a.startTicks {
			continue // exited or PID reused during the sample
		}
		cpu := float64(b.cpuTicks-a.cpuTicks) / clockTicks / cpuSampleInterval.Seconds() * 100
		procs = append(procs, &agentv1.Process{
			Pid: pid, Ppid: b.ppid, Name: b.name, State: b.state, CpuPercent: cpu,
			RssBytes: uint64(max(b.rssPages, 0) * page), StartTicks: b.startTicks, Threads: b.threads, //nolint:gosec // non-negative
		})
	}
	switch req.GetSort() {
	case agentv1.ProcessSort_PROCESS_SORT_MEMORY:
		sort.Slice(procs, func(i, j int) bool { return procs[i].RssBytes > procs[j].RssBytes })
	case agentv1.ProcessSort_PROCESS_SORT_PID:
		sort.Slice(procs, func(i, j int) bool { return procs[i].Pid < procs[j].Pid })
	default:
		sort.Slice(procs, func(i, j int) bool {
			if procs[i].CpuPercent != procs[j].CpuPercent {
				return procs[i].CpuPercent > procs[j].CpuPercent
			}
			return procs[i].RssBytes > procs[j].RssBytes
		})
	}
	total := len(procs)
	if len(procs) > limit {
		procs = procs[:limit]
	}
	for _, p := range procs { // only for the processes returned
		p.User = h.owner(p.Pid)
		p.CommandLine = h.cmdline(p.Pid)
	}
	return &agentv1.ProcessListResult{Processes: procs, Total: uint32(total)}, nil //nolint:gosec // process count fits
}

// SignalProcess sends a signal after safety checks: never PID 1, protected PIDs (the
// agent and the helper) or kernel threads, and only to the same process the operator
// saw when start_ticks is given. kill is syscall.Kill outside tests.
func (h Host) SignalProcess(req *agentv1.ProcessSignalRequest, protected []int32, kill func(int, syscall.Signal) error) error {
	pid := req.GetPid()
	sig, ok := signals[req.GetSignal()]
	if !ok {
		return errors.New("unsupported signal")
	}
	if pid <= 1 {
		return errors.New("refusing to signal PID 0 or 1")
	}
	for _, p := range protected {
		if p == pid {
			return fmt.Errorf("refusing to signal PID %d (Server Manager agent or helper)", pid)
		}
	}
	st, err := h.readStat(pid)
	if err != nil {
		return fmt.Errorf("process %d not found", pid)
	}
	if st.flags&pfKthread != 0 {
		return fmt.Errorf("refusing to signal kernel thread %d (%s)", pid, st.name)
	}
	if req.GetStartTicks() != 0 && req.GetStartTicks() != st.startTicks {
		return fmt.Errorf("PID %d now belongs to a different process; refresh the process list", pid)
	}
	return kill(int(pid), sig)
}
