package server_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/internal/agent"
	"github.com/monirujjaman-dev/server-manager/internal/pki"
	"github.com/monirujjaman-dev/server-manager/internal/privd"
	"github.com/monirujjaman-dev/server-manager/internal/server/audit"
	"github.com/monirujjaman-dev/server-manager/internal/server/jobs"
	"github.com/monirujjaman-dev/server-manager/internal/server/store/db"
)

type fakeSystemd struct {
	mu    sync.Mutex
	units map[string]*agentv1.ServiceUnit
	ops   []string
}

func (f *fakeSystemd) ListServices(context.Context) ([]*agentv1.ServiceUnit, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*agentv1.ServiceUnit
	for _, u := range f.units {
		out = append(out, &agentv1.ServiceUnit{Name: u.Name, LoadState: u.LoadState, ActiveState: u.ActiveState})
	}
	return out, nil
}

func (f *fakeSystemd) Unit(_ context.Context, name string) (*agentv1.ServiceUnit, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, ok := f.units[name]; ok {
		return &agentv1.ServiceUnit{Name: u.Name, LoadState: u.LoadState, ActiveState: u.ActiveState}, nil
	}
	return &agentv1.ServiceUnit{Name: name, LoadState: "not-found"}, nil
}

func (f *fakeSystemd) Control(_ context.Context, unit string, op agentv1.ServiceOperation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ops = append(f.ops, unit+" "+op.String())
	return nil
}

func TestCommandsEndToEnd(t *testing.T) {
	cp := startControlPlane(t)
	defer cp.stop()
	ctx := context.Background()
	st := cp.srv.Store()

	cfg, res := cp.enrollAgent(t, "app-1")
	if _, err := pki.ReadCommandPublicKey(cfg.CommandKeyFile); err != nil {
		t.Fatalf("command key not written at enrollment: %v", err)
	}

	sd := &fakeSystemd{units: map[string]*agentv1.ServiceUnit{
		"nginx.service": {Name: "nginx.service", LoadState: "loaded", ActiveState: "active"},
	}}

	// Privileged helper on a private socket, accepting only this test's UID.
	pcfg := privd.DefaultConfig()
	pcfg.Socket = filepath.Join(t.TempDir(), "privd.sock")
	pcfg.CertFile, pcfg.CommandKeyFile = cfg.CertFile, cfg.CommandKeyFile
	uid := uint32(os.Getuid()) //nolint:gosec // UIDs fit uint32
	psrv, err := privd.New(pcfg, slog.New(slog.DiscardHandler), privd.Options{Systemd: sd, AllowedUID: &uid})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := privd.Listen(context.Background(), pcfg.Socket, -1)
	if err != nil {
		t.Fatal(err)
	}
	pctx, stopPrivd := context.WithCancel(ctx)
	defer stopPrivd()
	go func() { _ = psrv.Serve(pctx, ln) }()
	cfg.PrivdSocket = pcfg.Socket

	run := func(t *testing.T, req *agentv1.ActionRequest) (db.Job, *agentv1.CommandResult) {
		t.Helper()
		job, err := jobs.Submit(ctx, st, res.ServerID, req, "test", 0)
		if err != nil {
			t.Fatal(err)
		}
		wctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		job, err = jobs.Wait(wctx, st.Queries, job.ID)
		if err != nil {
			t.Fatalf("wait for %s: %v (status %s)", job.Action, err, job.Status)
		}
		r, err := jobs.Result(job)
		if err != nil {
			t.Fatal(err)
		}
		return job, r
	}

	// Queued while the agent is offline; delivered when it connects.
	queued, err := jobs.Submit(ctx, st, res.ServerID, &agentv1.ActionRequest{
		Action: &agentv1.ActionRequest_SystemInfo{SystemInfo: &agentv1.SystemInfoRequest{}},
	}, "test", 0)
	if err != nil {
		t.Fatal(err)
	}

	_, stopAgent := runAgent(t, cfg, agent.WithSystemd(sd))
	defer stopAgent()

	t.Run("job queued while offline is delivered after connect", func(t *testing.T) {
		wctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		job, err := jobs.Wait(wctx, st.Queries, queued.ID)
		if err != nil || job.Status != jobs.StatusSucceeded {
			t.Fatalf("queued job: %s %s %v", job.Status, job.Error, err)
		}
		r, _ := jobs.Result(job)
		if r.GetResult().GetSystemInfo().GetMemoryTotalBytes() == 0 {
			t.Fatalf("system info result %v", r)
		}
	})

	t.Run("services list", func(t *testing.T) {
		job, r := run(t, &agentv1.ActionRequest{Action: &agentv1.ActionRequest_ServiceList{ServiceList: &agentv1.ServiceListRequest{}}})
		if job.Status != jobs.StatusSucceeded || len(r.GetResult().GetServiceList().GetUnits()) != 1 {
			t.Fatalf("%s %s %v", job.Status, job.Error, r)
		}
	})

	t.Run("restart a service through the privileged helper", func(t *testing.T) {
		job, r := run(t, &agentv1.ActionRequest{Action: &agentv1.ActionRequest_ServiceControl{ServiceControl: &agentv1.ServiceControlRequest{
			Unit: "nginx.service", Operation: agentv1.ServiceOperation_SERVICE_OPERATION_RESTART,
		}}})
		if job.Status != jobs.StatusSucceeded || r.GetResult().GetServiceControl().GetUnit().GetActiveState() != "active" {
			t.Fatalf("%s %s %v", job.Status, job.Error, r)
		}
		sd.mu.Lock()
		defer sd.mu.Unlock()
		if len(sd.ops) != 1 || sd.ops[0] != "nginx.service SERVICE_OPERATION_RESTART" {
			t.Fatalf("systemd ops %v", sd.ops)
		}
	})

	t.Run("unknown unit fails without touching systemd", func(t *testing.T) {
		job, _ := run(t, &agentv1.ActionRequest{Action: &agentv1.ActionRequest_ServiceControl{ServiceControl: &agentv1.ServiceControlRequest{
			Unit: "missing.service", Operation: agentv1.ServiceOperation_SERVICE_OPERATION_START,
		}}})
		if job.Status != jobs.StatusFailed {
			t.Fatalf("status %s", job.Status)
		}
	})

	t.Run("list processes and terminate one by PID and start time", func(t *testing.T) {
		child := exec.Command("sleep", "60")
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		exited := make(chan error, 1)
		go func() { exited <- child.Wait() }()
		defer func() { _ = child.Process.Kill() }()

		_, r := run(t, &agentv1.ActionRequest{Action: &agentv1.ActionRequest_ProcessList{ProcessList: &agentv1.ProcessListRequest{
			Sort: agentv1.ProcessSort_PROCESS_SORT_PID, Limit: 500,
		}}})
		var target *agentv1.Process
		for _, p := range r.GetResult().GetProcessList().GetProcesses() {
			if int(p.GetPid()) == child.Process.Pid {
				target = p
			}
		}
		if target == nil || target.GetStartTicks() == 0 {
			t.Fatalf("child process %d not listed", child.Process.Pid)
		}

		job, _ := run(t, &agentv1.ActionRequest{Action: &agentv1.ActionRequest_ProcessSignal{ProcessSignal: &agentv1.ProcessSignalRequest{
			Pid: target.GetPid(), Signal: agentv1.Signal_SIGNAL_TERM, StartTicks: target.GetStartTicks(),
		}}})
		if job.Status != jobs.StatusSucceeded {
			t.Fatalf("signal job %s: %s", job.Status, job.Error)
		}
		select {
		case err := <-exited:
			var ee *exec.ExitError
			if !errors.As(err, &ee) || ee.Sys().(syscall.WaitStatus).Signal() != syscall.SIGTERM {
				t.Fatalf("child exit: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("child not terminated")
		}
	})

	t.Run("privileged helper down: job fails, outcome reported", func(t *testing.T) {
		stopPrivd()
		time.Sleep(100 * time.Millisecond)
		job, _ := run(t, &agentv1.ActionRequest{Action: &agentv1.ActionRequest_ServiceControl{ServiceControl: &agentv1.ServiceControlRequest{
			Unit: "nginx.service", Operation: agentv1.ServiceOperation_SERVICE_OPERATION_STOP,
		}}})
		if job.Status != jobs.StatusFailed || job.Error == "" {
			t.Fatalf("status %s error %q", job.Status, job.Error)
		}
	})

	if _, err := audit.Verify(ctx, st.Queries); err != nil {
		t.Fatal(err)
	}
}
