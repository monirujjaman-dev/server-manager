package server_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/internal/server"
	"github.com/monirujjaman-dev/server-manager/internal/server/jobs"
)

func TestMetricsAndLogsEndToEnd(t *testing.T) {
	var mu sync.Mutex
	var imported strings.Builder
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		imported.Write(b)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer vm.Close()

	cp := startControlPlaneWith(t, func(c *server.Config) { c.VictoriaMetricsURL = vm.URL })
	defer cp.stop()
	ctx := context.Background()
	st := cp.srv.Store()

	cfg, res := cp.enrollAgent(t, "web-1")
	cfg.MetricsInterval = time.Second

	// Fake journalctl that prints one sshd login and one nginx line.
	dir := t.TempDir()
	fixture := filepath.Join(dir, "out.json")
	_ = os.WriteFile(fixture, []byte(
		`{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1700000000000000","SYSLOG_IDENTIFIER":"sshd","PRIORITY":"6","MESSAGE":"Accepted publickey for deploy from 203.0.113.9 port 4711 ssh2"}`+"\n"+
			`{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"1700000001000000","SYSLOG_IDENTIFIER":"nginx","_SYSTEMD_UNIT":"nginx.service","PRIORITY":"3","MESSAGE":"upstream timed out"}`+"\n"), 0o600)
	script := filepath.Join(dir, "journalctl")
	_ = os.WriteFile(script, []byte("#!/bin/sh\ncat "+fixture+"\n"), 0o700) //nolint:gosec // test helper
	cfg.JournalctlPath = script

	_, stopAgent := runAgent(t, cfg)
	defer stopAgent()

	waitFor(t, "dashboard row with metrics", func() bool {
		rows, err := st.Dashboard(ctx)
		return err == nil && len(rows) == 1 && rows[0].CollectedAt != nil && *rows[0].MemoryTotalBytes > 0
	})
	waitFor(t, "samples in VictoriaMetrics", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return strings.Contains(imported.String(), `sm_memory_total_bytes{server_id="`+res.ServerID.String()+`"}`)
	})

	run := func(req *agentv1.ActionRequest) *agentv1.ActionResult {
		t.Helper()
		job, err := jobs.Submit(ctx, st, res.ServerID, req, "test", 0)
		if err != nil {
			t.Fatal(err)
		}
		wctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		job, err = jobs.Wait(wctx, st.Queries, job.ID)
		if err != nil || job.Status != jobs.StatusSucceeded {
			t.Fatalf("%s: %s %s %v", job.Action, job.Status, job.Error, err)
		}
		r, _ := jobs.Result(job)
		return r.GetResult()
	}

	logs := run(&agentv1.ActionRequest{Action: &agentv1.ActionRequest_LogQuery{LogQuery: &agentv1.LogQueryRequest{Grep: "timed out"}}})
	if e := logs.GetLogQuery().GetEntries(); len(e) != 1 || e[0].GetUnit() != "nginx.service" || logs.GetLogQuery().GetCursor() != "c2" {
		t.Fatalf("log query %v", logs)
	}
	auth := run(&agentv1.ActionRequest{Action: &agentv1.ActionRequest_AuthLog{AuthLog: &agentv1.AuthLogRequest{}}})
	if ev := auth.GetAuthLog().GetEvents(); len(ev) != 1 || ev[0].GetUser() != "deploy" || ev[0].GetSourceIp() != "203.0.113.9" {
		t.Fatalf("auth log %v", auth)
	}
}
