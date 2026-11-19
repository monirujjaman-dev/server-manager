package jobs

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/internal/command"
	"github.com/monirujjaman-dev/server-manager/internal/server/audit"
	"github.com/monirujjaman-dev/server-manager/internal/server/store"
	"github.com/monirujjaman-dev/server-manager/internal/server/store/db"
	"github.com/monirujjaman-dev/server-manager/internal/server/store/storetest"
)

func setup(t *testing.T) (*store.Store, *Dispatcher, uuid.UUID) {
	t.Helper()
	st, _ := storetest.Open(t)
	id := uuid.New()
	if _, err := st.CreateServer(context.Background(), db.CreateServerParams{ID: id, Name: "web-1"}); err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	return st, NewDispatcher(st, command.NewSigner(key), slog.New(slog.DiscardHandler)), id
}

func sysinfo() *agentv1.ActionRequest {
	return &agentv1.ActionRequest{Action: &agentv1.ActionRequest_SystemInfo{SystemInfo: &agentv1.SystemInfoRequest{}}}
}

func claim(t *testing.T, st *store.Store, server uuid.UUID) db.Job {
	t.Helper()
	jobs, err := st.ClaimPendingJobs(context.Background(), db.ClaimPendingJobsParams{ServerID: server, MaxJobs: 10})
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim: %v, %v", jobs, err)
	}
	return jobs[0]
}

func TestSubmitValidates(t *testing.T) {
	st, _, id := setup(t)
	ctx := context.Background()
	bad := &agentv1.ActionRequest{Action: &agentv1.ActionRequest_ServiceControl{ServiceControl: &agentv1.ServiceControlRequest{Unit: "x; reboot"}}}
	if _, err := Submit(ctx, st, id, bad, "alice", 0); err == nil {
		t.Fatal("invalid request accepted")
	}
	if _, err := Submit(ctx, st, uuid.New(), sysinfo(), "alice", 0); !errors.Is(err, ErrServerUnknown) {
		t.Fatalf("unknown server: %v", err)
	}
	if err := st.SetServerStatus(ctx, db.SetServerStatusParams{ID: id, Status: "revoked"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Submit(ctx, st, id, sysinfo(), "alice", 0); !errors.Is(err, ErrServerRevoked) {
		t.Fatalf("revoked server: %v", err)
	}
}

func TestCompleteOnlyByTargetServerOnce(t *testing.T) {
	st, d, id := setup(t)
	ctx := context.Background()
	job, err := Submit(ctx, st, id, sysinfo(), "alice", 0)
	if err != nil {
		t.Fatal(err)
	}
	if job.Action != "system.info" || job.Risk != "read" || job.Status != StatusPending {
		t.Fatalf("job %+v", job)
	}
	claim(t, st, id)
	res := &agentv1.CommandResult{Id: job.ID.String(), Status: agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED}
	if err := d.Complete(ctx, uuid.New(), res); err == nil {
		t.Fatal("another server completed the job")
	}
	if err := d.Complete(ctx, id, res); err != nil {
		t.Fatal(err)
	}
	if err := d.Complete(ctx, id, res); err == nil {
		t.Fatal("job completed twice")
	}
	got, _ := st.GetJob(ctx, job.ID)
	if got.Status != StatusSucceeded || got.FinishedAt == nil {
		t.Fatalf("job after completion %+v", got)
	}
	if n, err := audit.Verify(ctx, st.Queries); err != nil || n != 2 { // requested + outcome
		t.Fatalf("audit = %d, %v", n, err)
	}
}

func TestSweepExpiresAndFailsStaleJobs(t *testing.T) {
	st, d, id := setup(t)
	ctx := context.Background()
	pending, _ := Submit(ctx, st, id, sysinfo(), "alice", time.Minute)
	if _, err := st.Pool.Exec(ctx, "UPDATE jobs SET expires_at = now() - interval '1 second' WHERE id = $1", pending.ID); err != nil {
		t.Fatal(err)
	}
	stale, _ := Submit(ctx, st, id, sysinfo(), "alice", time.Minute)
	if _, err := st.Pool.Exec(ctx, "UPDATE jobs SET status = 'dispatched', dispatched_at = now() - interval '1 hour' WHERE id = $1", stale.ID); err != nil {
		t.Fatal(err)
	}
	d.sweep(ctx)
	if j, _ := st.GetJob(ctx, pending.ID); j.Status != StatusExpired {
		t.Errorf("pending job status %q", j.Status)
	}
	if j, _ := st.GetJob(ctx, stale.ID); j.Status != StatusFailed || j.Error == "" {
		t.Errorf("stale job %q %q", j.Status, j.Error)
	}
}
