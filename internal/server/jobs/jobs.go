// Package jobs queues typed actions for agents, dispatches them as signed commands and
// records their results.
//
// Life of a job: Submit inserts it as pending (audited, with a NOTIFY on commit). The
// dispatcher claims pending jobs of connected servers, signs each one and queues it on
// the agent's stream. The agent's result completes the job (audited). Pending jobs wait
// for the agent to reconnect until they expire; dispatched jobs without a result are
// failed after a timeout and never retried, because their outcome is unknown.
package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/internal/command"
	"github.com/monirujjaman-dev/server-manager/internal/server/audit"
	"github.com/monirujjaman-dev/server-manager/internal/server/gateway"
	"github.com/monirujjaman-dev/server-manager/internal/server/store"
	"github.com/monirujjaman-dev/server-manager/internal/server/store/db"
)

// Timing defaults.
const (
	// DefaultPendingTTL is how long a job waits for its agent to be online.
	DefaultPendingTTL = 10 * time.Minute
	// ResultTimeout fails dispatched jobs that never report back.
	ResultTimeout = 2 * time.Minute
	sweepInterval = 5 * time.Second
	claimBatch    = 16
)

// Job statuses.
const (
	StatusPending    = "pending"
	StatusDispatched = "dispatched"
	StatusSucceeded  = "succeeded"
	StatusFailed     = "failed"
	StatusRejected   = "rejected"
	StatusExpired    = "expired"
)

// Errors returned by Submit.
var (
	ErrServerRevoked = errors.New("server is revoked")
	ErrServerUnknown = errors.New("server not found")
)

// Finished reports whether a job reached a final status.
func Finished(status string) bool {
	return status != StatusPending && status != StatusDispatched
}

// Submit validates and queues an action for a server. It returns the created job.
func Submit(ctx context.Context, st *store.Store, serverID uuid.UUID, req *agentv1.ActionRequest, actor string, ttl time.Duration) (db.Job, error) {
	if err := command.Validate(req); err != nil {
		return db.Job{}, err
	}
	info, _ := command.Describe(req)
	if ttl <= 0 {
		ttl = DefaultPendingTTL
	}
	raw, err := proto.Marshal(req)
	if err != nil {
		return db.Job{}, err
	}

	tx, err := st.Pool.Begin(ctx)
	if err != nil {
		return db.Job{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := st.WithTx(tx)

	srv, err := q.GetServer(ctx, serverID)
	if errors.Is(err, pgx.ErrNoRows) {
		return db.Job{}, ErrServerUnknown
	} else if err != nil {
		return db.Job{}, err
	}
	if srv.Status == "revoked" {
		return db.Job{}, ErrServerRevoked
	}
	job, err := q.CreateJob(ctx, db.CreateJobParams{
		ServerID: serverID, Action: info.Name, Risk: string(info.Risk), Request: raw,
		RequestedBy: actor, ExpiresAt: time.Now().Add(ttl),
	})
	if err != nil {
		return db.Job{}, err
	}
	if _, err := audit.Append(ctx, q, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor, ServerID: &serverID, Action: info.Name,
		Params: map[string]string{"job_id": job.ID.String(), "request": requestSummary(req), "risk": string(info.Risk)},
		Result: audit.Requested,
	}); err != nil {
		return db.Job{}, err
	}
	// Delivered to listeners when the transaction commits.
	if err := q.NotifyJobs(ctx, serverID.String()); err != nil {
		return db.Job{}, err
	}
	return job, tx.Commit(ctx)
}

// Wait polls until the job is finished or ctx ends.
func Wait(ctx context.Context, q *db.Queries, jobID uuid.UUID) (db.Job, error) {
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()
	for {
		job, err := q.GetJob(ctx, jobID)
		if err != nil {
			return job, err
		}
		if Finished(job.Status) {
			return job, nil
		}
		select {
		case <-ctx.Done():
			return job, ctx.Err()
		case <-t.C:
		}
	}
}

// Result decodes a finished job's result.
func Result(job db.Job) (*agentv1.CommandResult, error) {
	res := &agentv1.CommandResult{}
	if len(job.Result) == 0 {
		return res, nil
	}
	return res, proto.Unmarshal(job.Result, res)
}

func requestSummary(req *agentv1.ActionRequest) string {
	b, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(req)
	if err != nil {
		return ""
	}
	return string(b)
}

// Dispatcher delivers pending jobs to connected agents.
type Dispatcher struct {
	st     *store.Store
	signer *command.Signer
	log    *slog.Logger
	reg    *gateway.Registry
	kick   chan uuid.UUID
}

// NewDispatcher creates a dispatcher. SetRegistry must be called before Run.
func NewDispatcher(st *store.Store, signer *command.Signer, log *slog.Logger) *Dispatcher {
	return &Dispatcher{st: st, signer: signer, log: log, kick: make(chan uuid.UUID, 1024)}
}

// SetRegistry connects the dispatcher to the gateway's sessions.
func (d *Dispatcher) SetRegistry(r *gateway.Registry) { d.reg = r }

// Kick asks the dispatcher to deliver a server's pending jobs.
func (d *Dispatcher) Kick(id uuid.UUID) {
	select {
	case d.kick <- id:
	default: // the periodic sweep catches up
	}
}

// Run dispatches until ctx ends.
func (d *Dispatcher) Run(ctx context.Context) error {
	go d.listen(ctx)
	sweep := time.NewTicker(sweepInterval)
	defer sweep.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case id := <-d.kick:
			d.dispatch(ctx, id)
		case <-sweep.C:
			d.sweep(ctx)
		}
	}
}

// listen turns NOTIFY sm_jobs into kicks, reconnecting on errors.
func (d *Dispatcher) listen(ctx context.Context) {
	for ctx.Err() == nil {
		if err := d.listenOnce(ctx); err != nil && ctx.Err() == nil {
			d.log.Warn("job notification listener failed; retrying", "err", err)
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
			}
		}
	}
}

func (d *Dispatcher) listenOnce(ctx context.Context) error {
	conn, err := d.st.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "LISTEN sm_jobs"); err != nil {
		return err
	}
	// Catch up on anything queued before LISTEN took effect.
	d.sweep(ctx)
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			// The connection's LISTEN state is unknown now; do not return it to the pool.
			_ = conn.Conn().Close(context.WithoutCancel(ctx))
			return err
		}
		if id, err := uuid.Parse(n.Payload); err == nil {
			d.Kick(id)
		}
	}
}

func (d *Dispatcher) dispatch(ctx context.Context, serverID uuid.UUID) {
	if d.reg == nil {
		return
	}
	if _, ok := d.reg.Get(serverID); !ok {
		return
	}
	jobs, err := d.st.ClaimPendingJobs(ctx, db.ClaimPendingJobsParams{ServerID: serverID, MaxJobs: claimBatch})
	if err != nil {
		d.log.Error("claim jobs", "server_id", serverID.String(), "err", err)
		return
	}
	for _, job := range jobs {
		if err := d.send(job); err != nil {
			d.log.Warn("job not sent; will retry", "job_id", job.ID.String(), "err", err)
			if err := d.st.ReleaseJob(ctx, job.ID); err != nil {
				d.log.Error("release job", "job_id", job.ID.String(), "err", err)
			}
			continue
		}
		d.log.Info("job dispatched", "job_id", job.ID.String(), "server_id", serverID.String(), "action", job.Action)
	}
	if len(jobs) == claimBatch {
		d.Kick(serverID) // more may be waiting
	}
}

func (d *Dispatcher) send(job db.Job) error {
	req := &agentv1.ActionRequest{}
	if err := proto.Unmarshal(job.Request, req); err != nil {
		return err
	}
	cmd, err := d.signer.Sign(job.ID, job.ServerID, req, command.DefaultTTL)
	if err != nil {
		return err
	}
	return d.reg.SendCommand(job.ServerID, cmd)
}

// sweep expires undeliverable jobs, fails unanswered ones and retries delivery.
func (d *Dispatcher) sweep(ctx context.Context) {
	expired, err := d.st.ExpirePendingJobs(ctx)
	if err != nil {
		d.log.Error("expire jobs", "err", err)
	}
	stale, err := d.st.FailStaleDispatchedJobs(ctx, ResultTimeout.Seconds())
	if err != nil {
		d.log.Error("fail stale jobs", "err", err)
	}
	for _, j := range append(expired, stale...) {
		d.auditOutcome(ctx, j, audit.ActorSystem, "dispatcher")
	}
	pending, err := d.st.ServersWithPendingJobs(ctx)
	if err != nil {
		d.log.Error("list pending jobs", "err", err)
		return
	}
	for _, id := range pending {
		d.dispatch(ctx, id)
	}
}

// Complete records a result reported by serverID. A server can only complete jobs that
// were dispatched to it, and each job only once.
func (d *Dispatcher) Complete(ctx context.Context, serverID uuid.UUID, res *agentv1.CommandResult) error {
	jobID, err := uuid.Parse(res.GetId())
	if err != nil {
		return fmt.Errorf("bad job id: %w", err)
	}
	status := StatusFailed
	switch res.GetStatus() {
	case agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED:
		status = StatusSucceeded
	case agentv1.CommandStatus_COMMAND_STATUS_REJECTED:
		status = StatusRejected
	}
	raw, err := proto.Marshal(res)
	if err != nil {
		return err
	}
	errText := res.GetError()
	if len(errText) > 1024 {
		errText = errText[:1024]
	}

	tx, err := d.st.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := d.st.WithTx(tx)
	job, err := q.CompleteJob(ctx, db.CompleteJobParams{ID: jobID, ServerID: serverID, Status: status, Error: errText, Result: raw})
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("job %s is not awaiting a result from this server", jobID)
	} else if err != nil {
		return err
	}
	if err := appendOutcome(ctx, q, job, audit.ActorAgent, serverID.String()); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	d.log.Info("job finished", "job_id", jobID.String(), "server_id", serverID.String(), "action", job.Action, "status", status)
	return nil
}

func (d *Dispatcher) auditOutcome(ctx context.Context, job db.Job, actorType audit.ActorType, actorID string) {
	tx, err := d.st.Pool.Begin(ctx)
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := appendOutcome(ctx, d.st.WithTx(tx), job, actorType, actorID); err != nil {
		d.log.Error("audit job outcome", "job_id", job.ID.String(), "err", err)
		return
	}
	_ = tx.Commit(ctx)
}

func appendOutcome(ctx context.Context, q *db.Queries, job db.Job, actorType audit.ActorType, actorID string) error {
	result := audit.Failed
	switch job.Status {
	case StatusSucceeded:
		result = audit.Succeeded
	case StatusRejected:
		result = audit.Denied
	}
	params := map[string]string{"job_id": job.ID.String(), "status": job.Status, "requested_by": job.RequestedBy}
	if job.Error != "" {
		params["error"] = job.Error
	}
	_, err := audit.Append(ctx, q, audit.Event{
		ActorType: actorType, ActorID: actorID, ServerID: &job.ServerID, Action: job.Action,
		Params: params, Result: result,
	})
	return err
}
