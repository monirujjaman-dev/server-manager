package api

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	operatorv1 "github.com/monirujjaman-dev/server-manager/gen/sm/operator/v1"
	"github.com/monirujjaman-dev/server-manager/gen/sm/operator/v1/operatorv1connect"
	"github.com/monirujjaman-dev/server-manager/internal/command"
	"github.com/monirujjaman-dev/server-manager/internal/server/auth"
	"github.com/monirujjaman-dev/server-manager/internal/server/jobs"
	"github.com/monirujjaman-dev/server-manager/internal/server/store"
	"github.com/monirujjaman-dev/server-manager/internal/server/store/db"
)

// Run waits at most this long for a result.
const (
	defaultWait = 120 * time.Second
	maxWait     = 180 * time.Second
)

// ActionServer implements operatorv1connect.ActionServiceHandler.
type ActionServer struct {
	operatorv1connect.UnimplementedActionServiceHandler
	Store *store.Store
}

func toJob(j db.Job) (*operatorv1.Job, error) {
	out := &operatorv1.Job{
		Id: j.ID.String(), ServerId: j.ServerID.String(), Action: j.Action, Risk: j.Risk, Status: j.Status, Error: j.Error,
	}
	if j.Status == jobs.StatusSucceeded {
		res, err := jobs.Result(j)
		if err != nil {
			return nil, err
		}
		out.Result = res.GetResult()
	}
	return out, nil
}

// Run implements ActionService.Run.
func (s *ActionServer) Run(ctx context.Context, req *connect.Request[operatorv1.RunRequest]) (*connect.Response[operatorv1.RunResponse], error) {
	p, g, err := grantsFor(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	areq := req.Msg.GetRequest()
	if err := command.Validate(areq); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	info, _ := command.Describe(areq)
	srv, err := resolveVisible(ctx, s.Store, g, req.Msg.GetServer())
	if err != nil {
		return nil, err
	}
	if err := auth.AuthorizeAction(g, p, srv, info.Risk, time.Now()); err != nil {
		return nil, mapAuthErr(err)
	}
	job, err := jobs.Submit(ctx, s.Store, srv.ID, areq, p.Actor(), 0)
	switch {
	case errors.Is(err, jobs.ErrServerRevoked):
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case err != nil:
		return nil, err
	}
	wait := time.Duration(req.Msg.GetWaitSeconds()) * time.Second
	if wait <= 0 {
		wait = defaultWait
	}
	wctx, cancel := context.WithTimeout(ctx, min(wait, maxWait))
	defer cancel()
	if done, err := jobs.Wait(wctx, s.Store.Queries, job.ID); err == nil {
		job = done
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	} else if latest, err := s.Store.GetJob(ctx, job.ID); err == nil {
		job = latest // not finished yet; the caller can poll GetJob
	}
	out, err := toJob(job)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&operatorv1.RunResponse{Job: out}), nil
}

// GetJob implements ActionService.GetJob.
func (s *ActionServer) GetJob(ctx context.Context, req *connect.Request[operatorv1.GetJobRequest]) (*connect.Response[operatorv1.GetJobResponse], error) {
	_, g, err := grantsFor(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.Msg.GetJobId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid job id"))
	}
	job, err := s.Store.GetJob(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("job not found"))
	} else if err != nil {
		return nil, err
	}
	if _, err := resolveVisible(ctx, s.Store, g, job.ServerID.String()); err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("job not found"))
	}
	out, err := toJob(job)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&operatorv1.GetJobResponse{Job: out}), nil
}
