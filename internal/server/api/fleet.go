package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	operatorv1 "github.com/monirujjaman-dev/server-manager/gen/sm/operator/v1"
	"github.com/monirujjaman-dev/server-manager/gen/sm/operator/v1/operatorv1connect"
	"github.com/monirujjaman-dev/server-manager/internal/command"
	"github.com/monirujjaman-dev/server-manager/internal/server/auth"
	"github.com/monirujjaman-dev/server-manager/internal/server/enroll"
	"github.com/monirujjaman-dev/server-manager/internal/server/fleet"
	"github.com/monirujjaman-dev/server-manager/internal/server/store"
	"github.com/monirujjaman-dev/server-manager/internal/server/store/db"
)

// FleetServer implements operatorv1connect.FleetServiceHandler.
type FleetServer struct {
	operatorv1connect.UnimplementedFleetServiceHandler
	Store  *store.Store
	Pin    string
	APIURL string
}

func grantsFor(ctx context.Context, st *store.Store) (auth.Principal, auth.Grants, error) {
	p, ok := PrincipalFrom(ctx)
	if !ok {
		return p, auth.Grants{}, connect.NewError(connect.CodeUnauthenticated, auth.ErrUnauthenticated)
	}
	g, err := auth.LoadGrants(ctx, st.Queries, p.UserID)
	return p, g, err
}

// resolveVisible finds a server the caller may see. Servers the caller cannot see are
// reported as not found, so their existence is not revealed.
func resolveVisible(ctx context.Context, st *store.Store, g auth.Grants, nameOrID string) (db.Server, error) {
	s, err := fleet.Resolve(ctx, st.Queries, nameOrID)
	if errors.Is(err, fleet.ErrNotFound) || (err == nil && !g.CanSee(s.GroupID)) {
		return db.Server{}, connect.NewError(connect.CodeNotFound, fmt.Errorf("server %q not found", nameOrID))
	}
	return s, err
}

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

// ListServers implements FleetService.ListServers.
func (s *FleetServer) ListServers(ctx context.Context, _ *connect.Request[operatorv1.ListServersRequest]) (*connect.Response[operatorv1.ListServersResponse], error) {
	_, g, err := grantsFor(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	rows, err := s.Store.ListServersWithMetrics(ctx)
	if err != nil {
		return nil, err
	}
	resp := &operatorv1.ListServersResponse{}
	for _, r := range rows {
		if !g.CanSee(r.GroupID) {
			continue
		}
		srv := &operatorv1.Server{
			Id: r.ID.String(), Name: r.Name, Group: deref(r.GroupName), Status: r.Status, Hostname: r.Hostname,
			Distro: r.Distro, DistroVersion: r.DistroVersion, AgentVersion: r.AgentVersion, LastSeenAt: ts(r.LastSeenAt),
		}
		if r.CollectedAt != nil {
			srv.Metrics = &operatorv1.ServerMetrics{
				CollectedAt: ts(r.CollectedAt), CpuPercent: deref(r.CpuPercent), CpuCount: uint32(max(deref(r.CpuCount), 0)), //nolint:gosec // non-negative
				Load1: deref(r.Load1), MemoryTotalBytes: uint64(max(deref(r.MemoryTotalBytes), 0)), //nolint:gosec // non-negative
				MemoryAvailableBytes: uint64(max(deref(r.MemoryAvailableBytes), 0)), //nolint:gosec // non-negative
				DiskMaxUsedPercent:   deref(r.DiskMaxUsedPercent), DiskMaxMount: deref(r.DiskMaxMount),
				NetRxBytesPerSecond: deref(r.NetRxBytesPerSecond), NetTxBytesPerSecond: deref(r.NetTxBytesPerSecond),
				UptimeSeconds: uint64(max(deref(r.UptimeSeconds), 0)), //nolint:gosec // non-negative
			}
			if r.ContainersRunning != nil {
				n := uint32(max(*r.ContainersRunning, 0)) //nolint:gosec // non-negative
				srv.Metrics.ContainersRunning = &n
				srv.Metrics.ContainersMemoryBytes = uint64(max(deref(r.ContainersMemoryBytes), 0)) //nolint:gosec // non-negative
			}
		}
		resp.Servers = append(resp.Servers, srv)
	}
	return connect.NewResponse(resp), nil
}

// CreateEnrollmentToken implements FleetService.CreateEnrollmentToken.
func (s *FleetServer) CreateEnrollmentToken(ctx context.Context, req *connect.Request[operatorv1.CreateEnrollmentTokenRequest]) (*connect.Response[operatorv1.CreateEnrollmentTokenResponse], error) {
	p, g, err := grantsFor(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	var groupID *uuid.UUID
	if name := req.Msg.GetGroup(); name != "" {
		grp, err := s.Store.GetServerGroupByName(ctx, name)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, enroll.ErrGroupMissing)
		} else if err != nil {
			return nil, err
		}
		groupID = &grp.ID
	}
	if err := auth.AuthorizeAction(g, p, db.Server{Name: "new server", GroupID: groupID}, command.RiskHigh, time.Now()); err != nil {
		return nil, mapAuthErr(err)
	}
	tok, err := enroll.CreateToken(ctx, s.Store, enroll.TokenRequest{
		ServerName: req.Msg.GetServerName(), GroupName: req.Msg.GetGroup(),
		TTL: time.Duration(req.Msg.GetTtlSeconds()) * time.Second, Actor: p.Actor(),
	})
	switch {
	case errors.Is(err, enroll.ErrInvalidName), errors.Is(err, enroll.ErrNameInUse):
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	case err != nil:
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return connect.NewResponse(&operatorv1.CreateEnrollmentTokenResponse{
		Token: tok.Value, ExpiresAt: timestamppb.New(tok.ExpiresAt), Pin: s.Pin, ApiUrl: s.APIURL,
	}), nil
}

// RevokeServer implements FleetService.RevokeServer.
func (s *FleetServer) RevokeServer(ctx context.Context, req *connect.Request[operatorv1.RevokeServerRequest]) (*connect.Response[operatorv1.RevokeServerResponse], error) {
	p, g, err := grantsFor(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	if req.Msg.GetReason() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("a reason is required"))
	}
	srv, err := resolveVisible(ctx, s.Store, g, req.Msg.GetServer())
	if err != nil {
		return nil, err
	}
	if err := auth.AuthorizeAction(g, p, srv, command.RiskHigh, time.Now()); err != nil {
		return nil, mapAuthErr(err)
	}
	if err := fleet.Revoke(ctx, s.Store, srv.ID, p.Actor(), req.Msg.GetReason()); errors.Is(err, fleet.ErrAlreadyRevoked) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	} else if err != nil {
		return nil, err
	}
	return connect.NewResponse(&operatorv1.RevokeServerResponse{}), nil
}

// ListAuditEvents implements FleetService.ListAuditEvents.
func (s *FleetServer) ListAuditEvents(ctx context.Context, req *connect.Request[operatorv1.ListAuditEventsRequest]) (*connect.Response[operatorv1.ListAuditEventsResponse], error) {
	_, g, err := grantsFor(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	if !g.Has(nil, auth.RoleAdmin) {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("%w: the audit log needs the global admin role", auth.ErrForbidden))
	}
	limit := req.Msg.GetLimit()
	if limit == 0 {
		limit = 100
	}
	rows, err := s.Store.ListAuditEvents(ctx, db.ListAuditEventsParams{AfterID: req.Msg.GetAfterId(), MaxRows: int32(min(limit, 1000))}) //nolint:gosec // capped
	if err != nil {
		return nil, err
	}
	resp := &operatorv1.ListAuditEventsResponse{}
	for _, r := range rows {
		ev := &operatorv1.AuditEvent{
			Id: r.ID, Time: timestamppb.New(r.Ts), ActorType: r.ActorType, ActorId: r.ActorID,
			Action: r.Action, Result: r.Result, Params: map[string]string{},
		}
		if r.SourceIP != nil {
			ev.SourceIp = r.SourceIP.String()
		}
		if r.ServerID != nil {
			ev.ServerId = r.ServerID.String()
		}
		_ = json.Unmarshal(r.Params, &ev.Params)
		resp.Events = append(resp.Events, ev)
	}
	return connect.NewResponse(resp), nil
}
