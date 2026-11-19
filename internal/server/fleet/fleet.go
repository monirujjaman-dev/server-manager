// Package fleet keeps the servers table in step with connected agents and implements
// database-backed certificate revocation.
package fleet

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/big"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/internal/server/audit"
	"github.com/monirujjaman-dev/server-manager/internal/server/gateway"
	"github.com/monirujjaman-dev/server-manager/internal/server/store"
	"github.com/monirujjaman-dev/server-manager/internal/server/store/db"
)

// Revocations is a pki.RevocationChecker backed by the agent_certificates table. A
// certificate is rejected when it is revoked, its server is revoked, or it is unknown.
type Revocations struct {
	Q *db.Queries
}

// IsRevoked implements pki.RevocationChecker.
func (r Revocations) IsRevoked(ctx context.Context, serial *big.Int) (bool, error) {
	return r.Q.CertificateRejected(ctx, serial.Text(16))
}

// Hooks implements the connection-related gateway hooks on top of the servers table.
type Hooks struct {
	Q   *db.Queries
	Log *slog.Logger
}

// OnHello records host facts and marks the server online. Unknown or revoked servers
// are rejected.
func (h Hooks) OnHello(ctx context.Context, id uuid.UUID, hello *agentv1.Hello) error {
	f := hello.GetHost()
	n, err := h.Q.UpdateServerFacts(ctx, db.UpdateServerFactsParams{
		ID: id, Hostname: f.GetHostname(), OS: f.GetOs(), Arch: f.GetArch(), Kernel: f.GetKernel(),
		Distro: f.GetDistro(), DistroVersion: f.GetDistroVersion(), AgentVersion: hello.GetAgentVersion(),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return gateway.ErrAgentRevoked
	}
	return nil
}

// OnHeartbeat updates last_seen_at. Zero updated rows means the server was revoked
// while connected, which ends the stream within one heartbeat interval.
func (h Hooks) OnHeartbeat(ctx context.Context, id uuid.UUID) error {
	n, err := h.Q.MarkServerSeen(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return gateway.ErrAgentRevoked
	}
	return nil
}

// OnDisconnect marks the server offline.
func (h Hooks) OnDisconnect(ctx context.Context, id uuid.UUID) {
	if err := h.Q.SetServerOffline(ctx, id); err != nil && h.Log != nil {
		h.Log.Warn("mark server offline", "server_id", id.String(), "err", err)
	}
}

// ErrNotFound is returned when no server matches.
var ErrNotFound = errors.New("server not found")

// ErrAlreadyRevoked is returned when revoking a revoked server.
var ErrAlreadyRevoked = errors.New("server already revoked")

// Resolve finds a server by UUID or name.
func Resolve(ctx context.Context, q *db.Queries, nameOrID string) (db.Server, error) {
	var (
		s   db.Server
		err error
	)
	if id, perr := uuid.Parse(nameOrID); perr == nil {
		s, err = q.GetServer(ctx, id)
	} else {
		s, err = q.GetServerByName(ctx, nameOrID)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return s, ErrNotFound
	}
	return s, err
}

// Revoke marks a server revoked and revokes all its certificates in one transaction.
// New connections are refused immediately; an open stream is closed at its next
// heartbeat.
func Revoke(ctx context.Context, st *store.Store, id uuid.UUID, actor string, reason string) error {
	tx, err := st.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := st.WithTx(tx)
	n, err := q.RevokeServer(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		if _, err := q.GetServer(ctx, id); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return ErrAlreadyRevoked
	}
	certs, err := q.RevokeServerCertificates(ctx, id)
	if err != nil {
		return err
	}
	if _, err := audit.Append(ctx, q, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor, ServerID: &id, Action: "server.revoke",
		Params: map[string]string{"reason": reason, "certificates_revoked": fmt.Sprint(certs)}, Result: audit.Succeeded,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
