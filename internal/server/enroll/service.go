package enroll

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/time/rate"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1/agentv1connect"
	"github.com/monirujjaman-dev/server-manager/internal/pki"
	"github.com/monirujjaman-dev/server-manager/internal/server/audit"
	"github.com/monirujjaman-dev/server-manager/internal/server/gateway"
	"github.com/monirujjaman-dev/server-manager/internal/server/store"
	"github.com/monirujjaman-dev/server-manager/internal/server/store/db"
)

// errBadToken is deliberately vague: callers learn nothing about why a token failed.
var errBadToken = errors.New("invalid, used or expired enrollment token")

// Service implements agentv1connect.EnrollmentServiceHandler and gateway.CertRenewer.
type Service struct {
	agentv1connect.UnimplementedEnrollmentServiceHandler

	st       *store.Store
	ca       *pki.CA
	agentURL string
	log      *slog.Logger
	limiter  *ipLimiter
	// renewAfter is the fraction of a certificate's lifetime that must have passed
	// before it can be renewed.
	renewAfter float64
}

// Options configures a Service.
type Options struct {
	// AgentURL is returned to enrolling agents (public agent gateway URL).
	AgentURL string
	Logger   *slog.Logger
	// RenewAfter is the fraction of lifetime after which renewal is allowed (default 0.5).
	RenewAfter float64
	// RateLimit and RateBurst bound enrollment attempts per source IP (default 5/min, burst 5).
	RateLimit rate.Limit
	RateBurst int
}

// NewService creates the enrollment service.
func NewService(st *store.Store, ca *pki.CA, opts Options) *Service {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.RenewAfter <= 0 || opts.RenewAfter >= 1 {
		opts.RenewAfter = 0.5
	}
	if opts.RateLimit == 0 {
		opts.RateLimit = rate.Every(12 * time.Second)
	}
	if opts.RateBurst == 0 {
		opts.RateBurst = 5
	}
	return &Service{
		st: st, ca: ca, agentURL: opts.AgentURL, log: opts.Logger,
		limiter: newIPLimiter(opts.RateLimit, opts.RateBurst), renewAfter: opts.RenewAfter,
	}
}

// Handler returns the route and handler for the enrollment service.
func (s *Service) Handler() (string, http.Handler) {
	return agentv1connect.NewEnrollmentServiceHandler(s, connect.WithReadMaxBytes(64<<10))
}

func peerIP(addr string) *netip.Addr {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil
	}
	a := ap.Addr().Unmap()
	return &a
}

// Enroll exchanges a valid token and CSR for an agent certificate.
func (s *Service) Enroll(ctx context.Context, req *connect.Request[agentv1.EnrollRequest]) (*connect.Response[agentv1.EnrollResponse], error) {
	ip := peerIP(req.Peer().Addr)
	if ip != nil && !s.limiter.allow(*ip) {
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("too many enrollment attempts; try again later"))
	}
	m := req.Msg
	hash, err := hashToken(m.GetToken())
	if err != nil {
		s.recordFailure(ctx, ip, "malformed token")
		return nil, connect.NewError(connect.CodePermissionDenied, errBadToken)
	}
	if err := gateway.ValidateHostFacts(m.GetHost()); err != nil || len(m.GetAgentVersion()) > 256 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid host facts"))
	}
	// Validate the CSR before consuming the token, so a bad CSR does not burn it.
	if _, err := x509.ParseCertificateRequest(m.GetCsr()); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid certificate request"))
	}

	tx, err := s.st.Pool.Begin(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("database unavailable"))
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.st.WithTx(tx)

	tok, err := q.ConsumeEnrollmentToken(ctx, hash)
	if errors.Is(err, pgx.ErrNoRows) {
		_ = tx.Rollback(ctx)
		s.recordFailure(ctx, ip, "unknown, used or expired token")
		return nil, connect.NewError(connect.CodePermissionDenied, errBadToken)
	} else if err != nil {
		return nil, s.internal("consume token", err)
	}

	id := uuid.New()
	if _, err := q.CreateServer(ctx, db.CreateServerParams{ID: id, Name: tok.ServerName, GroupID: tok.GroupID}); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("server name is already in use; create a token with another name"))
		}
		return nil, s.internal("create server", err)
	}
	if err := q.SetEnrollmentTokenServer(ctx, db.SetEnrollmentTokenServerParams{ID: tok.ID, ServerID: &id}); err != nil {
		return nil, s.internal("link token", err)
	}
	cert, err := s.ca.SignAgentCSR(m.GetCsr(), id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := s.recordCert(ctx, q, id, cert); err != nil {
		return nil, s.internal("record certificate", err)
	}
	if _, err := audit.Append(ctx, q, audit.Event{
		ActorType: audit.ActorAgent, ActorID: id.String(), SourceIP: ip, ServerID: &id, Action: "agent.enroll",
		Params: map[string]string{
			"server_name": tok.ServerName, "token_id": tok.ID.String(), "hostname": m.GetHost().GetHostname(),
			"certificate_serial": cert.SerialNumber.Text(16), "agent_version": m.GetAgentVersion(),
		},
		Result: audit.Succeeded,
	}); err != nil {
		return nil, s.internal("audit", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, s.internal("commit", err)
	}
	s.log.Info("agent enrolled", "server_id", id.String(), "server_name", tok.ServerName, "source_ip", ipString(ip))
	return connect.NewResponse(&agentv1.EnrollResponse{
		ServerId:         id.String(),
		ServerName:       tok.ServerName,
		CertificateChain: [][]byte{cert.Raw, s.ca.Intermediate.Raw},
		CaCertificate:    s.ca.Root.Raw,
		AgentUrl:         s.agentURL,
	}), nil
}

// RenewAgentCertificate implements gateway.CertRenewer.
func (s *Service) RenewAgentCertificate(ctx context.Context, id uuid.UUID, current *x509.Certificate, csr []byte) ([][]byte, error) {
	lifetime := current.NotAfter.Sub(current.NotBefore)
	earliest := current.NotBefore.Add(time.Duration(float64(lifetime) * s.renewAfter))
	if time.Now().Before(earliest) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("certificate is too new to renew"))
	}
	tx, err := s.st.Pool.Begin(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("database unavailable"))
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.st.WithTx(tx)

	cert, err := s.ca.SignAgentCSR(csr, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := s.recordCert(ctx, q, id, cert); err != nil {
		return nil, s.internal("record certificate", err)
	}
	if _, err := audit.Append(ctx, q, audit.Event{
		ActorType: audit.ActorAgent, ActorID: id.String(), ServerID: &id, Action: "agent.certificate_renew",
		Params: map[string]string{
			"old_serial": current.SerialNumber.Text(16), "new_serial": cert.SerialNumber.Text(16),
			"not_after": cert.NotAfter.UTC().Format(time.RFC3339),
		},
		Result: audit.Succeeded,
	}); err != nil {
		return nil, s.internal("audit", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, s.internal("commit", err)
	}
	return [][]byte{cert.Raw, s.ca.Intermediate.Raw}, nil
}

func (s *Service) recordCert(ctx context.Context, q *db.Queries, id uuid.UUID, cert *x509.Certificate) error {
	return q.InsertAgentCertificate(ctx, db.InsertAgentCertificateParams{
		Serial: cert.SerialNumber.Text(16), ServerID: id, NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
	})
}

// recordFailure audits a rejected enrollment in its own transaction.
func (s *Service) recordFailure(ctx context.Context, ip *netip.Addr, reason string) {
	s.log.Warn("enrollment rejected", "source_ip", ipString(ip), "reason", reason)
	tx, err := s.st.Pool.Begin(ctx)
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := audit.Append(ctx, s.st.WithTx(tx), audit.Event{
		ActorType: audit.ActorSystem, ActorID: "enrollment", SourceIP: ip, Action: "agent.enroll",
		Params: map[string]string{"reason": reason}, Result: audit.Denied,
	}); err != nil {
		s.log.Error("audit enrollment failure", "err", err)
		return
	}
	_ = tx.Commit(ctx)
}

func (s *Service) internal(step string, err error) error {
	s.log.Error("enrollment failed", "step", step, "err", err)
	return connect.NewError(connect.CodeInternal, errors.New("internal error"))
}

func ipString(ip *netip.Addr) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
