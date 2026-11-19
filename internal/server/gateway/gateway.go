// Package gateway serves the long-lived agent streams on the mTLS listener.
package gateway

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1/agentv1connect"
	"github.com/monirujjaman-dev/server-manager/internal/pki"
)

const (
	// maxMessageBytes bounds every message an agent can send.
	maxMessageBytes = 1 << 20
	// maxFieldLen bounds free-text fields in Hello.
	maxFieldLen = 256
)

// Errors used as cancellation causes.
var (
	ErrReplaced = errors.New("replaced by a newer connection from the same server")
	ErrShutdown = errors.New("control plane shutting down")
)

// ErrAgentRevoked is returned by Hooks when the server has been revoked or is unknown.
// The gateway then closes the stream. Other hook errors (for example a database outage)
// are logged and the stream stays open, so a short outage does not drop the fleet.
var ErrAgentRevoked = errors.New("server revoked or unknown")

var errCertExpired = errors.New("agent certificate expired")

// CertRenewer issues renewed agent certificates.
type CertRenewer interface {
	// RenewAgentCertificate returns the DER chain (leaf, intermediate) of a new
	// certificate for id. Errors should be *connect.Error values.
	RenewAgentCertificate(ctx context.Context, id uuid.UUID, current *x509.Certificate, csr []byte) ([][]byte, error)
}

// Hooks lets the control plane persist agent state. All methods are optional to
// implement through NopHooks; an error from OnHello rejects the connection.
type Hooks interface {
	OnHello(ctx context.Context, id uuid.UUID, hello *agentv1.Hello) error
	OnHeartbeat(ctx context.Context, id uuid.UUID) error
	OnDisconnect(ctx context.Context, id uuid.UUID)
}

// NopHooks does nothing.
type NopHooks struct{}

func (NopHooks) OnHello(context.Context, uuid.UUID, *agentv1.Hello) error { return nil }
func (NopHooks) OnHeartbeat(context.Context, uuid.UUID) error             { return nil }
func (NopHooks) OnDisconnect(context.Context, uuid.UUID)                  {}

// Options configures a Gateway.
type Options struct {
	Logger *slog.Logger
	Hooks  Hooks
	// Revocations is checked on every stream, not only at TLS handshake time: HTTP/2
	// reuses connections, so a revoked agent could otherwise open new streams on a
	// connection established before the revocation.
	Revocations       pki.RevocationChecker
	Renewer           CertRenewer
	HeartbeatInterval time.Duration // default 15s
	HelloTimeout      time.Duration // default 10s
	// MissedHeartbeats is how many intervals may pass without a heartbeat before the
	// stream is closed. Default 3.
	MissedHeartbeats int
}

// Gateway implements agentv1connect.AgentServiceHandler.
type Gateway struct {
	agentv1connect.UnimplementedAgentServiceHandler

	reg   *Registry
	opts  Options
	log   *slog.Logger
	hooks Hooks
	now   func() time.Time
}

// New creates a gateway.
func New(opts Options) *Gateway {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Hooks == nil {
		opts.Hooks = NopHooks{}
	}
	if opts.HeartbeatInterval <= 0 {
		opts.HeartbeatInterval = 15 * time.Second
	}
	if opts.HelloTimeout <= 0 {
		opts.HelloTimeout = 10 * time.Second
	}
	if opts.MissedHeartbeats <= 0 {
		opts.MissedHeartbeats = 3
	}
	return &Gateway{reg: NewRegistry(), opts: opts, log: opts.Logger, hooks: opts.Hooks, now: time.Now}
}

// Registry exposes the connected-agent registry.
func (g *Gateway) Registry() *Registry { return g.reg }

// Handler returns the HTTP route and handler for the agent service, wrapped so that
// every request must carry a verified agent client certificate.
func (g *Gateway) Handler() (string, http.Handler) {
	path, h := agentv1connect.NewAgentServiceHandler(g, connect.WithReadMaxBytes(maxMessageBytes))
	return path, g.requireAgentIdentity(h)
}

type ctxKey struct{}

type identity struct {
	id   uuid.UUID
	cert *x509.Certificate
}

// requireAgentIdentity extracts the server ID from the verified client certificate and
// re-checks revocation for every request. The TLS layer already rejects bad
// certificates at handshake time; this is a second, independent check.
func (g *Gateway) requireAgentIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		leaf := r.TLS.VerifiedChains[0][0]
		id, err := pki.AgentID(leaf)
		if err != nil {
			http.Error(w, "invalid agent certificate", http.StatusUnauthorized)
			return
		}
		// HTTP/2 connections outlive the handshake that verified the certificate, so
		// expiry is checked per request too.
		if time.Now().After(leaf.NotAfter) {
			http.Error(w, "agent certificate expired", http.StatusUnauthorized)
			return
		}
		if g.opts.Revocations != nil {
			revoked, err := g.opts.Revocations.IsRevoked(r.Context(), leaf.SerialNumber)
			if err != nil || revoked {
				g.log.Warn("rejected agent request", "server_id", id.String(), "revoked", revoked, "err", err)
				http.Error(w, "agent certificate not accepted", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, identity{id: id, cert: leaf})))
	})
}

func identityFrom(ctx context.Context) (identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(identity)
	return id, ok
}

// RenewCertificate issues a fresh certificate for the calling agent.
func (g *Gateway) RenewCertificate(ctx context.Context, req *connect.Request[agentv1.RenewCertificateRequest]) (*connect.Response[agentv1.RenewCertificateResponse], error) {
	who, ok := identityFrom(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("no agent identity"))
	}
	if g.opts.Renewer == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("certificate renewal is not enabled"))
	}
	chain, err := g.opts.Renewer.RenewAgentCertificate(ctx, who.id, who.cert, req.Msg.GetCsr())
	if err != nil {
		g.log.Warn("certificate renewal failed", "server_id", who.id.String(), "err", err)
		return nil, err
	}
	g.log.Info("certificate renewed", "server_id", who.id.String())
	return connect.NewResponse(&agentv1.RenewCertificateResponse{CertificateChain: chain}), nil
}

// Connect handles one agent stream.
func (g *Gateway) Connect(ctx context.Context, stream *connect.BidiStream[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	who, ok := identityFrom(ctx)
	if !ok {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("no agent identity"))
	}
	id := who.id
	log := g.log.With("server_id", id.String(), "remote", stream.Peer().Addr)

	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	msgs := make(chan *agentv1.ConnectRequest)
	recvErr := make(chan error, 1)
	go func() {
		for {
			m, err := stream.Receive()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case msgs <- m:
			case <-ctx.Done():
				return
			}
		}
	}()

	// The first message must be Hello.
	hello, err := g.awaitHello(ctx, msgs, recvErr)
	if err != nil {
		log.Warn("agent handshake failed", "err", err)
		return err
	}
	if err := g.hooks.OnHello(ctx, id, hello); err != nil {
		log.Warn("agent rejected", "err", err)
		return connect.NewError(connect.CodePermissionDenied, errors.New("agent not allowed"))
	}

	now := g.now()
	sess := &session{
		info: SessionInfo{
			ServerID: id, RemoteAddr: stream.Peer().Addr, AgentVersion: hello.GetAgentVersion(),
			Hostname: hello.GetHost().GetHostname(), ConnectedAt: now, LastSeen: now,
		},
		cancel: cancel,
	}
	if old := g.reg.attach(sess); old != nil {
		old.cancel(ErrReplaced)
		log.Info("replacing existing agent session")
	}
	defer func() {
		g.reg.detach(sess)
		if !errors.Is(context.Cause(ctx), ErrReplaced) {
			g.hooks.OnDisconnect(context.WithoutCancel(ctx), id)
		}
		log.Info("agent disconnected", "cause", context.Cause(ctx))
	}()
	log.Info("agent connected", "agent_version", hello.GetAgentVersion(), "hostname", hello.GetHost().GetHostname())

	if err := stream.Send(&agentv1.ConnectResponse{Payload: &agentv1.ConnectResponse_Welcome{Welcome: &agentv1.Welcome{
		ServerId:          id.String(),
		HeartbeatInterval: durationpb.New(g.opts.HeartbeatInterval),
		ServerTime:        timestamppb.New(now),
	}}}); err != nil {
		return err
	}

	// End the stream when the certificate that authenticated it expires.
	if who.cert != nil {
		expiry := time.AfterFunc(time.Until(who.cert.NotAfter), func() { cancel(errCertExpired) })
		defer expiry.Stop()
	}

	idleLimit := g.opts.HeartbeatInterval * time.Duration(g.opts.MissedHeartbeats)
	idle := time.NewTimer(idleLimit)
	defer idle.Stop()
	var lastSeq uint64

	for {
		select {
		case m := <-msgs:
			switch p := m.GetPayload().(type) {
			case *agentv1.ConnectRequest_Heartbeat:
				seq := p.Heartbeat.GetSeq()
				if seq <= lastSeq {
					return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("heartbeat sequence %d not increasing", seq))
				}
				lastSeq = seq
				t := g.now()
				g.reg.touch(sess, t)
				idle.Reset(idleLimit)
				if err := g.hooks.OnHeartbeat(ctx, id); errors.Is(err, ErrAgentRevoked) {
					cancel(err)
					return connect.NewError(connect.CodePermissionDenied, err)
				} else if err != nil {
					log.Warn("heartbeat hook failed", "err", err)
				}
				if err := stream.Send(&agentv1.ConnectResponse{Payload: &agentv1.ConnectResponse_HeartbeatAck{
					HeartbeatAck: &agentv1.HeartbeatAck{Seq: seq, ServerTime: timestamppb.New(t)},
				}}); err != nil {
					return err
				}
			case *agentv1.ConnectRequest_Hello:
				return connect.NewError(connect.CodeInvalidArgument, errors.New("duplicate hello"))
			default:
				return connect.NewError(connect.CodeInvalidArgument, errors.New("unknown message"))
			}
		case err := <-recvErr:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case <-idle.C:
			cancel(errors.New("heartbeat timeout"))
			return connect.NewError(connect.CodeDeadlineExceeded, errors.New("heartbeat timeout"))
		case <-ctx.Done():
			cause := context.Cause(ctx)
			if errors.Is(cause, ErrReplaced) || errors.Is(cause, ErrShutdown) {
				return connect.NewError(connect.CodeAborted, cause)
			}
			if errors.Is(cause, errCertExpired) {
				return connect.NewError(connect.CodeUnauthenticated, cause)
			}
			return connect.NewError(connect.CodeCanceled, cause)
		}
	}
}

func (g *Gateway) awaitHello(ctx context.Context, msgs <-chan *agentv1.ConnectRequest, recvErr <-chan error) (*agentv1.Hello, error) {
	timer := time.NewTimer(g.opts.HelloTimeout)
	defer timer.Stop()
	select {
	case m := <-msgs:
		hello := m.GetHello()
		if hello == nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("first message must be hello"))
		}
		if err := ValidateHello(hello); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		return hello, nil
	case err := <-recvErr:
		return nil, err
	case <-timer.C:
		return nil, connect.NewError(connect.CodeDeadlineExceeded, errors.New("no hello received"))
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}

// ValidateHello bounds the free-text fields an agent reports.
func ValidateHello(h *agentv1.Hello) error {
	if h.GetAgentVersion() == "" {
		return errors.New("agent_version is required")
	}
	return validateFields(map[string]string{"agent_version": h.GetAgentVersion()}, h.GetHost())
}

// ValidateHostFacts bounds the free-text fields of host facts.
func ValidateHostFacts(f *agentv1.HostFacts) error {
	return validateFields(nil, f)
}

func validateFields(extra map[string]string, f *agentv1.HostFacts) error {
	fields := map[string]string{
		"hostname":       f.GetHostname(),
		"os":             f.GetOs(),
		"arch":           f.GetArch(),
		"kernel":         f.GetKernel(),
		"distro":         f.GetDistro(),
		"distro_version": f.GetDistroVersion(),
	}
	for k, v := range extra {
		fields[k] = v
	}
	for name, v := range fields {
		if len(v) > maxFieldLen {
			return fmt.Errorf("%s longer than %d bytes", name, maxFieldLen)
		}
	}
	return nil
}
