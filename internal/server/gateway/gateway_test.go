package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1/agentv1connect"
	"github.com/monirujjaman-dev/server-manager/internal/pki"
)

type env struct {
	gw     *Gateway
	client agentv1connect.AgentServiceClient
	id     uuid.UUID
}

func newEnv(t *testing.T, opts Options) *env {
	t.Helper()
	return newEnvWithAgentLifetime(t, opts, 0)
}

// newEnvWithAgentLifetime issues the agent certificate so that it expires after
// lifetime (0 = normal validity).
func newEnvWithAgentLifetime(t *testing.T, opts Options, lifetime time.Duration) *env {
	t.Helper()
	ca, err := pki.CreateCA("Test")
	if err != nil {
		t.Fatal(err)
	}
	srvCert, srvKey, err := ca.IssueServerCert(nil, []net.IP{net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	key, csr, _ := pki.NewAgentKey()
	id := uuid.New()
	if lifetime > 0 {
		ca.Now = func() time.Time { return time.Now().Add(lifetime - pki.AgentCertValidity) }
	}
	agentCert, err := ca.SignAgentCSR(csr, id)
	ca.Now = nil
	if err != nil {
		t.Fatal(err)
	}

	gw := New(opts)
	mux := http.NewServeMux()
	mux.Handle(gw.Handler())
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.TLS = pki.AgentServerTLSConfig(ca, ca.TLSCertificate(srvCert, srvKey), pki.NewRevocationList())
	srv.StartTLS()
	t.Cleanup(srv.Close)

	clientCert := ca.TLSCertificate(agentCert, key)
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	hc := &http.Client{Transport: &http.Transport{
		Protocols:       protocols,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: ca.RootPool(), Certificates: []tls.Certificate{clientCert}},
	}}
	return &env{gw: gw, client: agentv1connect.NewAgentServiceClient(hc, srv.URL, connect.WithGRPC()), id: id}
}

func hello() *agentv1.ConnectRequest {
	return &agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_Hello{Hello: &agentv1.Hello{
		AgentVersion: "test", Host: &agentv1.HostFacts{Hostname: "h"},
	}}}
}

func heartbeat(seq uint64) *agentv1.ConnectRequest {
	return &agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_Heartbeat{Heartbeat: &agentv1.Heartbeat{Seq: seq}}}
}

// connectAndWelcome opens a stream, sends hello and waits for the welcome.
func (e *env) connectAndWelcome(t *testing.T, ctx context.Context) *connect.BidiStreamForClient[agentv1.ConnectRequest, agentv1.ConnectResponse] {
	t.Helper()
	s := e.client.Connect(ctx)
	t.Cleanup(func() { _ = s.CloseRequest(); _ = s.CloseResponse() })
	if err := s.Send(hello()); err != nil {
		t.Fatal(err)
	}
	m, err := s.Receive()
	if err != nil {
		t.Fatalf("receive welcome: %v", err)
	}
	if m.GetWelcome().GetServerId() != e.id.String() {
		t.Fatalf("welcome = %v", m)
	}
	return s
}

// drainCode reads until the stream ends and returns the error code.
func drainCode(s *connect.BidiStreamForClient[agentv1.ConnectRequest, agentv1.ConnectResponse]) connect.Code {
	for {
		if _, err := s.Receive(); err != nil {
			return connect.CodeOf(err)
		}
	}
}

func TestHeartbeatAcked(t *testing.T) {
	e := newEnv(t, Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := e.connectAndWelcome(t, ctx)
	if err := s.Send(heartbeat(1)); err != nil {
		t.Fatal(err)
	}
	m, err := s.Receive()
	if err != nil || m.GetHeartbeatAck().GetSeq() != 1 {
		t.Fatalf("ack = %v, %v", m, err)
	}
	if e.gw.Registry().Len() != 1 {
		t.Fatal("session not registered")
	}
}

func TestFirstMessageMustBeHello(t *testing.T) {
	e := newEnv(t, Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := e.client.Connect(ctx)
	_ = s.Send(heartbeat(1))
	if code := drainCode(s); code != connect.CodeInvalidArgument {
		t.Fatalf("code = %v", code)
	}
}

func TestHelloTimeout(t *testing.T) {
	e := newEnv(t, Options{HelloTimeout: 100 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := e.client.Connect(ctx)
	_ = s.Send(nil) // open the stream without sending a message
	if code := drainCode(s); code != connect.CodeDeadlineExceeded {
		t.Fatalf("code = %v", code)
	}
}

func TestHeartbeatSequenceMustIncrease(t *testing.T) {
	e := newEnv(t, Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := e.connectAndWelcome(t, ctx)
	_ = s.Send(heartbeat(5))
	if _, err := s.Receive(); err != nil {
		t.Fatal(err)
	}
	_ = s.Send(heartbeat(5)) // replayed
	if code := drainCode(s); code != connect.CodeInvalidArgument {
		t.Fatalf("code = %v", code)
	}
}

func TestMissedHeartbeatsCloseStream(t *testing.T) {
	e := newEnv(t, Options{HeartbeatInterval: 50 * time.Millisecond, MissedHeartbeats: 2})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := e.connectAndWelcome(t, ctx)
	if code := drainCode(s); code != connect.CodeDeadlineExceeded {
		t.Fatalf("code = %v", code)
	}
}

func TestNewConnectionReplacesOld(t *testing.T) {
	var disconnects int
	e := newEnv(t, Options{Hooks: countingHooks{disconnects: &disconnects}})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	first := e.connectAndWelcome(t, ctx)
	second := e.connectAndWelcome(t, ctx)
	if code := drainCode(first); code != connect.CodeAborted {
		t.Fatalf("old stream code = %v", code)
	}
	// The new session must still be registered and working.
	_ = second.Send(heartbeat(1))
	if m, err := second.Receive(); err != nil || m.GetHeartbeatAck() == nil {
		t.Fatalf("second stream broken: %v %v", m, err)
	}
	if e.gw.Registry().Len() != 1 {
		t.Fatalf("registry has %d sessions", e.gw.Registry().Len())
	}
	if disconnects != 0 {
		t.Fatalf("OnDisconnect called %d times for a replaced session", disconnects)
	}
}

func TestOnHelloRejects(t *testing.T) {
	e := newEnv(t, Options{Hooks: rejectHooks{}})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := e.client.Connect(ctx)
	_ = s.Send(hello())
	if code := drainCode(s); code != connect.CodePermissionDenied {
		t.Fatalf("code = %v", code)
	}
}

type countingHooks struct {
	NopHooks
	disconnects *int
}

func (h countingHooks) OnDisconnect(context.Context, uuid.UUID) { *h.disconnects++ }

type rejectHooks struct{ NopHooks }

func (rejectHooks) OnHello(context.Context, uuid.UUID, *agentv1.Hello) error {
	return errors.New("server is revoked")
}

func TestStreamEndsWhenCertificateExpires(t *testing.T) {
	e := newEnvWithAgentLifetime(t, Options{}, 1500*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := e.connectAndWelcome(t, ctx)
	start := time.Now()
	if code := drainCode(s); code != connect.CodeUnauthenticated {
		t.Fatalf("code = %v", code)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("stream ended after %v, want about 1.5s", d)
	}
}

func TestRenewWithoutRenewerIsUnimplemented(t *testing.T) {
	e := newEnv(t, Options{})
	_, err := e.client.RenewCertificate(context.Background(), connect.NewRequest(&agentv1.RenewCertificateRequest{}))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("err = %v", err)
	}
}

func TestRevokedDuringHeartbeatClosesStream(t *testing.T) {
	e := newEnv(t, Options{Hooks: revokeOnHeartbeat{}})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := e.connectAndWelcome(t, ctx)
	_ = s.Send(heartbeat(1))
	if code := drainCode(s); code != connect.CodePermissionDenied {
		t.Fatalf("code = %v", code)
	}
}

type revokeOnHeartbeat struct{ NopHooks }

func (revokeOnHeartbeat) OnHeartbeat(context.Context, uuid.UUID) error { return ErrAgentRevoked }
