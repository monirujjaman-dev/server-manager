package enroll_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/time/rate"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1/agentv1connect"
	"github.com/monirujjaman-dev/server-manager/internal/pki"
	"github.com/monirujjaman-dev/server-manager/internal/server/audit"
	"github.com/monirujjaman-dev/server-manager/internal/server/enroll"
	"github.com/monirujjaman-dev/server-manager/internal/server/fleet"
	"github.com/monirujjaman-dev/server-manager/internal/server/store"
	"github.com/monirujjaman-dev/server-manager/internal/server/store/storetest"
)

type env struct {
	st     *store.Store
	ca     *pki.CA
	svc    *enroll.Service
	client agentv1connect.EnrollmentServiceClient
}

func newEnv(t *testing.T, opts enroll.Options) *env {
	t.Helper()
	st, _ := storetest.Open(t)
	ca, err := pki.CreateCA("Test")
	if err != nil {
		t.Fatal(err)
	}
	srvCert, srvKey, err := ca.IssueServerCert(nil, []net.IP{net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	opts.AgentURL = "https://cp.test:8443"
	svc := enroll.NewService(st, ca, opts)
	mux := http.NewServeMux()
	mux.Handle(svc.Handler())
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{ca.TLSCertificate(srvCert, srvKey)}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: ca.RootPool()}}}
	return &env{st: st, ca: ca, svc: svc, client: agentv1connect.NewEnrollmentServiceClient(hc, srv.URL)}
}

func (e *env) token(t *testing.T, name string) string {
	t.Helper()
	tok, err := enroll.CreateToken(context.Background(), e.st, enroll.TokenRequest{ServerName: name, Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return tok.Value
}

func (e *env) enroll(token string, csr []byte) (*agentv1.EnrollResponse, error) {
	resp, err := e.client.Enroll(context.Background(), connect.NewRequest(&agentv1.EnrollRequest{
		Token: token, Csr: csr, AgentVersion: "test", Host: &agentv1.HostFacts{Hostname: "h1"},
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func csr(t *testing.T) []byte {
	t.Helper()
	_, c, err := pki.NewAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEnrollIssuesRecordedCertificate(t *testing.T) {
	e := newEnv(t, enroll.Options{})
	ctx := context.Background()
	resp, err := e.enroll(e.token(t, "web-1"), csr(t))
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetServerName() != "web-1" || resp.GetAgentUrl() != "https://cp.test:8443" || len(resp.GetCertificateChain()) != 2 {
		t.Fatalf("unexpected response %+v", resp)
	}
	leaf, err := x509.ParseCertificate(resp.GetCertificateChain()[0])
	if err != nil {
		t.Fatal(err)
	}
	id, err := pki.AgentID(leaf)
	if err != nil || id.String() != resp.GetServerId() {
		t.Fatalf("identity %v %v, want %s", id, err, resp.GetServerId())
	}
	srv, err := e.st.GetServer(ctx, id)
	if err != nil || srv.Name != "web-1" || srv.Status != "pending" {
		t.Fatalf("server row %+v, %v", srv, err)
	}
	rejected, err := fleet.Revocations{Q: e.st.Queries}.IsRevoked(ctx, leaf.SerialNumber)
	if err != nil || rejected {
		t.Fatalf("issued certificate rejected=%v err=%v", rejected, err)
	}
	if n, err := audit.Verify(ctx, e.st.Queries); err != nil || n != 2 { // token_create + agent.enroll
		t.Fatalf("audit verify = %d, %v", n, err)
	}
}

func TestTokenIsSingleUse(t *testing.T) {
	e := newEnv(t, enroll.Options{})
	tok := e.token(t, "web-1")
	if _, err := e.enroll(tok, csr(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.enroll(tok, csr(t)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("second use: %v", err)
	}
}

func TestExpiredAndUnknownTokensRejected(t *testing.T) {
	e := newEnv(t, enroll.Options{})
	tok := e.token(t, "web-1")
	if _, err := e.st.Pool.Exec(context.Background(),
		"UPDATE enrollment_tokens SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour'"); err != nil {
		t.Fatal(err)
	}
	for name, tk := range map[string]string{
		"expired":   tok,
		"unknown":   enroll.TokenPrefix + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"malformed": "not-a-token",
	} {
		if _, err := e.enroll(tk, csr(t)); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Errorf("%s token: %v", name, err)
		}
	}
	var denied int
	if err := e.st.Pool.QueryRow(context.Background(), "SELECT count(*) FROM audit_events WHERE result = 'denied'").Scan(&denied); err != nil || denied != 3 {
		t.Errorf("denied audit events = %d, %v", denied, err)
	}
}

func TestBadCSRDoesNotBurnToken(t *testing.T) {
	e := newEnv(t, enroll.Options{})
	tok := e.token(t, "web-1")
	if _, err := e.enroll(tok, []byte("garbage")); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad CSR: %v", err)
	}
	if _, err := e.enroll(tok, csr(t)); err != nil {
		t.Fatalf("token unusable after bad CSR: %v", err)
	}
}

func TestCreateTokenValidation(t *testing.T) {
	e := newEnv(t, enroll.Options{})
	ctx := context.Background()
	e.token(t, "web-1")
	cases := map[string]struct {
		req  enroll.TokenRequest
		want error
	}{
		"bad name":      {enroll.TokenRequest{ServerName: "Web_1", Actor: "t"}, enroll.ErrInvalidName},
		"reserved name": {enroll.TokenRequest{ServerName: "web-1", Actor: "t"}, enroll.ErrNameInUse},
		"no group":      {enroll.TokenRequest{ServerName: "web-2", GroupName: "nope", Actor: "t"}, enroll.ErrGroupMissing},
		"ttl too long":  {enroll.TokenRequest{ServerName: "web-3", TTL: 48 * time.Hour, Actor: "t"}, nil},
	}
	for name, tc := range cases {
		_, err := enroll.CreateToken(ctx, e.st, tc.req)
		if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
}

func TestRateLimited(t *testing.T) {
	e := newEnv(t, enroll.Options{RateLimit: rate.Every(time.Hour), RateBurst: 2})
	var last error
	for range 3 {
		_, last = e.enroll("not-a-token", csr(t))
	}
	if connect.CodeOf(last) != connect.CodeResourceExhausted {
		t.Fatalf("third attempt: %v", last)
	}
}

func TestRenewRequiresAgedCertificate(t *testing.T) {
	e := newEnv(t, enroll.Options{})
	resp, err := e.enroll(e.token(t, "web-1"), csr(t))
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(resp.GetCertificateChain()[0])
	id, _ := pki.AgentID(leaf)
	if _, err := e.svc.RenewAgentCertificate(context.Background(), id, leaf, csr(t)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("renewing a fresh certificate: %v", err)
	}
}
