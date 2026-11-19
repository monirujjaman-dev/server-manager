package server_test

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"

	operatorv1 "github.com/monirujjaman-dev/server-manager/gen/sm/operator/v1"
	"github.com/monirujjaman-dev/server-manager/gen/sm/operator/v1/operatorv1connect"
	"github.com/monirujjaman-dev/server-manager/internal/agent"
	"github.com/monirujjaman-dev/server-manager/internal/pkg/config"
	"github.com/monirujjaman-dev/server-manager/internal/pki"
	"github.com/monirujjaman-dev/server-manager/internal/server"
	"github.com/monirujjaman-dev/server-manager/internal/server/audit"
	"github.com/monirujjaman-dev/server-manager/internal/server/enroll"
	"github.com/monirujjaman-dev/server-manager/internal/server/fleet"
	"github.com/monirujjaman-dev/server-manager/internal/server/store/storetest"
)

type controlPlane struct {
	srv     *server.Server
	ca      *pki.CA
	pin     string
	agentLn net.Listener
	apiLn   net.Listener
	stop    func()
}

// startControlPlane creates a PKI and a fresh database and serves on loopback.
func startControlPlane(t *testing.T, opts ...server.Option) *controlPlane {
	t.Helper()
	dbURL := storetest.NewDatabase(t)
	pkiDir := filepath.Join(t.TempDir(), "pki")
	ca, err := pki.CreateCA("Test")
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.SaveCA(pkiDir, ca); err != nil {
		t.Fatal(err)
	}
	srvCert, srvKey, err := ca.IssueServerCert([]string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.SaveServerCert(pkiDir, ca, srvCert, srvKey); err != nil {
		t.Fatal(err)
	}

	agentLn, _ := net.Listen("tcp", "127.0.0.1:0")
	apiLn, _ := net.Listen("tcp", "127.0.0.1:0")
	cfg := server.DefaultConfig()
	cfg.PKIDir = pkiDir
	cfg.DatabaseURL = dbURL
	cfg.HeartbeatInterval = time.Second
	cfg.PublicAgentURL = "https://" + agentLn.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	srv, err := server.New(ctx, cfg, slog.New(slog.DiscardHandler), opts...)
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx, agentLn, apiLn) }()
	cp := &controlPlane{srv: srv, ca: ca, pin: pki.SPKIFingerprint(srvCert), agentLn: agentLn, apiLn: apiLn}
	cp.stop = func() {
		cancel()
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Error("server did not shut down")
		}
		srv.Close()
	}
	return cp
}

// enrollAgent runs the real enrollment flow and returns the agent configuration.
func (cp *controlPlane) enrollAgent(t *testing.T, name string) (agent.Config, agent.EnrollResult) {
	t.Helper()
	tok, err := enroll.CreateToken(context.Background(), cp.srv.Store(), enroll.TokenRequest{ServerName: name, Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "agent")
	res, err := agent.Enroll(context.Background(), agent.EnrollOptions{
		APIURL: "https://" + cp.apiLn.Addr().String(), Token: tok.Value, Pin: cp.pin, Dir: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := agent.DefaultConfig()
	if err := config.Load(res.ConfigPath, "SM_AGENT_TEST_UNUSED_", &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.MinBackoff, cfg.MaxBackoff = 50*time.Millisecond, 200*time.Millisecond
	return cfg, res
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func runAgent(t *testing.T, cfg agent.Config) (*agent.Agent, func()) {
	t.Helper()
	ag, err := agent.New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ag.Run(ctx) }()
	return ag, func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("agent run: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("agent did not stop")
		}
	}
}

func TestEnrollConnectRevoke(t *testing.T) {
	cp := startControlPlane(t)
	defer cp.stop()
	ctx := context.Background()

	cfg, res := cp.enrollAgent(t, "web-1")
	if fi, err := os.Stat(cfg.KeyFile); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("agent key mode %v, %v", fi.Mode().Perm(), err)
	}
	if cfg.ServerURL != "https://"+cp.agentLn.Addr().String() {
		t.Fatalf("agent config server_url = %q", cfg.ServerURL)
	}

	ag, stopAgent := runAgent(t, cfg)
	defer stopAgent()

	waitFor(t, "heartbeat ack", func() bool { return !ag.Status().LastAck.IsZero() })
	if got := ag.Status().ServerID; got != res.ServerID {
		t.Fatalf("agent server ID %v, want %v", got, res.ServerID)
	}
	row, err := cp.srv.Store().GetServer(ctx, res.ServerID)
	if err != nil || row.Status != "online" || row.Hostname == "" || row.AgentVersion == "" || row.LastSeenAt == nil {
		t.Fatalf("server row after connect: %+v, %v", row, err)
	}

	t.Run("health check on API listener", func(t *testing.T) {
		hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: cp.ca.RootPool()},
		}}
		client := operatorv1connect.NewHealthServiceClient(hc, "https://"+cp.apiLn.Addr().String())
		resp, err := client.Check(ctx, connect.NewRequest(&operatorv1.CheckRequest{}))
		if err != nil || resp.Msg.GetStatus() != operatorv1.ServingStatus_SERVING_STATUS_SERVING {
			t.Fatalf("health: %v %v", resp, err)
		}
	})

	t.Run("agent port rejects clients without certificate", func(t *testing.T) {
		hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: cp.ca.RootPool()},
		}}
		resp, err := hc.Get("https://" + cp.agentLn.Addr().String() + "/sm.agent.v1.AgentService/Connect")
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("request without client certificate got HTTP %d", resp.StatusCode)
		}
	})

	t.Run("certificate signed by the CA but not issued through enrollment is rejected", func(t *testing.T) {
		rogue := cfg
		dir := t.TempDir()
		key, csr, _ := pki.NewAgentKey()
		cert, err := cp.ca.SignAgentCSR(csr, res.ServerID) // same identity, never recorded
		if err != nil {
			t.Fatal(err)
		}
		rogue.KeyFile, rogue.CertFile = filepath.Join(dir, "k"), filepath.Join(dir, "c")
		if err := pki.WriteKeyFile(rogue.KeyFile, key, false); err != nil {
			t.Fatal(err)
		}
		if err := pki.WriteCertFile(rogue.CertFile, cert, cp.ca.Intermediate); err != nil {
			t.Fatal(err)
		}
		rag, stopRogue := runAgent(t, rogue)
		time.Sleep(time.Second)
		connected := rag.Status().Connected
		stopRogue()
		if connected {
			t.Fatal("unrecorded certificate was accepted")
		}
	})

	t.Run("revoked server is disconnected and cannot reconnect", func(t *testing.T) {
		if err := fleet.Revoke(ctx, cp.srv.Store(), res.ServerID, "test", "decommissioned"); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "agent disconnected", func() bool { return !ag.Status().Connected })
		time.Sleep(time.Second) // several reconnect attempts at 50-200 ms back-off
		if _, ok := cp.srv.Gateway().Registry().Get(res.ServerID); ok || ag.Status().Connected {
			t.Fatal("revoked agent reconnected")
		}
		if row, _ := cp.srv.Store().GetServer(ctx, res.ServerID); row.Status != "revoked" {
			t.Fatalf("status after revoke = %q", row.Status)
		}
	})

	if n, err := audit.Verify(ctx, cp.srv.Store().Queries); err != nil || n < 3 {
		t.Fatalf("audit verify = %d, %v", n, err)
	}
}

func TestCertificateRenewal(t *testing.T) {
	// Allow renewal immediately and make the agent renew at start.
	cp := startControlPlane(t, server.WithRenewAfter(1e-9))
	defer cp.stop()
	ctx := context.Background()

	cfg, res := cp.enrollAgent(t, "db-1")
	before, err := pki.ReadCertFile(cfg.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg.RenewBefore = 0.999999

	ag, stopAgent := runAgent(t, cfg)
	defer stopAgent()

	waitFor(t, "renewed certificate on disk", func() bool {
		after, err := pki.ReadCertFile(cfg.CertFile)
		return err == nil && after[0].SerialNumber.Cmp(before[0].SerialNumber) != 0
	})
	waitFor(t, "agent connected", func() bool { return ag.Status().Connected && !ag.Status().LastAck.IsZero() })

	var certs int
	if err := cp.srv.Store().Pool.QueryRow(ctx, "SELECT count(*) FROM agent_certificates WHERE server_id = $1", res.ServerID).Scan(&certs); err != nil || certs != 2 {
		t.Fatalf("certificates recorded = %d, %v", certs, err)
	}
	after, _ := pki.ReadCertFile(cfg.CertFile)
	if id, err := pki.AgentID(after[0]); err != nil || id != res.ServerID {
		t.Fatalf("renewed identity %v, %v", id, err)
	}
}

func TestEnrollRejectsWrongPin(t *testing.T) {
	cp := startControlPlane(t)
	defer cp.stop()
	tok, err := enroll.CreateToken(context.Background(), cp.srv.Store(), enroll.TokenRequest{ServerName: "web-9", Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = agent.Enroll(context.Background(), agent.EnrollOptions{
		APIURL: "https://" + cp.apiLn.Addr().String(), Token: tok.Value,
		Pin: "0000000000000000000000000000000000000000000000000000000000000000", Dir: t.TempDir(),
	})
	if err == nil {
		t.Fatal("enrollment succeeded with a wrong pin")
	}
	// The token must not have been sent, so it is still usable.
	var used bool
	if err := cp.srv.Store().Pool.QueryRow(context.Background(), "SELECT used_at IS NOT NULL FROM enrollment_tokens").Scan(&used); err != nil || used {
		t.Fatalf("token used=%v err=%v", used, err)
	}
}
