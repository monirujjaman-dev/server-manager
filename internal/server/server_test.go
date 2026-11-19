package server_test

import (
	"context"
	"crypto/tls"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	operatorv1 "github.com/monirujjaman-dev/server-manager/gen/sm/operator/v1"
	"github.com/monirujjaman-dev/server-manager/gen/sm/operator/v1/operatorv1connect"
	"github.com/monirujjaman-dev/server-manager/internal/agent"
	"github.com/monirujjaman-dev/server-manager/internal/pki"
	"github.com/monirujjaman-dev/server-manager/internal/server"
)

type fixture struct {
	ca          *pki.CA
	pkiDir      string
	agentDir    string
	agentID     uuid.UUID
	agentSerial *big.Int
}

// setupPKI creates a CA, a server certificate for 127.0.0.1 and one enrolled agent,
// following the real flow: the agent generates its own key and only a CSR is signed.
func setupPKI(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{pkiDir: filepath.Join(dir, "pki"), agentDir: filepath.Join(dir, "agent"), agentID: uuid.New()}

	ca, err := pki.CreateCA("Test")
	if err != nil {
		t.Fatal(err)
	}
	f.ca = ca
	if err := pki.SaveCA(f.pkiDir, ca); err != nil {
		t.Fatal(err)
	}
	srvCert, srvKey, err := ca.IssueServerCert([]string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.SaveServerCert(f.pkiDir, ca, srvCert, srvKey); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) enrollAgent(t *testing.T) agent.Config {
	t.Helper()
	key, csr, err := pki.NewAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := f.ca.SignAgentCSR(csr, f.agentID)
	if err != nil {
		t.Fatal(err)
	}
	f.agentSerial = cert.SerialNumber
	cfg := agent.DefaultConfig()
	cfg.CAFile = filepath.Join(f.agentDir, "ca.crt")
	cfg.CertFile = filepath.Join(f.agentDir, "agent.crt")
	cfg.KeyFile = filepath.Join(f.agentDir, "agent.key")
	cfg.MinBackoff, cfg.MaxBackoff = 50*time.Millisecond, 200*time.Millisecond
	if err := os.MkdirAll(f.agentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := pki.WriteKeyFile(cfg.KeyFile, key, false); err != nil {
		t.Fatal(err)
	}
	if err := pki.WriteCertFile(cfg.CertFile, cert, f.ca.Intermediate); err != nil {
		t.Fatal(err)
	}
	if err := pki.WriteCertFile(cfg.CAFile, f.ca.Root); err != nil {
		t.Fatal(err)
	}
	return cfg
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

func TestAgentConnectsOverMTLS(t *testing.T) {
	f := setupPKI(t)
	log := slog.New(slog.DiscardHandler)

	cfg := server.DefaultConfig()
	cfg.PKIDir = f.pkiDir
	cfg.HeartbeatInterval = time.Second
	srv, err := server.New(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	agentLn, _ := net.Listen("tcp", "127.0.0.1:0")
	apiLn, _ := net.Listen("tcp", "127.0.0.1:0")

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx, agentLn, apiLn) }()

	acfg := f.enrollAgent(t)
	acfg.ServerURL = "https://" + agentLn.Addr().String()
	ag, err := agent.New(acfg, log)
	if err != nil {
		t.Fatal(err)
	}
	agentCtx, stopAgent := context.WithCancel(ctx)
	agentDone := make(chan error, 1)
	go func() { agentDone <- ag.Run(agentCtx) }()

	// Exit criterion: hello → welcome → heartbeats acknowledged over mTLS.
	waitFor(t, "agent registered", func() bool { _, ok := srv.Gateway().Registry().Get(f.agentID); return ok })
	waitFor(t, "heartbeat ack", func() bool { return !ag.Status().LastAck.IsZero() })
	if got := ag.Status().ServerID; got != f.agentID {
		t.Fatalf("agent learned server ID %v, want %v", got, f.agentID)
	}
	info, _ := srv.Gateway().Registry().Get(f.agentID)
	if info.AgentVersion == "" || info.Hostname == "" || !info.LastSeen.After(info.ConnectedAt) {
		t.Errorf("unexpected session info %+v", info)
	}

	t.Run("health check on API listener", func(t *testing.T) {
		pool := f.ca.RootPool()
		hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool},
		}}
		client := operatorv1connect.NewHealthServiceClient(hc, "https://"+apiLn.Addr().String())
		resp, err := client.Check(ctx, connect.NewRequest(&operatorv1.CheckRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		if resp.Msg.GetStatus() != operatorv1.ServingStatus_SERVING_STATUS_SERVING {
			t.Errorf("status = %v", resp.Msg.GetStatus())
		}
	})

	t.Run("agent port rejects clients without certificate", func(t *testing.T) {
		hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: f.ca.RootPool()},
		}}
		resp, err := hc.Get("https://" + agentLn.Addr().String() + "/sm.agent.v1.AgentService/Connect")
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("request without client certificate got HTTP %d", resp.StatusCode)
		}
	})

	t.Run("revoked agent cannot reconnect", func(t *testing.T) {
		srv.Revocations().Revoke(f.agentSerial)
		srv.Gateway().Registry().Disconnect(f.agentID, context.Canceled)
		waitFor(t, "agent disconnected", func() bool { return !ag.Status().Connected })
		time.Sleep(time.Second) // several reconnect attempts at 50-200 ms back-off
		if _, ok := srv.Gateway().Registry().Get(f.agentID); ok || ag.Status().Connected {
			t.Fatal("revoked agent reconnected")
		}
	})

	stopAgent()
	select {
	case err := <-agentDone:
		if err != nil {
			t.Fatalf("agent run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not stop")
	}
	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("server did not shut down")
	}
}
