//go:build linux

package privd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/google/uuid"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/internal/agent/modules"
	"github.com/monirujjaman-dev/server-manager/internal/command"
	"github.com/monirujjaman-dev/server-manager/internal/pki"
)

type fakeSystemd struct {
	mu  sync.Mutex
	ops []string
}

func (f *fakeSystemd) ListServices(context.Context) ([]*agentv1.ServiceUnit, error) { return nil, nil }
func (f *fakeSystemd) Unit(_ context.Context, name string) (*agentv1.ServiceUnit, error) {
	return &agentv1.ServiceUnit{Name: name, LoadState: "loaded", ActiveState: "active"}, nil
}
func (f *fakeSystemd) Control(_ context.Context, unit string, op agentv1.ServiceOperation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ops = append(f.ops, unit+":"+op.String())
	return nil
}

type env struct {
	signer   *command.Signer
	serverID uuid.UUID
	sd       *fakeSystemd
	client   *Client
	// dockerCalls counts requests that reached the fake Docker daemon.
	dockerCalls *atomic.Int32
}

func newEnv(t *testing.T, allowedUID uint32) *env {
	t.Helper()
	dir := t.TempDir()
	ca, err := pki.CreateCA("Test")
	if err != nil {
		t.Fatal(err)
	}
	_, csr, _ := pki.NewAgentKey()
	id := uuid.New()
	cert, err := ca.SignAgentCSR(csr, id)
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer := command.NewSigner(key)
	cfg := DefaultConfig()
	cfg.Socket = filepath.Join(dir, "privd.sock")
	cfg.CertFile = filepath.Join(dir, "agent.crt")
	cfg.CommandKeyFile = filepath.Join(dir, "command.pub")
	if err := pki.WriteCertFile(cfg.CertFile, cert); err != nil {
		t.Fatal(err)
	}
	if err := pki.WriteCommandPublicKey(cfg.CommandKeyFile, signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	sd := &fakeSystemd{}
	var dockerCalls atomic.Int32
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dockerCalls.Add(1)
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte(`{"ApiVersion":"1.47"}`))
		case "/v1.47/containers/json":
			_, _ = w.Write([]byte(`[{"Id":"abc123","Names":["/web"],"State":"running"}]`))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(daemon.Close)
	srv, err := New(cfg, slog.New(slog.DiscardHandler), Options{
		Systemd: sd, AllowedUID: &allowedUID, Docker: modules.NewDockerHTTP(daemon.Client(), daemon.URL),
		Kill: func(int, syscall.Signal) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := Listen(context.Background(), cfg.Socket, -1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return &env{signer: signer, serverID: id, sd: sd, client: NewClient(cfg.Socket), dockerCalls: &dockerCalls}
}

func restart() *agentv1.ActionRequest {
	return &agentv1.ActionRequest{Action: &agentv1.ActionRequest_ServiceControl{ServiceControl: &agentv1.ServiceControlRequest{
		Unit: "nginx.service", Operation: agentv1.ServiceOperation_SERVICE_OPERATION_RESTART,
	}}}
}

func uid() uint32 { return uint32(os.Getuid()) } //nolint:gosec // UIDs fit uint32

func TestExecuteSignedCommandOnce(t *testing.T) {
	e := newEnv(t, uid())
	cmd, _ := e.signer.Sign(uuid.New(), e.serverID, restart(), 0)
	res, err := e.client.Execute(context.Background(), cmd)
	if err != nil || res.GetStatus() != agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED {
		t.Fatalf("execute: %v %v", res, err)
	}
	res, err = e.client.Execute(context.Background(), cmd)
	if err != nil || res.GetStatus() != agentv1.CommandStatus_COMMAND_STATUS_REJECTED {
		t.Fatalf("replay: %v %v", res, err)
	}
	if len(e.sd.ops) != 1 {
		t.Fatalf("systemd ops %v", e.sd.ops)
	}
}

func TestRejectsUnsignedAndUnprivileged(t *testing.T) {
	e := newEnv(t, uid())
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	forged, _ := command.NewSigner(otherKey).Sign(uuid.New(), e.serverID, restart(), 0)
	otherServer, _ := e.signer.Sign(uuid.New(), uuid.New(), restart(), 0)
	readOnly, _ := e.signer.Sign(uuid.New(), e.serverID, &agentv1.ActionRequest{
		Action: &agentv1.ActionRequest_SystemInfo{SystemInfo: &agentv1.SystemInfoRequest{}},
	}, 0)
	for name, cmd := range map[string]*agentv1.Command{"forged": forged, "other server": otherServer, "unprivileged action": readOnly} {
		res, err := e.client.Execute(context.Background(), cmd)
		if err != nil || res.GetStatus() != agentv1.CommandStatus_COMMAND_STATUS_REJECTED {
			t.Errorf("%s: %v %v", name, res, err)
		}
	}
	if len(e.sd.ops) != 0 {
		t.Fatalf("systemd called: %v", e.sd.ops)
	}
}

func TestRejectsOtherUsers(t *testing.T) {
	e := newEnv(t, uid()+1)
	cmd, _ := e.signer.Sign(uuid.New(), e.serverID, restart(), 0)
	if _, err := e.client.Execute(context.Background(), cmd); err == nil {
		t.Fatal("connection from a different UID was accepted")
	}
	if len(e.sd.ops) != 0 {
		t.Fatalf("systemd called: %v", e.sd.ops)
	}
}

func TestSocketPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s", "privd.sock")
	ln, err := Listen(context.Background(), path, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode %v, %v", fi.Mode().Perm(), err)
	}
}

func TestDockerRunsInHelperOnlyWhenSigned(t *testing.T) {
	e := newEnv(t, uid())
	list := &agentv1.ActionRequest{Action: &agentv1.ActionRequest_DockerContainerList{DockerContainerList: &agentv1.DockerContainerListRequest{}}}
	cmd, err := e.signer.Sign(uuid.New(), e.serverID, list, 0)
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.client.Execute(context.Background(), cmd)
	if err != nil || res.GetStatus() != agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED ||
		res.GetResult().GetDockerContainerList().GetContainers()[0].GetName() != "web" {
		t.Fatalf("docker.list: %v %v", res, err)
	}

	before := e.dockerCalls.Load()
	prune := &agentv1.ActionRequest{Action: &agentv1.ActionRequest_DockerPrune{DockerPrune: &agentv1.DockerPruneRequest{
		Target: agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_VOLUMES, AllVolumes: true,
	}}}
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	forged, _ := command.NewSigner(otherKey).Sign(uuid.New(), e.serverID, prune, 0)
	otherServer, _ := e.signer.Sign(uuid.New(), uuid.New(), prune, 0)
	for name, c := range map[string]*agentv1.Command{"forged": forged, "other server": otherServer, "replayed list": cmd} {
		res, err := e.client.Execute(context.Background(), c)
		if err != nil || res.GetStatus() != agentv1.CommandStatus_COMMAND_STATUS_REJECTED {
			t.Errorf("%s: %v %v", name, res, err)
		}
	}
	if n := e.dockerCalls.Load(); n != before {
		t.Fatalf("rejected commands reached the Docker daemon (%d requests)", n-before)
	}
}
