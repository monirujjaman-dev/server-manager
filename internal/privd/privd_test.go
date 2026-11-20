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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/google/uuid"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/internal/agent/modules"
	"github.com/monirujjaman-dev/server-manager/internal/command"
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
	cfg      Config
	// dockerCalls counts requests that reached the fake Docker daemon.
	dockerCalls *atomic.Int32
}

func newEnv(t *testing.T, allowedUID uint32) *env {
	t.Helper()
	return newEnvOwner(t, allowedUID, uid())
}

// newEnvOwner starts a helper that accepts trust files owned by root or trustedUID.
func newEnvOwner(t *testing.T, allowedUID, trustedUID uint32) *env {
	t.Helper()
	dir := t.TempDir()
	id := uuid.New()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer := command.NewSigner(key)
	cfg := DefaultConfig()
	cfg.Socket = filepath.Join(dir, "privd.sock")
	trustDir := filepath.Join(trustedTempDir(t), "trust")
	cfg.CommandKeyFile, cfg.ServerIDFile = TrustPaths(trustDir)
	if err := WriteTrust(trustDir, id, signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	// The test runs unprivileged, so a given UID stands in for root as the trust owner.
	owner := trustedUID
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
		Systemd: sd, AllowedUID: &allowedUID, TrustedUID: &owner, Docker: modules.NewDockerHTTP(daemon.Client(), daemon.URL),
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
	return &env{signer: signer, serverID: id, sd: sd, client: NewClient(cfg.Socket), dockerCalls: &dockerCalls, cfg: cfg}
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

func signedRestart(t *testing.T, e *env) *agentv1.Command {
	t.Helper()
	cmd, err := e.signer.Sign(uuid.New(), e.serverID, restart(), 0)
	if err != nil {
		t.Fatal(err)
	}
	return cmd
}

func TestRefusesUntrustedTrustFiles(t *testing.T) {
	for name, tamper := range map[string]func(t *testing.T, cfg Config){
		"group-writable key": func(t *testing.T, cfg Config) {
			if err := os.Chmod(cfg.CommandKeyFile, 0o664); err != nil {
				t.Fatal(err)
			}
		},
		"world-writable id": func(t *testing.T, cfg Config) {
			if err := os.Chmod(cfg.ServerIDFile, 0o646); err != nil {
				t.Fatal(err)
			}
		},
		"writable trust dir": func(t *testing.T, cfg Config) {
			if err := os.Chmod(filepath.Dir(cfg.CommandKeyFile), 0o777); err != nil { //nolint:gosec // the point of the test
				t.Fatal(err)
			}
		},
		"symlink to an untrusted file": func(t *testing.T, cfg Config) {
			other := filepath.Join(t.TempDir(), "evil.pub")
			if err := os.WriteFile(other, []byte("x"), 0o666); err != nil { //nolint:gosec // the point of the test
				t.Fatal(err)
			}
			if err := os.Chmod(other, 0o666); err != nil { //nolint:gosec // umask-independent
				t.Fatal(err)
			}
			if err := os.Remove(cfg.CommandKeyFile); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(other, cfg.CommandKeyFile); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, uid())
			tamper(t, e.cfg)
			res, err := e.client.Execute(context.Background(), signedRestart(t, e))
			if err != nil || res.GetStatus() != agentv1.CommandStatus_COMMAND_STATUS_REJECTED ||
				!strings.Contains(res.GetError(), "untrusted") {
				t.Fatalf("result %v, %v; want rejected as untrusted", res, err)
			}
			if len(e.sd.ops) != 0 {
				t.Fatalf("systemd called: %v", e.sd.ops)
			}
		})
	}
}

func TestRefusesTrustFilesOwnedByOthers(t *testing.T) {
	// The helper trusts root and UID+1 here. Unprivileged, the files are owned by the
	// test user; as root, they are handed to another user.
	e := newEnvOwner(t, uid(), uid()+1)
	if uid() == 0 {
		for _, p := range []string{e.cfg.CommandKeyFile, e.cfg.ServerIDFile} {
			if err := os.Chown(p, 4242, 4242); err != nil {
				t.Fatal(err)
			}
		}
	}
	res, err := e.client.Execute(context.Background(), signedRestart(t, e))
	if err != nil || res.GetStatus() != agentv1.CommandStatus_COMMAND_STATUS_REJECTED || !strings.Contains(res.GetError(), "not root") {
		t.Fatalf("result %v, %v; want rejected (owner)", res, err)
	}
}

func TestCheckTrusted(t *testing.T) {
	me := uid()
	base := trustedTempDir(t)
	dir := filepath.Join(base, "trust")
	if err := WriteTrust(dir, uuid.New(), make([]byte, ed25519.PublicKeySize)); err != nil {
		t.Fatal(err)
	}
	key, id := TrustPaths(dir)
	for _, p := range []string{key, id} {
		real, err := CheckTrusted(p, &me)
		if err != nil || real == "" {
			t.Errorf("%s: %q, %v", p, real, err)
		}
		if _, err := CheckTrusted(p, nil); err == nil && me != 0 {
			t.Errorf("%s accepted although owned by UID %d, not root", p, me)
		}
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != 0o644 {
			t.Errorf("%s mode %v", p, fi.Mode().Perm())
		}
	}
	if _, err := ReadServerID(id); err != nil {
		t.Fatal(err)
	}

	// Relative paths are checked like absolute ones.
	wd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckTrusted("command.pub", &me); err != nil {
		t.Errorf("relative path: %v", err)
	}
	_ = os.Chdir(wd)

	// A sticky world-writable directory above is fine (like /tmp)...
	sticky := filepath.Join(base, "sticky")
	if err := os.Mkdir(sticky, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sticky, 0o777|os.ModeSticky); err != nil { //nolint:gosec // the point of the test
		t.Fatal(err)
	}
	if err := WriteTrust(filepath.Join(sticky, "t"), uuid.New(), make([]byte, ed25519.PublicKeySize)); err != nil {
		t.Fatalf("trust dir under a sticky directory: %v", err)
	}
	// ...a plain writable ancestor is not.
	open := filepath.Join(base, "open")
	if err := WriteTrust(filepath.Join(open, "t"), uuid.New(), make([]byte, ed25519.PublicKeySize)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil { //nolint:gosec // the point of the test
		t.Fatal(err)
	}
	if _, err := CheckTrusted(filepath.Join(open, "t", "command.pub"), &me); err == nil {
		t.Error("file under a group/world-writable ancestor accepted")
	}
	// Writing into it is refused too, before anything is written.
	if err := WriteTrust(filepath.Join(open, "t2"), uuid.New(), make([]byte, ed25519.PublicKeySize)); err == nil {
		t.Error("WriteTrust wrote below a world-writable directory")
	}

	for name, p := range map[string]string{
		"missing":   filepath.Join(dir, "missing"),
		"directory": dir,
	} {
		if _, err := CheckTrusted(p, &me); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readTrusted(fifo, &me); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Errorf("FIFO accepted: %v", err)
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, make([]byte, maxTrustFile+1), 0o644); err != nil { //nolint:gosec // test file
		t.Fatal(err)
	}
	if err := os.Chmod(big, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readTrusted(big, &me); err == nil {
		t.Error("oversized trust file accepted")
	}
}

func TestWriteTrustIgnoresPlantedTempFile(t *testing.T) {
	dir := filepath.Join(trustedTempDir(t), "trust")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The old implementation wrote through server-id.tmp and command.pub.tmp names.
	for _, n := range []string{"server-id.tmp", ".server-id.tmp", "command.pub.tmp"} {
		if err := os.Symlink(victim, filepath.Join(dir, n)); err != nil {
			t.Fatal(err)
		}
	}
	if err := WriteTrust(dir, uuid.New(), make([]byte, ed25519.PublicKeySize)); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep me" { //nolint:gosec // test file
		t.Fatalf("write followed a planted symlink: victim is now %q", b)
	}
}

// trustedTempDir returns a temp directory that, like the directories above a real trust
// directory, is not writable by group or others (umask 002 would make it 0775).
func trustedTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, p := range []string{filepath.Dir(dir), dir} {
		if err := os.Chmod(p, 0o755); err != nil { //nolint:gosec // directories, not secrets
			t.Fatal(err)
		}
	}
	return dir
}
