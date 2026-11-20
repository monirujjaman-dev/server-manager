// Package privd is the privileged helper (`sm-agent privd`). It runs as root, has no
// network access, listens only on a local UNIX socket, accepts connections only from the
// agent's UID (checked with SO_PEERCRED), and executes a fixed set of privileged actions
// after verifying the control plane's signature itself. A compromised unprivileged agent
// therefore cannot make it do anything the control plane did not sign.
package privd

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1/agentv1connect"
	"github.com/monirujjaman-dev/server-manager/internal/agent/modules"
	"github.com/monirujjaman-dev/server-manager/internal/command"
	"github.com/monirujjaman-dev/server-manager/internal/pkg/logging"
	"github.com/monirujjaman-dev/server-manager/internal/pki"
)

// Config configures the helper. Environment variables use the SM_PRIVD_ prefix.
type Config struct {
	// Socket is the UNIX socket path.
	Socket string `yaml:"socket" env:"SOCKET"`
	// AgentUser is the only user allowed to connect (the unprivileged agent).
	AgentUser string `yaml:"agent_user" env:"AGENT_USER"`
	// CommandKeyFile is the control plane's command verification key and ServerIDFile
	// this server's identity. Both must be root-owned and not writable by anyone else,
	// as must every directory above them (see CheckTrusted); they are never read from
	// the agent's own directory.
	CommandKeyFile string `yaml:"command_key_file" env:"COMMAND_KEY_FILE"`
	ServerIDFile   string `yaml:"server_id_file" env:"SERVER_ID_FILE"`
	// DockerSocket is the Docker daemon's socket for docker.* actions.
	DockerSocket string         `yaml:"docker_socket" env:"DOCKER_SOCKET"`
	Log          logging.Config `yaml:"log"`
}

// DefaultConfig returns production defaults.
func DefaultConfig() Config {
	return Config{
		Socket:         "/run/sm-agent/privd.sock",
		AgentUser:      "smagent",
		CommandKeyFile: DefaultTrustDir + "/" + commandKeyName,
		ServerIDFile:   DefaultTrustDir + "/" + serverIDName,
		DockerSocket:   modules.DefaultDockerSocket,
		Log:            logging.Config{Level: "info", Format: "json"},
	}
}

// Server is a running helper.
type Server struct {
	agentv1connect.UnimplementedPrivilegedServiceHandler

	cfg        Config
	log        *slog.Logger
	host       modules.Host
	systemd    modules.Systemd
	docker     *modules.Docker
	kill       func(int, syscall.Signal) error
	allowedUID uint32
	trustedUID *uint32 // besides root; tests only

	mu       sync.Mutex
	verifier *command.Verifier
}

// Options overrides system access in tests.
type Options struct {
	Host    *modules.Host
	Systemd modules.Systemd
	Docker  *modules.Docker
	Kill    func(int, syscall.Signal) error
	// AllowedUID overrides the lookup of Config.AgentUser.
	AllowedUID *uint32
	// TrustedUID additionally accepts trust files owned by this UID. Tests only: in
	// production the files must be owned by root.
	TrustedUID *uint32
}

// New prepares the helper.
func New(cfg Config, log *slog.Logger, opts Options) (*Server, error) {
	s := &Server{cfg: cfg, log: log, host: modules.DefaultHost(), systemd: modules.DBusSystemd{}, kill: modules.Kill}
	if opts.Host != nil {
		s.host = *opts.Host
	}
	if opts.Systemd != nil {
		s.systemd = opts.Systemd
	}
	if opts.Kill != nil {
		s.kill = opts.Kill
	}
	s.docker = modules.NewDocker(cfg.DockerSocket)
	if opts.Docker != nil {
		s.docker = opts.Docker
	}
	s.trustedUID = opts.TrustedUID
	if opts.AllowedUID != nil {
		s.allowedUID = *opts.AllowedUID
	} else {
		u, err := user.Lookup(cfg.AgentUser)
		if err != nil {
			return nil, fmt.Errorf("agent user %q: %w", cfg.AgentUser, err)
		}
		uid, err := strconv.ParseUint(u.Uid, 10, 32)
		if err != nil {
			return nil, err
		}
		s.allowedUID = uint32(uid)
	}
	if s.allowedUID == 0 && opts.AllowedUID == nil {
		return nil, errors.New("agent_user must not be root")
	}
	return s, nil
}

// getVerifier loads the identity and key lazily, so the helper can start before the
// server is enrolled. Both files are checked to be root-controlled before they are read;
// a failed load is retried on the next command.
func (s *Server) getVerifier() (*command.Verifier, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.verifier != nil {
		return s.verifier, nil
	}
	// Each file is checked and then read through its resolved path, so nothing can be
	// swapped in between (every directory on that path is root-controlled).
	idData, err := readTrusted(s.cfg.ServerIDFile, s.trustedUID)
	if err != nil {
		return nil, fmt.Errorf("trust file: %w", err)
	}
	id, err := ParseServerID(idData, s.cfg.ServerIDFile)
	if err != nil {
		return nil, fmt.Errorf("server identity: %w", err)
	}
	keyData, err := readTrusted(s.cfg.CommandKeyFile, s.trustedUID)
	if err != nil {
		return nil, fmt.Errorf("trust file: %w", err)
	}
	pub, err := pki.ParseCommandPublicKey(keyData, s.cfg.CommandKeyFile)
	if err != nil {
		return nil, fmt.Errorf("command key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("command key has the wrong size")
	}
	s.verifier = command.NewVerifier(pub, id)
	return s.verifier, nil
}

// Listen creates the socket, owned by root with group access for the agent user's
// primary group only (mode 0660), inside a 0750 directory.
func Listen(ctx context.Context, path string, gid int) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil { //nolint:gosec // the agent group must be able to connect
		_ = ln.Close()
		return nil, err
	}
	if gid >= 0 {
		if err := os.Chown(path, 0, gid); err != nil {
			_ = ln.Close()
			return nil, err
		}
		_ = os.Chown(filepath.Dir(path), 0, gid)
	}
	return ln, nil
}

// AgentGID returns the primary group of the configured agent user.
func AgentGID(name string) (int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return -1, err
	}
	return strconv.Atoi(u.Gid)
}

type credKey struct{}

// peer identifies the process on the other end of the socket, as reported by the kernel.
type peer struct {
	uid uint32
	pid int32
}

// Serve handles requests on ln until ctx ends.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	path, h := agentv1connect.NewPrivilegedServiceHandler(s, connect.WithReadMaxBytes(1<<20))
	mux := http.NewServeMux()
	mux.Handle(path, s.requirePeer(h))
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			cred, err := peerCred(c)
			if err != nil {
				return ctx
			}
			return context.WithValue(ctx, credKey{}, cred)
		},
		ErrorLog: slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) requirePeer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cred, ok := r.Context().Value(credKey{}).(*peer)
		if !ok || cred.uid != s.allowedUID {
			uid := "unknown"
			if ok {
				uid = strconv.FormatUint(uint64(cred.uid), 10)
			}
			s.log.Warn("rejected connection from unauthorized user", "uid", uid)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Execute verifies and runs one privileged action.
func (s *Server) Execute(ctx context.Context, req *connect.Request[agentv1.ExecuteRequest]) (*connect.Response[agentv1.ExecuteResponse], error) {
	cred, _ := ctx.Value(credKey{}).(*peer)
	res := s.execute(ctx, req.Msg.GetCommand(), cred)
	return connect.NewResponse(&agentv1.ExecuteResponse{Result: res}), nil
}

func (s *Server) execute(ctx context.Context, cmd *agentv1.Command, cred *peer) *agentv1.CommandResult {
	id := unverifiedID(cmd)
	reject := func(err error) *agentv1.CommandResult {
		s.log.Warn("command rejected", "job_id", id, "err", err)
		return &agentv1.CommandResult{Id: id, Status: agentv1.CommandStatus_COMMAND_STATUS_REJECTED, Error: err.Error()}
	}
	v, err := s.getVerifier()
	if err != nil {
		return reject(err)
	}
	env, err := v.Verify(cmd)
	if err != nil {
		return reject(err)
	}
	info, _ := command.Describe(env.GetRequest())
	if !info.Privileged {
		return reject(fmt.Errorf("%s is not a privileged action", info.Name))
	}
	result, err := s.run(ctx, env.GetRequest(), cred)
	if err != nil {
		s.log.Info("privileged action failed", "job_id", env.GetId(), "action", info.Name, "err", err)
		return &agentv1.CommandResult{Id: env.GetId(), Status: agentv1.CommandStatus_COMMAND_STATUS_FAILED, Error: err.Error()}
	}
	s.log.Info("privileged action succeeded", "job_id", env.GetId(), "action", info.Name)
	return &agentv1.CommandResult{Id: env.GetId(), Status: agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED, Result: result}
}

func (s *Server) run(ctx context.Context, req *agentv1.ActionRequest, cred *peer) (*agentv1.ActionResult, error) {
	switch a := req.GetAction().(type) {
	case *agentv1.ActionRequest_ServiceControl:
		r, err := modules.ControlService(ctx, s.systemd, a.ServiceControl)
		if err != nil {
			return nil, err
		}
		return &agentv1.ActionResult{Result: &agentv1.ActionResult_ServiceControl{ServiceControl: r}}, nil
	case *agentv1.ActionRequest_ProcessSignal:
		protected := []int32{int32(os.Getpid())} //nolint:gosec // PIDs fit int32
		if cred != nil {
			protected = append(protected, cred.pid)
		}
		if err := s.host.SignalProcess(a.ProcessSignal, protected, s.kill); err != nil {
			return nil, err
		}
		return &agentv1.ActionResult{Result: &agentv1.ActionResult_ProcessSignal{ProcessSignal: &agentv1.ProcessSignalResult{}}}, nil
	case *agentv1.ActionRequest_DockerContainerList:
		r, err := s.docker.ListContainers(ctx, a.DockerContainerList)
		return wrap(r, err, func(r *agentv1.DockerContainerListResult) *agentv1.ActionResult {
			return &agentv1.ActionResult{Result: &agentv1.ActionResult_DockerContainerList{DockerContainerList: r}}
		})
	case *agentv1.ActionRequest_DockerContainerControl:
		r, err := s.docker.ControlContainer(ctx, a.DockerContainerControl)
		return wrap(r, err, func(r *agentv1.DockerContainerControlResult) *agentv1.ActionResult {
			return &agentv1.ActionResult{Result: &agentv1.ActionResult_DockerContainerControl{DockerContainerControl: r}}
		})
	case *agentv1.ActionRequest_DockerLogs:
		r, err := s.docker.Logs(ctx, a.DockerLogs)
		return wrap(r, err, func(r *agentv1.DockerLogsResult) *agentv1.ActionResult {
			return &agentv1.ActionResult{Result: &agentv1.ActionResult_DockerLogs{DockerLogs: r}}
		})
	case *agentv1.ActionRequest_DockerStats:
		r, err := s.docker.Stats(ctx, a.DockerStats)
		return wrap(r, err, func(r *agentv1.DockerStatsResult) *agentv1.ActionResult {
			return &agentv1.ActionResult{Result: &agentv1.ActionResult_DockerStats{DockerStats: r}}
		})
	case *agentv1.ActionRequest_DockerImageList:
		r, err := s.docker.ListImages(ctx, a.DockerImageList)
		return wrap(r, err, func(r *agentv1.DockerImageListResult) *agentv1.ActionResult {
			return &agentv1.ActionResult{Result: &agentv1.ActionResult_DockerImageList{DockerImageList: r}}
		})
	case *agentv1.ActionRequest_DockerVolumeList:
		r, err := s.docker.ListVolumes(ctx, a.DockerVolumeList)
		return wrap(r, err, func(r *agentv1.DockerVolumeListResult) *agentv1.ActionResult {
			return &agentv1.ActionResult{Result: &agentv1.ActionResult_DockerVolumeList{DockerVolumeList: r}}
		})
	case *agentv1.ActionRequest_DockerNetworkList:
		r, err := s.docker.ListNetworks(ctx, a.DockerNetworkList)
		return wrap(r, err, func(r *agentv1.DockerNetworkListResult) *agentv1.ActionResult {
			return &agentv1.ActionResult{Result: &agentv1.ActionResult_DockerNetworkList{DockerNetworkList: r}}
		})
	case *agentv1.ActionRequest_DockerPrune:
		r, err := s.docker.Prune(ctx, a.DockerPrune)
		return wrap(r, err, func(r *agentv1.DockerPruneResult) *agentv1.ActionResult {
			return &agentv1.ActionResult{Result: &agentv1.ActionResult_DockerPrune{DockerPrune: r}}
		})
	default:
		return nil, fmt.Errorf("unsupported privileged action %T", a)
	}
}

func wrap[T any](r T, err error, f func(T) *agentv1.ActionResult) (*agentv1.ActionResult, error) {
	if err != nil {
		return nil, err
	}
	return f(r), nil
}

// unverifiedID extracts the job ID for error reports only. It is never trusted for
// anything else.
func unverifiedID(cmd *agentv1.Command) string {
	env := &agentv1.CommandEnvelope{}
	if proto.Unmarshal(cmd.GetEnvelope(), env) != nil {
		return ""
	}
	return env.GetId()
}

// Client calls the helper from the unprivileged agent.
type Client struct {
	c agentv1connect.PrivilegedServiceClient
}

// NewClient connects to the helper's socket.
func NewClient(socket string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}
	hc := &http.Client{Transport: tr, Timeout: 2 * time.Minute}
	return &Client{c: agentv1connect.NewPrivilegedServiceClient(hc, "http://privd")}
}

// Execute forwards a signed command unchanged.
func (c *Client) Execute(ctx context.Context, cmd *agentv1.Command) (*agentv1.CommandResult, error) {
	resp, err := c.c.Execute(ctx, connect.NewRequest(&agentv1.ExecuteRequest{Command: cmd}))
	if err != nil {
		return nil, fmt.Errorf("privileged helper: %w", err)
	}
	return resp.Msg.GetResult(), nil
}
