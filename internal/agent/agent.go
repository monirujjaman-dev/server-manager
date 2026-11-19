// Package agent implements sm-agent: it dials out to the control plane over mTLS and
// keeps one long-lived stream open, reconnecting with jittered exponential back-off.
package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1/agentv1connect"
	"github.com/monirujjaman-dev/server-manager/internal/pkg/logging"
	"github.com/monirujjaman-dev/server-manager/internal/pkg/version"
	"github.com/monirujjaman-dev/server-manager/internal/pki"
)

// Config is the sm-agent configuration. Environment variables use the SM_AGENT_ prefix.
type Config struct {
	// ServerURL is the control plane's agent gateway, e.g. https://cp.internal:8443.
	ServerURL string `yaml:"server_url" env:"SERVER_URL"`
	// ServerName overrides the TLS server name; defaults to the URL host.
	ServerName string         `yaml:"server_name" env:"SERVER_NAME"`
	CAFile     string         `yaml:"ca_file" env:"CA_FILE"`
	CertFile   string         `yaml:"cert_file" env:"CERT_FILE"`
	KeyFile    string         `yaml:"key_file" env:"KEY_FILE"`
	Log        logging.Config `yaml:"log"`

	// Reconnect back-off bounds.
	MinBackoff time.Duration `yaml:"min_backoff" env:"MIN_BACKOFF"`
	MaxBackoff time.Duration `yaml:"max_backoff" env:"MAX_BACKOFF"`
}

// DefaultConfig returns production defaults.
func DefaultConfig() Config {
	return Config{
		CAFile:     "/etc/sm-agent/ca.crt",
		CertFile:   "/etc/sm-agent/agent.crt",
		KeyFile:    "/etc/sm-agent/agent.key",
		Log:        logging.Config{Level: "info", Format: "json"},
		MinBackoff: time.Second,
		MaxBackoff: time.Minute,
	}
}

// Validate checks the configuration.
func (c Config) Validate() error {
	var errs []error
	u, err := url.Parse(c.ServerURL)
	switch {
	case c.ServerURL == "":
		errs = append(errs, errors.New("server_url is required"))
	case err != nil:
		errs = append(errs, fmt.Errorf("server_url: %w", err))
	case u.Scheme != "https" || u.Host == "":
		errs = append(errs, errors.New("server_url must be an https:// URL"))
	}
	for name, v := range map[string]string{"ca_file": c.CAFile, "cert_file": c.CertFile, "key_file": c.KeyFile} {
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}
	if c.MinBackoff <= 0 || c.MaxBackoff < c.MinBackoff {
		errs = append(errs, errors.New("min_backoff must be > 0 and <= max_backoff"))
	}
	return errors.Join(errs...)
}

// Status is a snapshot of the agent's connection state.
type Status struct {
	Connected bool
	ServerID  uuid.UUID
	LastAck   time.Time
}

// Agent is a running agent.
type Agent struct {
	cfg    Config
	log    *slog.Logger
	client agentv1connect.AgentServiceClient

	mu     sync.RWMutex
	status Status
}

// New validates the configuration and prepares the client. Certificates are read on
// every TLS handshake so a renewed certificate is picked up without a restart.
func New(cfg Config, log *slog.Logger) (*Agent, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	caCerts, err := pki.ReadCertFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("load CA: %w", err)
	}
	roots := x509.NewCertPool()
	for _, c := range caCerts {
		roots.AddCert(c)
	}
	// Fail fast on a missing or unreadable client certificate.
	if _, err := loadClientCert(cfg.CertFile, cfg.KeyFile); err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: cfg.ServerName,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return loadClientCert(cfg.CertFile, cfg.KeyFile)
		},
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	transport := &http.Transport{
		TLSClientConfig:     tlsCfg,
		Protocols:           protocols,
		TLSHandshakeTimeout: 10 * time.Second,
		HTTP2: &http.HTTP2Config{
			SendPingTimeout: 30 * time.Second,
			PingTimeout:     15 * time.Second,
		},
	}
	httpClient := &http.Client{Transport: transport} // no overall timeout: the stream is long-lived

	return &Agent{
		cfg:    cfg,
		log:    log,
		client: agentv1connect.NewAgentServiceClient(httpClient, cfg.ServerURL, connect.WithGRPC()),
	}, nil
}

func loadClientCert(certFile, keyFile string) (*tls.Certificate, error) {
	certs, err := pki.ReadCertFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("load agent certificate: %w", err)
	}
	key, err := pki.ReadKeyFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("load agent key: %w", err)
	}
	tc := &tls.Certificate{PrivateKey: key, Leaf: certs[0]}
	for _, c := range certs {
		tc.Certificate = append(tc.Certificate, c.Raw)
	}
	return tc, nil
}

// Status returns the current connection state.
func (a *Agent) Status() Status {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.status
}

func (a *Agent) setStatus(fn func(*Status)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fn(&a.status)
}

// Run connects and reconnects until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	attempt := 0
	for {
		welcomed, err := a.session(ctx)
		a.setStatus(func(s *Status) { s.Connected = false })
		if ctx.Err() != nil {
			return nil //nolint:nilerr // cancellation is a normal shutdown, not a failure
		}
		if welcomed {
			attempt = 0
		}
		delay := backoff(attempt, a.cfg.MinBackoff, a.cfg.MaxBackoff)
		attempt++
		a.log.Warn("disconnected from control plane", "err", err, "retry_in", delay.Round(time.Millisecond))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
	}
}

// backoff returns a "full jitter" delay: random in [0, min(max, base*2^attempt)], never
// below base/2 so a flapping control plane is not hammered.
func backoff(attempt int, base, maxDelay time.Duration) time.Duration {
	ceiling := maxDelay
	if attempt < 30 {
		if d := base << attempt; d > 0 && d < maxDelay {
			ceiling = d
		}
	}
	floor := base / 2
	return floor + rand.N(ceiling-floor+1) //nolint:gosec // jitter does not need a CSPRNG
}

// session runs one stream. It reports whether the control plane accepted the agent.
func (a *Agent) session(ctx context.Context) (welcomed bool, err error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	stream := a.client.Connect(ctx)
	defer func() {
		_ = stream.CloseRequest()
		_ = stream.CloseResponse()
	}()

	if err := stream.Send(&agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_Hello{Hello: &agentv1.Hello{
		AgentVersion: version.Get().Version,
		Host:         collectHostFacts(),
	}}}); err != nil {
		return false, fmt.Errorf("send hello: %w", err)
	}

	welcomeTimer := time.AfterFunc(15*time.Second, func() { cancel(errors.New("no welcome from control plane")) })
	resp, err := stream.Receive()
	welcomeTimer.Stop()
	if err != nil {
		if cause := context.Cause(ctx); cause != nil && ctx.Err() != nil {
			return false, cause
		}
		return false, fmt.Errorf("receive welcome: %w", err)
	}
	welcome := resp.GetWelcome()
	if welcome == nil {
		return false, errors.New("first message from control plane was not a welcome")
	}
	serverID, err := uuid.Parse(welcome.GetServerId())
	if err != nil {
		return false, fmt.Errorf("welcome: bad server id: %w", err)
	}
	interval := clamp(welcome.GetHeartbeatInterval().AsDuration(), time.Second, 5*time.Minute)
	if skew := time.Since(welcome.GetServerTime().AsTime()); skew > time.Minute || skew < -time.Minute {
		a.log.Warn("clock skew against control plane", "skew", skew.Round(time.Second))
	}
	a.setStatus(func(s *Status) { s.Connected, s.ServerID = true, serverID })
	a.log.Info("connected to control plane", "server_id", serverID.String(), "heartbeat_interval", interval)

	recvErr := make(chan error, 1)
	go func() {
		for {
			m, err := stream.Receive()
			if err != nil {
				recvErr <- err
				return
			}
			if ack := m.GetHeartbeatAck(); ack != nil {
				a.setStatus(func(s *Status) { s.LastAck = time.Now() })
			}
		}
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var seq uint64
	for {
		select {
		case <-ctx.Done():
			return true, context.Cause(ctx)
		case err := <-recvErr:
			return true, err
		case <-ticker.C:
			seq++
			if err := stream.Send(&agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_Heartbeat{Heartbeat: &agentv1.Heartbeat{
				Seq: seq, SentAt: timestamppb.Now(),
			}}}); err != nil {
				return true, fmt.Errorf("send heartbeat: %w", err)
			}
		}
	}
}

func clamp(d, lo, hi time.Duration) time.Duration {
	return min(max(d, lo), hi)
}
