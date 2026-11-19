// Package server assembles the control plane: the mTLS agent gateway and the operator API.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/sync/errgroup"

	"github.com/monirujjaman-dev/server-manager/gen/sm/operator/v1/operatorv1connect"
	"github.com/monirujjaman-dev/server-manager/internal/pkg/logging"
	"github.com/monirujjaman-dev/server-manager/internal/pki"
	"github.com/monirujjaman-dev/server-manager/internal/server/api"
	"github.com/monirujjaman-dev/server-manager/internal/server/gateway"
)

// Config is the sm-server configuration. Environment variables use the SM_ prefix,
// e.g. SM_AGENT_LISTEN.
type Config struct {
	AgentListen       string         `yaml:"agent_listen" env:"AGENT_LISTEN"`
	APIListen         string         `yaml:"api_listen" env:"API_LISTEN"`
	PKIDir            string         `yaml:"pki_dir" env:"PKI_DIR"`
	DatabaseURL       string         `yaml:"database_url" env:"DATABASE_URL"`
	HeartbeatInterval time.Duration  `yaml:"heartbeat_interval" env:"HEARTBEAT_INTERVAL"`
	Log               logging.Config `yaml:"log"`
}

// DefaultConfig returns production defaults.
func DefaultConfig() Config {
	return Config{
		AgentListen:       ":8443",
		APIListen:         ":8444",
		PKIDir:            "/var/lib/sm-server/pki",
		HeartbeatInterval: 15 * time.Second,
		Log:               logging.Config{Level: "info", Format: "json"},
	}
}

// Validate checks the configuration.
func (c Config) Validate() error {
	var errs []error
	if c.AgentListen == "" {
		errs = append(errs, errors.New("agent_listen is required"))
	}
	if c.APIListen == "" {
		errs = append(errs, errors.New("api_listen is required"))
	}
	if c.PKIDir == "" {
		errs = append(errs, errors.New("pki_dir is required"))
	}
	if c.HeartbeatInterval < time.Second || c.HeartbeatInterval > 5*time.Minute {
		errs = append(errs, errors.New("heartbeat_interval must be between 1s and 5m"))
	}
	return errors.Join(errs...)
}

// Server is a running control plane.
type Server struct {
	cfg         Config
	log         *slog.Logger
	ca          *pki.CA
	serverCert  tls.Certificate
	revocations *pki.RevocationList
	gw          *gateway.Gateway
}

// New loads the PKI from cfg.PKIDir and prepares the services.
func New(cfg Config, log *slog.Logger) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	ca, err := pki.LoadCA(cfg.PKIDir)
	if err != nil {
		return nil, fmt.Errorf("load CA (run `sm-server pki init` first): %w", err)
	}
	certs, err := pki.ReadCertFile(filepath.Join(cfg.PKIDir, pki.ServerCertFile))
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	key, err := pki.ReadKeyFile(filepath.Join(cfg.PKIDir, pki.ServerKeyFile))
	if err != nil {
		return nil, fmt.Errorf("load server key: %w", err)
	}
	if time.Now().After(certs[0].NotAfter) {
		return nil, fmt.Errorf("server certificate expired on %s (run `sm-server pki issue-server`)", certs[0].NotAfter)
	}
	revocations := pki.NewRevocationList()
	return &Server{
		cfg:         cfg,
		log:         log,
		ca:          ca,
		serverCert:  ca.TLSCertificate(certs[0], key),
		revocations: revocations,
		gw: gateway.New(gateway.Options{
			Logger:            log.With("component", "gateway"),
			Revocations:       revocations,
			HeartbeatInterval: cfg.HeartbeatInterval,
		}),
	}, nil
}

// Revocations returns the in-memory certificate revocation list. Phase 1 replaces it
// with a database-backed list.
func (s *Server) Revocations() *pki.RevocationList { return s.revocations }

// Gateway returns the agent gateway.
func (s *Server) Gateway() *gateway.Gateway { return s.gw }

// Run listens on the configured addresses and serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	var lc net.ListenConfig
	agentLn, err := lc.Listen(ctx, "tcp", s.cfg.AgentListen)
	if err != nil {
		return fmt.Errorf("agent listener: %w", err)
	}
	apiLn, err := lc.Listen(ctx, "tcp", s.cfg.APIListen)
	if err != nil {
		_ = agentLn.Close()
		return fmt.Errorf("api listener: %w", err)
	}
	return s.Serve(ctx, agentLn, apiLn)
}

// Serve serves on the given listeners until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, agentLn, apiLn net.Listener) error {
	agentSrv := s.agentHTTPServer()
	apiSrv := s.apiHTTPServer()

	g, gctx := errgroup.WithContext(ctx)
	serve := func(srv *http.Server, ln net.Listener, name string) func() error {
		return func() error {
			s.log.Info("listening", "listener", name, "addr", ln.Addr().String())
			if err := srv.ServeTLS(ln, "", ""); !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("%s listener: %w", name, err)
			}
			return nil
		}
	}
	g.Go(serve(agentSrv, agentLn, "agent"))
	g.Go(serve(apiSrv, apiLn, "api"))
	g.Go(func() error {
		<-gctx.Done()
		s.log.Info("shutting down")
		// Long-lived agent streams never become idle, so end them explicitly first.
		s.gw.Registry().CloseAll(gateway.ErrShutdown)
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		return errors.Join(agentSrv.Shutdown(shutdownCtx), apiSrv.Shutdown(shutdownCtx))
	})
	return g.Wait()
}

func (s *Server) agentHTTPServer() *http.Server {
	mux := http.NewServeMux()
	mux.Handle(s.gw.Handler())

	protocols := new(http.Protocols)
	protocols.SetHTTP2(true) // gRPC streams need HTTP/2; refuse HTTP/1.1
	return &http.Server{
		Handler:           mux,
		TLSConfig:         pki.AgentServerTLSConfig(s.ca, s.serverCert, s.revocations),
		Protocols:         protocols,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams: 8,
			SendPingTimeout:      30 * time.Second,
			PingTimeout:          15 * time.Second,
		},
		ErrorLog: slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
}

func (s *Server) apiHTTPServer() *http.Server {
	mux := http.NewServeMux()
	mux.Handle(operatorv1connect.NewHealthServiceHandler(&api.Health{}, connect.WithReadMaxBytes(64<<10)))

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	return &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{s.serverCert},
		},
		Protocols:         protocols,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
}
