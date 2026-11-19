// Package ctl implements smctl: the session file, the authenticated API client and output
// formatting shared by the commands.
package ctl

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"connectrpc.com/connect"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	operatorv1 "github.com/monirujjaman-dev/server-manager/gen/sm/operator/v1"
	"github.com/monirujjaman-dev/server-manager/gen/sm/operator/v1/operatorv1connect"
	"github.com/monirujjaman-dev/server-manager/internal/pki"
)

// Session is what `smctl login` stores.
type Session struct {
	Server    string    `json:"server"`
	CAFile    string    `json:"ca_file,omitempty"`
	Token     string    `json:"token"`
	Email     string    `json:"email"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SessionPath is $SMCTL_SESSION or <user config dir>/smctl/session.json.
func SessionPath() (string, error) {
	if p := os.Getenv("SMCTL_SESSION"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "smctl", "session.json"), nil
}

// LoadSession reads the session file. A missing file returns os.ErrNotExist.
func LoadSession() (Session, error) {
	var s Session
	p, err := SessionPath()
	if err != nil {
		return s, err
	}
	b, err := os.ReadFile(p) //nolint:gosec // the user's own session file
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}

// SaveSession writes the session file with mode 0600.
func SaveSession(s Session) error {
	p, err := SessionPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// DeleteSession removes the session file.
func DeleteSession() error {
	p, err := SessionPath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Client talks to the operator API.
type Client struct {
	Auth   operatorv1connect.AuthServiceClient
	Fleet  operatorv1connect.FleetServiceClient
	Action operatorv1connect.ActionServiceClient
	Health operatorv1connect.HealthServiceClient
	// StepUp is called for a TOTP code when an action needs step-up. Nil disables it.
	StepUp func() (string, error)
}

// NewClient connects to serverURL. caFile may be empty to use the system trust store.
func NewClient(serverURL, caFile, token string) (*Client, error) {
	if serverURL == "" {
		return nil, errors.New("no control plane given: use --server or `smctl login`")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if caFile != "" {
		certs, err := pki.ReadCertFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		for _, c := range certs {
			pool.AddCert(c)
		}
		tlsCfg.RootCAs = pool
	}
	hc := &http.Client{Timeout: 4 * time.Minute, Transport: &http.Transport{TLSClientConfig: tlsCfg, ForceAttemptHTTP2: true}}
	opts := connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if token != "" {
				req.Header().Set("Authorization", "Bearer "+token)
			}
			req.Header().Set("User-Agent", "smctl")
			return next(ctx, req)
		}
	}))
	return &Client{
		Auth:   operatorv1connect.NewAuthServiceClient(hc, serverURL, opts),
		Fleet:  operatorv1connect.NewFleetServiceClient(hc, serverURL, opts),
		Action: operatorv1connect.NewActionServiceClient(hc, serverURL, opts),
		Health: operatorv1connect.NewHealthServiceClient(hc, serverURL, opts),
	}, nil
}

// NeedsStepUp reports whether err asks for a fresh TOTP code.
func NeedsStepUp(err error) bool {
	var ce *connect.Error
	return errors.As(err, &ce) && ce.Meta().Get("Sm-Step-Up") == "required"
}

// WithStepUp runs call; if the server asks for step-up, it prompts for a code, steps up
// and retries once.
func (c *Client) WithStepUp(ctx context.Context, call func() error) error {
	err := call()
	if !NeedsStepUp(err) || c.StepUp == nil {
		return err
	}
	code, perr := c.StepUp()
	if perr != nil {
		return perr
	}
	if _, err := c.Auth.StepUp(ctx, connect.NewRequest(&operatorv1.StepUpRequest{TotpCode: code})); err != nil {
		return fmt.Errorf("step-up: %w", err)
	}
	return call()
}

// Run executes an action and waits for a final status.
func (c *Client) Run(ctx context.Context, server string, req *agentv1.ActionRequest, wait time.Duration) (*operatorv1.Job, error) {
	var job *operatorv1.Job
	err := c.WithStepUp(ctx, func() error {
		resp, err := c.Action.Run(ctx, connect.NewRequest(&operatorv1.RunRequest{
			Server: server, Request: req, WaitSeconds: uint32(min(wait, 3*time.Minute).Seconds()),
		}))
		if err != nil {
			return err
		}
		job = resp.Msg.GetJob()
		return nil
	})
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for job.GetStatus() == "pending" || job.GetStatus() == "dispatched" {
		if time.Now().After(deadline) {
			return job, fmt.Errorf("job %s still %s; check later with the job ID", job.GetId(), job.GetStatus())
		}
		select {
		case <-ctx.Done():
			return job, ctx.Err()
		case <-time.After(2 * time.Second):
		}
		resp, err := c.Action.GetJob(ctx, connect.NewRequest(&operatorv1.GetJobRequest{JobId: job.GetId()}))
		if err != nil {
			return job, err
		}
		job = resp.Msg.GetJob()
	}
	if job.GetStatus() != "succeeded" {
		return job, fmt.Errorf("job %s %s: %s", job.GetId(), job.GetStatus(), job.GetError())
	}
	return job, nil
}
