package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"go.yaml.in/yaml/v3"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1/agentv1connect"
	"github.com/monirujjaman-dev/server-manager/internal/pkg/version"
	"github.com/monirujjaman-dev/server-manager/internal/pki"
)

// EnrollOptions configures a one-time enrollment.
type EnrollOptions struct {
	// APIURL is the control plane's API listener, e.g. https://cp.internal:8444.
	APIURL string
	// Token is the one-time enrollment token.
	Token string
	// Pin is the hex SHA-256 of the control plane certificate's public key
	// (printed by `sm-server enroll create-token`).
	Pin string
	// Dir receives agent.key, agent.crt, ca.crt and agent.yaml.
	Dir string
	// AgentURL overrides the agent gateway URL returned by the control plane.
	AgentURL string
	// Owner, if set, becomes the owner of Dir and the files in it, so the agent can run
	// unprivileged as that user and rewrite its certificate on renewal.
	Owner string
}

// EnrollResult describes a successful enrollment.
type EnrollResult struct {
	ServerID   uuid.UUID
	ServerName string
	ConfigPath string
	AgentURL   string
}

// Enroll generates the agent key locally, exchanges the token and a CSR for a
// certificate, and writes the agent's files. The control plane is authenticated by the
// public-key pin, because the agent does not have the CA certificate yet.
func Enroll(ctx context.Context, opts EnrollOptions) (EnrollResult, error) {
	u, err := url.Parse(opts.APIURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return EnrollResult{}, errors.New("API URL must be an https:// URL")
	}
	pin, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(opts.Pin)))
	if err != nil || len(pin) != sha256.Size {
		return EnrollResult{}, errors.New("pin must be 64 hex characters (SHA-256 of the server public key)")
	}
	if opts.Token == "" {
		return EnrollResult{}, errors.New("token is required")
	}
	paths := agentPaths(opts.Dir)
	if _, err := os.Stat(paths.key); err == nil {
		return EnrollResult{}, fmt.Errorf("%s already exists: this server is already enrolled", paths.key)
	}

	key, csr, err := pki.NewAgentKey()
	if err != nil {
		return EnrollResult{}, err
	}

	var (
		mu       sync.Mutex
		peerCert []*x509.Certificate
	)
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		// Chain verification is replaced by the public-key pin below: the agent has no
		// CA certificate before enrollment. The pin is checked on every handshake.
		InsecureSkipVerify: true, //nolint:gosec // verified by VerifyConnection (SPKI pin)
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("server sent no certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(got[:], pin) != 1 {
				return fmt.Errorf("server public key %x does not match the pin", got)
			}
			mu.Lock()
			peerCert = cs.PeerCertificates
			mu.Unlock()
			return nil
		},
	}
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg, ForceAttemptHTTP2: true}}
	client := agentv1connect.NewEnrollmentServiceClient(hc, opts.APIURL)
	resp, err := client.Enroll(ctx, connect.NewRequest(&agentv1.EnrollRequest{
		Token: opts.Token, Csr: csr, AgentVersion: version.Get().Version, Host: collectHostFacts(),
	}))
	if err != nil {
		return EnrollResult{}, fmt.Errorf("enroll: %w", err)
	}

	mu.Lock()
	serverChain := peerCert
	mu.Unlock()
	res, chain, root, err := checkEnrollResponse(resp.Msg, serverChain)
	if err != nil {
		return EnrollResult{}, err
	}

	res.AgentURL = opts.AgentURL
	if res.AgentURL == "" {
		res.AgentURL = resp.Msg.GetAgentUrl()
	}
	if res.AgentURL == "" {
		res.AgentURL = "https://" + net.JoinHostPort(u.Hostname(), "8443")
	}

	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return EnrollResult{}, err
	}
	if err := pki.WriteKeyFile(paths.key, key, false); err != nil {
		return EnrollResult{}, err
	}
	if err := pki.WriteCertFile(paths.cert, chain...); err != nil {
		return EnrollResult{}, err
	}
	if err := pki.WriteCertFile(paths.ca, root); err != nil {
		return EnrollResult{}, err
	}
	if k := resp.Msg.GetCommandPublicKey(); len(k) == ed25519.PublicKeySize {
		if err := pki.WriteCommandPublicKey(paths.cmdKey, k); err != nil {
			return EnrollResult{}, err
		}
	}
	res.ConfigPath = filepath.Join(opts.Dir, "agent.yaml")
	if err := writeAgentConfig(res.ConfigPath, res.AgentURL, paths); err != nil {
		return EnrollResult{}, err
	}
	if opts.Owner != "" {
		if err := chownAll(opts.Owner, opts.Dir, paths.key, paths.cert, paths.ca, paths.cmdKey, res.ConfigPath); err != nil {
			return EnrollResult{}, err
		}
	}
	return res, nil
}

// checkEnrollResponse verifies that the issued certificate chains to the returned CA,
// carries the returned identity, and that the pinned server certificate belongs to the
// same CA.
func checkEnrollResponse(m *agentv1.EnrollResponse, serverChain []*x509.Certificate) (EnrollResult, []*x509.Certificate, *x509.Certificate, error) {
	fail := func(format string, a ...any) (EnrollResult, []*x509.Certificate, *x509.Certificate, error) {
		return EnrollResult{}, nil, nil, fmt.Errorf("enroll: invalid response: "+format, a...)
	}
	root, err := x509.ParseCertificate(m.GetCaCertificate())
	if err != nil {
		return fail("CA certificate: %v", err)
	}
	if len(m.GetCertificateChain()) == 0 {
		return fail("empty certificate chain")
	}
	var chain []*x509.Certificate
	for _, der := range m.GetCertificateChain() {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fail("certificate chain: %v", err)
		}
		chain = append(chain, c)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fail("agent certificate does not verify: %v", err)
	}
	id, err := pki.AgentID(chain[0])
	if err != nil {
		return fail("%v", err)
	}
	if id.String() != m.GetServerId() {
		return fail("certificate identity %s does not match server id %s", id, m.GetServerId())
	}
	if len(serverChain) == 0 {
		return fail("no server certificate observed")
	}
	srvInter := x509.NewCertPool()
	for _, c := range serverChain[1:] {
		srvInter.AddCert(c)
	}
	if _, err := serverChain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: srvInter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return fail("control-plane certificate is not issued by the returned CA: %v", err)
	}
	return EnrollResult{ServerID: id, ServerName: m.GetServerName()}, chain, root, nil
}

// chownAll gives the agent user its files. Missing files are skipped.
func chownAll(owner string, paths ...string) error {
	u, err := user.Lookup(owner)
	if err != nil {
		return fmt.Errorf("owner %q: %w (create it, e.g. useradd --system smagent)", owner, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}
	for _, p := range paths {
		if err := os.Chown(p, uid, gid); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

type filePaths struct{ key, cert, ca, cmdKey string }

func agentPaths(dir string) filePaths {
	return filePaths{
		key:    filepath.Join(dir, "agent.key"),
		cert:   filepath.Join(dir, "agent.crt"),
		ca:     filepath.Join(dir, "ca.crt"),
		cmdKey: filepath.Join(dir, "command.pub"),
	}
}

func writeAgentConfig(path, agentURL string, p filePaths) error {
	abs := func(s string) string {
		if a, err := filepath.Abs(s); err == nil {
			return a
		}
		return s
	}
	cfg := map[string]string{
		"server_url": agentURL,
		"ca_file":    abs(p.ca),
		"cert_file":  abs(p.cert),
		"key_file":   abs(p.key),
		// Written at enrollment, or on first connection for older control planes.
		"command_key_file": abs(p.cmdKey),
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	data = append([]byte("# Written by `sm-agent enroll`. Keys can be overridden with SM_AGENT_<KEY>.\n"), data...)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // path under the agent's own directory
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
