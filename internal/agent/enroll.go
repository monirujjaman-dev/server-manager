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
	"github.com/monirujjaman-dev/server-manager/internal/privd"
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
	// Dir receives agent.key, agent.crt, ca.crt and agent.yaml. It belongs to the agent.
	Dir string
	// TrustDir receives the command verification key and the server identity that the
	// privileged helper trusts. It must not be inside Dir: in production it is
	// /etc/sm-agent-trust, owned by root and only readable by the agent.
	TrustDir string
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
	if err := checkTrustDir(opts.Dir, opts.TrustDir); err != nil {
		return EnrollResult{}, err
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

	cmdKey := resp.Msg.GetCommandPublicKey()
	if len(cmdKey) != ed25519.PublicKeySize {
		return EnrollResult{}, errors.New("enroll: the control plane sent no command key; upgrade sm-server")
	}

	res.AgentURL = opts.AgentURL
	if res.AgentURL == "" {
		res.AgentURL = resp.Msg.GetAgentUrl()
	}
	if res.AgentURL == "" {
		res.AgentURL = "https://" + net.JoinHostPort(u.Hostname(), "8443")
	}

	// The trust files come first and stay owned by whoever runs enroll (root in
	// production), never by Owner. Writing them before the agent's key means a failed
	// enrollment can simply be retried and never leaves an identity without them.
	if err := privd.WriteTrust(opts.TrustDir, res.ServerID, cmdKey); err != nil {
		return EnrollResult{}, fmt.Errorf("write trust files: %w", err)
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
	res.ConfigPath = filepath.Join(opts.Dir, "agent.yaml")
	cmdKeyPath, _ := privd.TrustPaths(opts.TrustDir)
	if err := writeAgentConfig(res.ConfigPath, res.AgentURL, paths, cmdKeyPath); err != nil {
		return EnrollResult{}, err
	}
	if opts.Owner != "" {
		if err := chownAll(opts.Owner, opts.Dir, paths.key, paths.cert, paths.ca, res.ConfigPath); err != nil {
			return EnrollResult{}, err
		}
	}
	return res, nil
}

// checkTrustDir refuses a trust directory inside (or equal to) the agent's directory,
// where the agent could replace it.
func checkTrustDir(dir, trustDir string) error {
	if trustDir == "" {
		return errors.New("a trust directory is required (e.g. " + privd.DefaultTrustDir + ")")
	}
	d, err1 := resolveExisting(dir)
	t, err2 := resolveExisting(trustDir)
	if err := errors.Join(err1, err2); err != nil {
		return err
	}
	rel, err := filepath.Rel(d, t)
	if err != nil {
		return err
	}
	outside := rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
	if !outside { // also rejects rel == "." (the same directory)
		return fmt.Errorf("trust directory %s must not be inside the agent directory %s", trustDir, dir)
	}
	return nil
}

// resolveExisting makes p absolute and resolves symlinks in the part of it that exists,
// so a symlinked directory cannot hide that one path is inside the other.
func resolveExisting(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	var rest []string
	for cur := abs; ; cur = filepath.Dir(cur) {
		if real, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(append([]string{real}, rest...)...), nil
		}
		if filepath.Dir(cur) == cur {
			return abs, nil
		}
		rest = append([]string{filepath.Base(cur)}, rest...)
	}
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

type filePaths struct{ key, cert, ca string }

func agentPaths(dir string) filePaths {
	return filePaths{
		key:  filepath.Join(dir, "agent.key"),
		cert: filepath.Join(dir, "agent.crt"),
		ca:   filepath.Join(dir, "ca.crt"),
	}
}

func writeAgentConfig(path, agentURL string, p filePaths, cmdKey string) error {
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
		// Root-owned; written at enrollment and never by the agent.
		"command_key_file": abs(cmdKey),
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

// MigrateTrust moves an existing enrollment to the root-owned trust directory. Agents
// enrolled before it existed kept the command key in their own directory, where the
// agent could replace it. It copies that key and the identity from agent.crt into
// trustDir unless trustDir already has them, and reports whether it did. Run it as
// root (the package's post-install script does).
//
// This trusts the key as it is in agentDir at the time of the migration; if the agent
// could have been compromised before, re-enroll instead.
func MigrateTrust(agentDir, trustDir string) (bool, error) {
	if err := checkTrustDir(agentDir, trustDir); err != nil {
		return false, err
	}
	// Anything already in the trust directory wins: never replace a key there with one
	// from the agent's directory.
	keyPath, idPath := privd.TrustPaths(trustDir)
	for _, p := range []string{keyPath, idPath} {
		if _, err := os.Lstat(p); err == nil || !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	// Both inputs are in a directory the agent controls: read them without following
	// symlinks, only as small regular files.
	paths := agentPaths(agentDir)
	certData, err := readAgentFile(paths.cert)
	if err != nil {
		return false, fmt.Errorf("agent certificate: %w", err)
	}
	certs, err := pki.ParseCerts(certData, paths.cert)
	if err != nil {
		return false, err
	}
	id, err := pki.AgentID(certs[0])
	if err != nil {
		return false, err
	}
	keyFile := filepath.Join(agentDir, "command.pub")
	keyData, err := readAgentFile(keyFile)
	if err != nil {
		return false, fmt.Errorf("command key: %w (re-enroll this server)", err)
	}
	key, err := pki.ParseCommandPublicKey(keyData, keyFile)
	if err != nil {
		return false, fmt.Errorf("command key: %w (re-enroll this server)", err)
	}
	if err := privd.WriteTrust(trustDir, id, key); err != nil {
		return false, err
	}
	return true, nil
}
