package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func mustCA(t *testing.T) *CA {
	t.Helper()
	ca, err := CreateCA("Test Org")
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func verifyOpts(ca *CA, usage x509.ExtKeyUsage, at time.Time) x509.VerifyOptions {
	inter := x509.NewCertPool()
	inter.AddCert(ca.Intermediate)
	return x509.VerifyOptions{Roots: ca.RootPool(), Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{usage}, CurrentTime: at}
}

func issueAgent(t *testing.T, ca *CA) (*x509.Certificate, tls.Certificate, uuid.UUID) {
	t.Helper()
	key, csr, err := NewAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	cert, err := ca.SignAgentCSR(csr, id)
	if err != nil {
		t.Fatal(err)
	}
	return cert, ca.TLSCertificate(cert, key), id
}

func TestCAHierarchy(t *testing.T) {
	ca := mustCA(t)
	if !ca.Root.IsCA || !ca.Intermediate.IsCA {
		t.Fatal("root and intermediate must be CAs")
	}
	if ca.Intermediate.MaxPathLen != 0 || !ca.Intermediate.MaxPathLenZero {
		t.Error("intermediate must not be able to sign further CAs")
	}
	if err := ca.Intermediate.CheckSignatureFrom(ca.Root); err != nil {
		t.Fatal(err)
	}
}

func TestSignAgentCSR(t *testing.T) {
	ca := mustCA(t)
	cert, _, id := issueAgent(t, ca)

	got, err := AgentID(cert)
	if err != nil || got != id {
		t.Fatalf("AgentID = %v, %v; want %v", got, err, id)
	}
	if _, err := cert.Verify(verifyOpts(ca, x509.ExtKeyUsageClientAuth, time.Now())); err != nil {
		t.Fatalf("agent cert does not verify for clientAuth: %v", err)
	}
	if _, err := cert.Verify(verifyOpts(ca, x509.ExtKeyUsageServerAuth, time.Now())); err == nil {
		t.Fatal("agent cert must not be usable as a server certificate")
	}
	if life := cert.NotAfter.Sub(cert.NotBefore); life > AgentCertValidity+clockSkew {
		t.Errorf("agent cert lifetime %v too long", life)
	}
}

func TestSignAgentCSRIgnoresRequestedIdentity(t *testing.T) {
	ca := mustCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "evil"},
		DNSNames: []string{"control-plane.example.com"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	cert, err := ca.SignAgentCSR(csr, id)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != id.String() || len(cert.DNSNames) != 0 {
		t.Fatalf("CSR identity leaked into certificate: CN=%q DNS=%v", cert.Subject.CommonName, cert.DNSNames)
	}
}

func TestSignAgentCSRRejects(t *testing.T) {
	ca := mustCA(t)
	_, goodCSR, _ := NewAgentKey()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaCSR, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, rsaKey)

	tampered := append([]byte(nil), goodCSR...)
	tampered[len(tampered)-1] ^= 0xff

	cases := map[string]struct {
		csr []byte
		id  uuid.UUID
	}{
		"nil id":        {goodCSR, uuid.Nil},
		"rsa key":       {rsaCSR, uuid.New()},
		"bad signature": {tampered, uuid.New()},
		"garbage":       {[]byte("nope"), uuid.New()},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ca.SignAgentCSR(tc.csr, tc.id); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestAgentCertExpiry(t *testing.T) {
	ca := mustCA(t)
	cert, _, _ := issueAgent(t, ca)
	if _, err := cert.Verify(verifyOpts(ca, x509.ExtKeyUsageClientAuth, time.Now().Add(AgentCertValidity+time.Hour))); err == nil {
		t.Fatal("expired agent cert must not verify")
	}
}

func TestAgentIDRejectsServerCert(t *testing.T) {
	ca := mustCA(t)
	srv, _, err := ca.IssueServerCert([]string{"cp.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AgentID(srv); !errors.Is(err, ErrNotAgentCert) {
		t.Fatalf("AgentID(server cert) err = %v", err)
	}
}

func TestSaveLoadCA(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	ca := mustCA(t)
	if err := SaveCA(dir, ca); err != nil {
		t.Fatal(err)
	}
	if err := SaveCA(dir, ca); err == nil {
		t.Fatal("SaveCA must refuse to overwrite an existing CA")
	}
	fi, err := os.Stat(filepath.Join(dir, IntermediateKeyFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("intermediate key mode = %v, %v", fi.Mode().Perm(), err)
	}
	loaded, err := LoadCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Root.Equal(ca.Root) || !loaded.Intermediate.Equal(ca.Intermediate) || loaded.RootKey == nil {
		t.Fatal("loaded CA differs")
	}

	// Root key moved offline: loading still works.
	if err := os.Remove(filepath.Join(dir, RootKeyFile)); err != nil {
		t.Fatal(err)
	}
	loaded, err = LoadCA(dir)
	if err != nil || loaded.RootKey != nil {
		t.Fatalf("load without root key: %v (root key %v)", err, loaded.RootKey)
	}

	// Keys with open permissions are refused.
	if err := os.Chmod(filepath.Join(dir, IntermediateKeyFile), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCA(dir); err == nil {
		t.Fatal("expected refusal of world-readable key")
	}
}

// handshake connects a TLS client to a server using the agent gateway config over
// loopback TCP. In TLS 1.3 the server verifies the client certificate after the client
// has finished its side of the handshake, so the client reads one byte the server sends
// only after a successful handshake.
func handshake(t *testing.T, serverCfg, clientCfg *tls.Config) error {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		s := tls.Server(c, serverCfg)
		_ = s.SetDeadline(time.Now().Add(5 * time.Second))
		if s.Handshake() == nil {
			_, _ = s.Write([]byte{1})
		}
	}()
	c, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = c.Read(make([]byte, 1))
	return err
}

func TestAgentGatewayHandshake(t *testing.T) {
	ca := mustCA(t)
	srvCert, srvKey, err := ca.IssueServerCert([]string{"cp.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rl := NewRevocationList()
	serverCfg := AgentServerTLSConfig(ca, ca.TLSCertificate(srvCert, srvKey), rl)
	client := func(certs ...tls.Certificate) *tls.Config {
		return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: ca.RootPool(), ServerName: "cp.test", Certificates: certs}
	}

	agentCert, agentTLS, _ := issueAgent(t, ca)
	if err := handshake(t, serverCfg, client(agentTLS)); err != nil {
		t.Fatalf("valid agent rejected: %v", err)
	}

	t.Run("no client cert", func(t *testing.T) {
		if err := handshake(t, serverCfg, client()); err == nil {
			t.Fatal("expected rejection")
		}
	})
	t.Run("foreign CA", func(t *testing.T) {
		_, foreignTLS, _ := issueAgent(t, mustCA(t))
		if err := handshake(t, serverCfg, client(foreignTLS)); err == nil {
			t.Fatal("expected rejection")
		}
	})
	t.Run("server cert used as client cert", func(t *testing.T) {
		if err := handshake(t, serverCfg, client(ca.TLSCertificate(srvCert, srvKey))); err == nil {
			t.Fatal("expected rejection")
		}
	})
	t.Run("revoked", func(t *testing.T) {
		rl.Revoke(agentCert.SerialNumber)
		if err := handshake(t, serverCfg, client(agentTLS)); err == nil {
			t.Fatal("expected rejection")
		}
	})
}
