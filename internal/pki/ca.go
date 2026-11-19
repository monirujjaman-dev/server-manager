// Package pki implements the internal certificate authority that issues mTLS
// certificates to agents and to the control plane.
//
// Hierarchy:
//
//	root CA (10 years, key can be moved offline after init)
//	└── intermediate CA (5 years, signs everything day to day)
//	    ├── control-plane server certificates (1 year, serverAuth)
//	    └── agent client certificates (30 days, clientAuth, identity = server UUID)
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"

	"github.com/google/uuid"
)

// Validity periods.
const (
	RootValidity         = 10 * 365 * 24 * time.Hour
	IntermediateValidity = 5 * 365 * 24 * time.Hour
	ServerCertValidity   = 365 * 24 * time.Hour
	AgentCertValidity    = 30 * 24 * time.Hour

	// clockSkew backdates NotBefore so that hosts with slightly slow clocks accept new certificates.
	clockSkew = 5 * time.Minute
)

// CA is the internal certificate authority.
type CA struct {
	Root *x509.Certificate
	// RootKey is nil when the root key has been moved offline; it is only needed to
	// issue a new intermediate.
	RootKey         crypto.Signer
	Intermediate    *x509.Certificate
	IntermediateKey crypto.Signer

	// Now returns the current time; tests override it.
	Now func() time.Time
}

func (ca *CA) now() time.Time {
	if ca.Now != nil {
		return ca.Now()
	}
	return time.Now()
}

// CreateCA generates a new root and intermediate CA for the given organization name.
func CreateCA(org string) (*CA, error) {
	if org == "" {
		org = "Server Manager"
	}
	ca := &CA{}
	now := ca.now()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate root key: %w", err)
	}
	rootTmpl := &x509.Certificate{
		Subject:               pkix.Name{Organization: []string{org}, CommonName: org + " Root CA"},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(RootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	root, err := createCert(rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	if err != nil {
		return nil, fmt.Errorf("create root: %w", err)
	}

	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate intermediate key: %w", err)
	}
	intTmpl := &x509.Certificate{
		Subject:               pkix.Name{Organization: []string{org}, CommonName: org + " Intermediate CA"},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(IntermediateValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	intermediate, err := createCert(intTmpl, root, intKey.Public(), rootKey)
	if err != nil {
		return nil, fmt.Errorf("create intermediate: %w", err)
	}

	ca.Root, ca.RootKey = root, rootKey
	ca.Intermediate, ca.IntermediateKey = intermediate, intKey
	return ca, nil
}

// IssueServerCert creates a TLS server certificate for the control plane.
func (ca *CA) IssueServerCert(dnsNames []string, ips []net.IP) (*x509.Certificate, crypto.Signer, error) {
	if len(dnsNames) == 0 && len(ips) == 0 {
		return nil, nil, errors.New("server certificate needs at least one DNS name or IP address")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	cn := ""
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	} else {
		cn = ips[0].String()
	}
	now := ca.now()
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{Organization: ca.Intermediate.Subject.Organization, CommonName: cn},
		NotBefore:   now.Add(-clockSkew),
		NotAfter:    now.Add(ServerCertValidity),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dnsNames,
		IPAddresses: ips,
	}
	cert, err := createCert(tmpl, ca.Intermediate, key.Public(), ca.IntermediateKey)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// SignAgentCSR issues an agent client certificate for serverID from a CSR generated on
// the agent. Only the CSR's public key is used: subject and SANs are set by the CA, so an
// agent cannot request a different identity.
func (ca *CA) SignAgentCSR(csrDER []byte, serverID uuid.UUID) (*x509.Certificate, error) {
	if serverID == uuid.Nil {
		return nil, errors.New("server ID must not be empty")
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature: %w", err)
	}
	if err := checkAgentKey(csr.PublicKey); err != nil {
		return nil, err
	}
	now := ca.now()
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{Organization: ca.Intermediate.Subject.Organization, CommonName: serverID.String()},
		NotBefore:   now.Add(-clockSkew),
		NotAfter:    now.Add(AgentCertValidity),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:        []*url.URL{agentURI(serverID)},
	}
	return createCert(tmpl, ca.Intermediate, csr.PublicKey, ca.IntermediateKey)
}

func checkAgentKey(pub any) error {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return nil
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() {
			return nil
		}
		return fmt.Errorf("unsupported ECDSA curve %s", k.Curve.Params().Name)
	default:
		return fmt.Errorf("unsupported agent key type %T (want Ed25519 or ECDSA P-256)", pub)
	}
}

// RootPool returns a pool containing only the root certificate.
func (ca *CA) RootPool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Root)
	return p
}

// TLSCertificate builds a tls.Certificate that presents leaf plus the intermediate.
func (ca *CA) TLSCertificate(leaf *x509.Certificate, key crypto.Signer) tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{leaf.Raw, ca.Intermediate.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}
}

// SPKIFingerprint returns the hex SHA-256 of a certificate's public key, used to pin the
// control plane during enrollment. It stays stable across renewals with the same key.
func SPKIFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

var serialLimit = new(big.Int).Lsh(big.NewInt(1), 128)

func createCert(tmpl, parent *x509.Certificate, pub any, signer crypto.Signer) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = serial.Add(serial, big.NewInt(1)) // never zero
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}
