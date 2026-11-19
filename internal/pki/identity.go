package pki

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"slices"

	"github.com/google/uuid"
)

// AgentURIScheme and AgentURIHost form the URI SAN of agent certificates:
// sm://agent/<server-uuid>.
const (
	AgentURIScheme = "sm"
	AgentURIHost   = "agent"
)

func agentURI(id uuid.UUID) *url.URL {
	return &url.URL{Scheme: AgentURIScheme, Host: AgentURIHost, Path: "/" + id.String()}
}

// ErrNotAgentCert is returned when a certificate is not a valid agent certificate.
var ErrNotAgentCert = errors.New("not an agent certificate")

// AgentID extracts the server UUID from a verified agent client certificate. The
// certificate must carry exactly one sm://agent/<uuid> URI SAN, a matching common name,
// the clientAuth extended key usage and no DNS, IP or e-mail SANs.
func AgentID(cert *x509.Certificate) (uuid.UUID, error) {
	if cert == nil {
		return uuid.Nil, ErrNotAgentCert
	}
	if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return uuid.Nil, fmt.Errorf("%w: missing clientAuth usage", ErrNotAgentCert)
	}
	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 || len(cert.EmailAddresses) > 0 {
		return uuid.Nil, fmt.Errorf("%w: unexpected SANs", ErrNotAgentCert)
	}
	if len(cert.URIs) != 1 {
		return uuid.Nil, fmt.Errorf("%w: want exactly one URI SAN", ErrNotAgentCert)
	}
	u := cert.URIs[0]
	if u.Scheme != AgentURIScheme || u.Host != AgentURIHost || len(u.Path) < 2 {
		return uuid.Nil, fmt.Errorf("%w: bad URI SAN %q", ErrNotAgentCert, u.String())
	}
	id, err := uuid.Parse(u.Path[1:])
	if err != nil || id == uuid.Nil {
		return uuid.Nil, fmt.Errorf("%w: bad server ID in URI SAN", ErrNotAgentCert)
	}
	if cert.Subject.CommonName != id.String() {
		return uuid.Nil, fmt.Errorf("%w: common name does not match URI SAN", ErrNotAgentCert)
	}
	return id, nil
}
