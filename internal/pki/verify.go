package pki

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// RevocationChecker reports whether a certificate serial number has been revoked.
// Implementations must fail closed: an error rejects the connection.
type RevocationChecker interface {
	IsRevoked(ctx context.Context, serial *big.Int) (bool, error)
}

// RevocationList is an in-memory RevocationChecker for tests. The control plane uses a
// database-backed checker so revocation is shared by all replicas and survives restarts.
type RevocationList struct {
	mu      sync.RWMutex
	revoked map[string]struct{}
}

// NewRevocationList returns an empty list.
func NewRevocationList() *RevocationList {
	return &RevocationList{revoked: make(map[string]struct{})}
}

// Revoke marks serial as revoked.
func (l *RevocationList) Revoke(serial *big.Int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.revoked[serial.Text(16)] = struct{}{}
}

// IsRevoked implements RevocationChecker.
func (l *RevocationList) IsRevoked(_ context.Context, serial *big.Int) (bool, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	_, ok := l.revoked[serial.Text(16)]
	return ok, nil
}

// ErrRevoked is returned for revoked certificates.
var ErrRevoked = errors.New("certificate revoked")

// VerifyAgentConnection returns a tls.Config.VerifyConnection hook for the agent gateway.
// It runs after the standard chain verification and additionally requires a well-formed
// agent identity and a non-revoked certificate.
func VerifyAgentConnection(rc RevocationChecker) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
			return errors.New("no verified client certificate")
		}
		leaf := cs.VerifiedChains[0][0]
		if _, err := AgentID(leaf); err != nil {
			return err
		}
		// tls.Config.VerifyConnection has no context; bound the lookup instead.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		revoked, err := rc.IsRevoked(ctx, leaf.SerialNumber)
		if err != nil {
			return fmt.Errorf("revocation check: %w", err)
		}
		if revoked {
			return ErrRevoked
		}
		return nil
	}
}

// AgentServerTLSConfig returns the TLS configuration for the agent gateway listener:
// TLS 1.3 only, client certificates required and verified against the internal root,
// plus identity and revocation checks.
func AgentServerTLSConfig(ca *CA, serverCert tls.Certificate, rc RevocationChecker) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{serverCert},
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        ca.RootPool(),
		VerifyConnection: VerifyAgentConnection(rc),
		NextProtos:       []string{"h2"},
	}
}
