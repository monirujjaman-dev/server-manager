package agent

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/internal/pki"
)

var errRenewed = errors.New("certificate renewed")

// renewLoop checks the certificate at start and then every RenewCheckInterval.
func (a *Agent) renewLoop(ctx context.Context) {
	ticker := time.NewTicker(a.cfg.RenewCheckInterval)
	defer ticker.Stop()
	for {
		renewed, err := a.renewIfDue(ctx)
		switch {
		case err != nil && ctx.Err() == nil:
			a.log.Error("certificate renewal failed", "err", err)
		case renewed:
			select {
			case a.renewed <- struct{}{}:
			default:
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// renewIfDue renews the certificate when less than RenewBefore of its lifetime remains.
// The key is kept: only the certificate file changes, and it is replaced atomically.
func (a *Agent) renewIfDue(ctx context.Context) (bool, error) {
	certs, err := pki.ReadCertFile(a.cfg.CertFile)
	if err != nil {
		return false, err
	}
	cur := certs[0]
	lifetime := cur.NotAfter.Sub(cur.NotBefore)
	remaining := time.Until(cur.NotAfter)
	if remaining <= 0 {
		return false, fmt.Errorf("certificate expired on %s; re-enroll this server", cur.NotAfter.Format(time.RFC3339))
	}
	if float64(remaining) > float64(lifetime)*a.cfg.RenewBefore {
		return false, nil
	}
	key, err := pki.ReadKeyFile(a.cfg.KeyFile)
	if err != nil {
		return false, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "sm-agent"}}, key)
	if err != nil {
		return false, err
	}
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := a.client.RenewCertificate(reqCtx, connect.NewRequest(&agentv1.RenewCertificateRequest{Csr: csr}))
	if err != nil {
		return false, fmt.Errorf("renew: %w", err)
	}
	chain, err := a.checkRenewed(resp.Msg.GetCertificateChain(), cur)
	if err != nil {
		return false, err
	}
	if err := pki.WriteCertFile(a.cfg.CertFile, chain...); err != nil {
		return false, err
	}
	a.log.Info("certificate renewed", "not_after", chain[0].NotAfter.Format(time.RFC3339))
	return true, nil
}

// checkRenewed verifies the new chain against the CA and requires the same identity.
func (a *Agent) checkRenewed(ders [][]byte, cur *x509.Certificate) ([]*x509.Certificate, error) {
	if len(ders) == 0 {
		return nil, errors.New("renew: empty certificate chain")
	}
	var chain []*x509.Certificate
	inter := x509.NewCertPool()
	for i, der := range ders {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("renew: %w", err)
		}
		if i > 0 {
			inter.AddCert(c)
		}
		chain = append(chain, c)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: a.roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, fmt.Errorf("renew: new certificate does not verify: %w", err)
	}
	newID, err := pki.AgentID(chain[0])
	if err != nil {
		return nil, err
	}
	oldID, err := pki.AgentID(cur)
	if err != nil {
		return nil, err
	}
	if newID != oldID {
		return nil, fmt.Errorf("renew: identity changed from %s to %s", oldID, newID)
	}
	return chain, nil
}
