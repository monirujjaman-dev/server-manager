// Package ctl implements smctl commands.
package ctl

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"

	"connectrpc.com/connect"

	operatorv1 "github.com/monirujjaman-dev/server-manager/gen/sm/operator/v1"
	"github.com/monirujjaman-dev/server-manager/gen/sm/operator/v1/operatorv1connect"
	"github.com/monirujjaman-dev/server-manager/internal/pki"
)

// HealthResult is the outcome of a health check.
type HealthResult struct {
	Serving bool
	Skew    time.Duration
	Latency time.Duration
}

// Health checks the control plane's operator API. caFile may be empty to use the
// system trust store.
func Health(ctx context.Context, serverURL, caFile string) (HealthResult, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if caFile != "" {
		certs, err := pki.ReadCertFile(caFile)
		if err != nil {
			return HealthResult{}, err
		}
		pool := x509.NewCertPool()
		for _, c := range certs {
			pool.AddCert(c)
		}
		tlsCfg.RootCAs = pool
	}
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg, ForceAttemptHTTP2: true}}
	client := operatorv1connect.NewHealthServiceClient(hc, serverURL)

	start := time.Now()
	resp, err := client.Check(ctx, connect.NewRequest(&operatorv1.CheckRequest{}))
	if err != nil {
		return HealthResult{}, fmt.Errorf("health check: %w", err)
	}
	latency := time.Since(start)
	return HealthResult{
		Serving: resp.Msg.GetStatus() == operatorv1.ServingStatus_SERVING_STATUS_SERVING,
		Skew:    resp.Msg.GetServerTime().AsTime().Sub(start.Add(latency / 2)),
		Latency: latency,
	}, nil
}
