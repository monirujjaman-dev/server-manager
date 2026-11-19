package ctl

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"

	operatorv1 "github.com/monirujjaman-dev/server-manager/gen/sm/operator/v1"
)

// HealthResult is the outcome of a health check.
type HealthResult struct {
	Serving bool
	Skew    time.Duration
	Latency time.Duration
}

// Health checks the control plane's operator API (no login needed).
func Health(ctx context.Context, c *Client) (HealthResult, error) {
	start := time.Now()
	resp, err := c.Health.Check(ctx, connect.NewRequest(&operatorv1.CheckRequest{}))
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
