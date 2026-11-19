// Package api implements the operator-facing API services.
package api

import (
	"context"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	operatorv1 "github.com/monirujjaman-dev/server-manager/gen/sm/operator/v1"
	"github.com/monirujjaman-dev/server-manager/gen/sm/operator/v1/operatorv1connect"
)

// Health implements operatorv1connect.HealthServiceHandler.
type Health struct {
	operatorv1connect.UnimplementedHealthServiceHandler
	// Ready reports whether the control plane can serve requests.
	Ready func() bool
}

// Check implements the health check.
func (h *Health) Check(context.Context, *connect.Request[operatorv1.CheckRequest]) (*connect.Response[operatorv1.CheckResponse], error) {
	status := operatorv1.ServingStatus_SERVING_STATUS_SERVING
	if h.Ready != nil && !h.Ready() {
		status = operatorv1.ServingStatus_SERVING_STATUS_NOT_SERVING
	}
	return connect.NewResponse(&operatorv1.CheckResponse{
		Status:     status,
		ServerTime: timestamppb.New(time.Now()),
	}), nil
}
