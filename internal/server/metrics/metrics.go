// Package metrics stores agent metrics: the latest snapshot per server in PostgreSQL
// (for the dashboard) and, optionally, the full history in VictoriaMetrics.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/google/uuid"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/internal/server/store/db"
)

// Limits on what an agent may report in one batch.
const (
	maxFilesystems = 64
	maxInterfaces  = 64
	maxLabelLen    = 128
	maxAge         = 24 * time.Hour
	maxFuture      = 5 * time.Minute
)

// Sink receives batches from the gateway.
type Sink struct {
	q   *db.Queries
	vm  *VMWriter // nil when no VictoriaMetrics is configured
	log *slog.Logger
	now func() time.Time
}

// NewSink creates a sink. vm may be nil.
func NewSink(q *db.Queries, vm *VMWriter, log *slog.Logger) *Sink {
	return &Sink{q: q, vm: vm, log: log, now: time.Now}
}

// Validate rejects batches that are malformed, implausible or too large.
func Validate(b *agentv1.MetricsBatch, now time.Time) error {
	if b.GetCollectedAt() == nil || b.GetHost() == nil {
		return errors.New("missing timestamp or host metrics")
	}
	at := b.GetCollectedAt().AsTime()
	if at.Before(now.Add(-maxAge)) || at.After(now.Add(maxFuture)) {
		return fmt.Errorf("collected_at %s out of range", at.Format(time.RFC3339))
	}
	h := b.GetHost()
	if len(h.GetFilesystems()) > maxFilesystems || len(h.GetInterfaces()) > maxInterfaces {
		return errors.New("too many filesystems or interfaces")
	}
	for _, f := range h.GetFilesystems() {
		if len(f.GetMountPoint()) > maxLabelLen || len(f.GetFsType()) > maxLabelLen || len(f.GetDevice()) > maxLabelLen {
			return errors.New("filesystem label too long")
		}
	}
	for _, n := range h.GetInterfaces() {
		if len(n.GetName()) > maxLabelLen {
			return errors.New("interface name too long")
		}
	}
	for _, v := range []float64{h.GetCpuPercent(), h.GetLoad1(), h.GetLoad5(), h.GetLoad15()} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			return errors.New("invalid numeric value")
		}
	}
	return nil
}

// Record stores one batch.
func (s *Sink) Record(ctx context.Context, serverID uuid.UUID, b *agentv1.MetricsBatch) error {
	if err := Validate(b, s.now()); err != nil {
		return err
	}
	h := b.GetHost()
	maxPct, maxMount := 0.0, ""
	for _, f := range h.GetFilesystems() {
		if f.GetTotalBytes() == 0 {
			continue
		}
		pct := float64(f.GetTotalBytes()-min(f.GetAvailableBytes(), f.GetTotalBytes())) / float64(f.GetTotalBytes()) * 100
		if pct >= maxPct {
			maxPct, maxMount = pct, f.GetMountPoint()
		}
	}
	var rx, tx float64
	for _, n := range h.GetInterfaces() {
		rx += n.GetRxBytesPerSecond()
		tx += n.GetTxBytesPerSecond()
	}
	if err := s.q.UpsertServerMetrics(ctx, db.UpsertServerMetricsParams{
		ServerID: serverID, CollectedAt: b.GetCollectedAt().AsTime(), CpuPercent: h.GetCpuPercent(),
		CpuCount: int32(min(h.GetCpuCount(), math.MaxInt32)), Load1: h.GetLoad1(), Load5: h.GetLoad5(), Load15: h.GetLoad15(), //nolint:gosec // bounded
		MemoryTotalBytes: clampInt64(h.GetMemoryTotalBytes()), MemoryAvailableBytes: clampInt64(h.GetMemoryAvailableBytes()),
		SwapTotalBytes: clampInt64(h.GetSwapTotalBytes()), SwapFreeBytes: clampInt64(h.GetSwapFreeBytes()),
		UptimeSeconds: clampInt64(h.GetUptimeSeconds()), DiskMaxUsedPercent: maxPct, DiskMaxMount: maxMount,
		NetRxBytesPerSecond: rx, NetTxBytesPerSecond: tx,
	}); err != nil {
		return err
	}
	if s.vm != nil {
		s.vm.Enqueue(PrometheusLines(serverID, b))
	}
	return nil
}

func clampInt64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}
