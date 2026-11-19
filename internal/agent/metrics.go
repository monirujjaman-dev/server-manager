package agent

import (
	"context"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/internal/agent/modules"
)

// metricsBuffer holds batches until a stream sends them. When full, the oldest batch is
// dropped. It is in memory: batches survive disconnects but not an agent restart.
type metricsBuffer struct {
	mu      sync.Mutex
	batches []*agentv1.MetricsBatch
	max     int
	dropped uint64
	ready   chan struct{}
}

func newMetricsBuffer(max int) *metricsBuffer {
	return &metricsBuffer{max: max, ready: make(chan struct{}, 1)}
}

func (b *metricsBuffer) push(m *agentv1.MetricsBatch) {
	b.mu.Lock()
	if len(b.batches) >= b.max {
		b.batches = b.batches[1:]
		b.dropped++
	}
	b.batches = append(b.batches, m)
	b.mu.Unlock()
	select {
	case b.ready <- struct{}{}:
	default:
	}
}

// take removes and returns all buffered batches, oldest first.
func (b *metricsBuffer) take() []*agentv1.MetricsBatch {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := b.batches
	b.batches = nil
	return out
}

// requeue puts unsent batches back in front of newer ones, keeping the size bound.
func (b *metricsBuffer) requeue(unsent []*agentv1.MetricsBatch) {
	b.mu.Lock()
	defer b.mu.Unlock()
	all := append(unsent, b.batches...)
	if over := len(all) - b.max; over > 0 {
		all = all[over:]
		b.dropped += uint64(over)
	}
	b.batches = all
}

func (b *metricsBuffer) len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.batches)
}

// metricsLoop collects a batch every MetricsInterval.
func (a *Agent) metricsLoop(ctx context.Context) {
	c := modules.NewCollector(a.host)
	t := time.NewTicker(a.cfg.MetricsInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m, err := c.Collect()
			if err != nil {
				a.log.Warn("collect metrics", "err", err)
				continue
			}
			a.metrics.push(&agentv1.MetricsBatch{CollectedAt: timestamppb.Now(), Host: m})
		}
	}
}

// sendMetrics flushes the buffer on stream. Unsent batches go back to the buffer.
func (a *Agent) sendMetrics(send func(*agentv1.ConnectRequest) error) error {
	batches := a.metrics.take()
	for i, m := range batches {
		if err := send(&agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_Metrics{Metrics: m}}); err != nil {
			a.metrics.requeue(batches[i:])
			return err
		}
	}
	return nil
}
