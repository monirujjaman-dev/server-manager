package agent

import (
	"errors"
	"testing"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
)

func batch(load float64) *agentv1.MetricsBatch {
	return &agentv1.MetricsBatch{Host: &agentv1.HostMetrics{Load1: load}}
}

func TestMetricsBufferDropsOldestAndRequeues(t *testing.T) {
	b := newMetricsBuffer(3)
	for i := range 5 {
		b.push(batch(float64(i)))
	}
	if b.len() != 3 || b.dropped != 2 {
		t.Fatalf("len %d dropped %d", b.len(), b.dropped)
	}
	a := &Agent{metrics: b}
	var sent []float64
	fail := errors.New("stream broken")
	err := a.sendMetrics(func(r *agentv1.ConnectRequest) error {
		if len(sent) == 1 {
			return fail
		}
		sent = append(sent, r.GetMetrics().GetHost().GetLoad1())
		return nil
	})
	if !errors.Is(err, fail) || len(sent) != 1 || sent[0] != 2 {
		t.Fatalf("err %v sent %v", err, sent)
	}
	got := b.take()
	if len(got) != 2 || got[0].GetHost().GetLoad1() != 3 || got[1].GetHost().GetLoad1() != 4 {
		t.Fatalf("requeued %v", got)
	}
}
