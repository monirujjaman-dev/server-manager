package metrics

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/internal/server/store/db"
	"github.com/monirujjaman-dev/server-manager/internal/server/store/storetest"
)

func sample(at time.Time, cpu float64) *agentv1.MetricsBatch {
	return &agentv1.MetricsBatch{CollectedAt: timestamppb.New(at), Host: &agentv1.HostMetrics{
		CpuPercent: cpu, CpuCount: 2, Load1: 0.5, MemoryTotalBytes: 1000, MemoryAvailableBytes: 250,
		Filesystems: []*agentv1.Filesystem{
			{MountPoint: "/", FsType: "ext4", TotalBytes: 100, AvailableBytes: 40},
			{MountPoint: `/mnt/a "b"`, FsType: "xfs", TotalBytes: 100, AvailableBytes: 5},
		},
		Interfaces: []*agentv1.NetworkInterface{{Name: "eth0", RxBytes: 10, RxBytesPerSecond: 100, TxBytesPerSecond: 50}},
	}}
}

func TestValidate(t *testing.T) {
	now := time.Now()
	if err := Validate(sample(now, 5), now); err != nil {
		t.Fatal(err)
	}
	tooMany := sample(now, 5)
	for range 65 {
		tooMany.Host.Interfaces = append(tooMany.Host.Interfaces, &agentv1.NetworkInterface{Name: "x"})
	}
	for name, b := range map[string]*agentv1.MetricsBatch{
		"old":      sample(now.Add(-48*time.Hour), 1),
		"future":   sample(now.Add(time.Hour), 1),
		"negative": sample(now, -1),
		"empty":    {},
		"too many": tooMany,
	} {
		if Validate(b, now) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestPrometheusLinesEscapes(t *testing.T) {
	id := uuid.New()
	at := time.UnixMilli(1700000000123)
	out := string(PrometheusLines(id, sample(at, 12.5)))
	for _, want := range []string{
		`sm_cpu_percent{server_id="` + id.String() + `"} 12.5 1700000000123`,
		`sm_filesystem_avail_bytes{server_id="` + id.String() + `",mount="/mnt/a \"b\"",fstype="xfs"} 5 1700000000123`,
		`sm_network_receive_bytes_total{server_id="` + id.String() + `",interface="eth0"} 10 1700000000123`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestRecordKeepsNewestSnapshot(t *testing.T) {
	st, _ := storetest.Open(t)
	ctx := context.Background()
	id := uuid.New()
	if _, err := st.CreateServer(ctx, db.CreateServerParams{ID: id, Name: "web-1"}); err != nil {
		t.Fatal(err)
	}
	s := NewSink(st.Queries, nil, slog.New(slog.DiscardHandler))
	now := time.Now()
	if err := s.Record(ctx, id, sample(now, 40)); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(ctx, id, sample(now.Add(-time.Minute), 99)); err != nil { // late, buffered batch
		t.Fatal(err)
	}
	rows, err := st.Dashboard(ctx)
	if err != nil || len(rows) != 1 {
		t.Fatalf("%v %v", rows, err)
	}
	r := rows[0]
	if *r.CpuPercent != 40 || *r.DiskMaxUsedPercent != 95 || *r.DiskMaxMount != `/mnt/a "b"` || *r.NetRxBytesPerSecond != 100 {
		t.Fatalf("snapshot %+v", r)
	}
}

func TestVMWriterRetries(t *testing.T) {
	var mu sync.Mutex
	var calls int
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		if r.URL.Path != "/api/v1/import/prometheus" {
			t.Errorf("path %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	w := NewVMWriter(srv.URL, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = w.Run(ctx); close(done) }()
	w.Enqueue([]byte("sm_load1{server_id=\"x\"} 1 1\n"))
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ok := strings.Contains(body, "sm_load1")
		mu.Unlock()
		if ok {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if calls < 2 || !strings.Contains(body, "sm_load1") {
		t.Fatalf("calls %d body %q", calls, body)
	}
}

func TestContainerMetrics(t *testing.T) {
	st, _ := storetest.Open(t)
	ctx := context.Background()
	withDocker, noDocker := uuid.New(), uuid.New()
	for i, id := range []uuid.UUID{withDocker, noDocker} {
		if _, err := st.CreateServer(ctx, db.CreateServerParams{ID: id, Name: []string{"docker-1", "plain-1"}[i]}); err != nil {
			t.Fatal(err)
		}
	}
	s := NewSink(st.Queries, nil, slog.New(slog.DiscardHandler))
	now := time.Now()
	b := sample(now, 10)
	three := uint32(3)
	b.Host.ContainersRunning, b.Host.ContainersMemoryBytes = &three, 4096
	if err := s.Record(ctx, withDocker, b); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(ctx, noDocker, sample(now, 10)); err != nil {
		t.Fatal(err)
	}
	rows, err := st.ListServersWithMetrics(ctx)
	if err != nil || len(rows) != 2 {
		t.Fatalf("%v %v", rows, err)
	}
	if r := rows[0]; r.ContainersRunning == nil || *r.ContainersRunning != 3 || *r.ContainersMemoryBytes != 4096 {
		t.Fatalf("docker host %+v", r)
	}
	if r := rows[1]; r.ContainersRunning != nil || r.ContainersMemoryBytes != nil {
		t.Fatalf("host without docker should have NULL containers: %+v", r)
	}
	out := string(PrometheusLines(withDocker, b))
	if !strings.Contains(out, `sm_containers_running{server_id="`+withDocker.String()+`"} 3 `) {
		t.Errorf("missing container gauge in\n%s", out)
	}
	if strings.Contains(string(PrometheusLines(noDocker, sample(now, 1))), "sm_containers") {
		t.Error("container gauges exported for a host without Docker")
	}
}
