package metrics

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
)

// VMWriter sends samples to VictoriaMetrics' Prometheus text import endpoint
// (/api/v1/import/prometheus) in the background, batching and retrying. If
// VictoriaMetrics is down for long, the oldest queued samples are dropped so the control
// plane's memory stays bounded.
type VMWriter struct {
	url    string
	client *http.Client
	log    *slog.Logger
	queue  chan []byte
}

// NewVMWriter targets baseURL, e.g. http://127.0.0.1:8428.
func NewVMWriter(baseURL string, log *slog.Logger) *VMWriter {
	return &VMWriter{
		url:    strings.TrimRight(baseURL, "/") + "/api/v1/import/prometheus",
		client: &http.Client{Timeout: 10 * time.Second},
		log:    log,
		queue:  make(chan []byte, 10000),
	}
}

// Enqueue adds lines without blocking; when the queue is full the oldest entry is dropped.
func (w *VMWriter) Enqueue(lines []byte) {
	for {
		select {
		case w.queue <- lines:
			return
		default:
			select {
			case <-w.queue:
			default:
			}
		}
	}
}

// Run flushes the queue until ctx ends.
func (w *VMWriter) Run(ctx context.Context) error {
	var buf bytes.Buffer
	flush := time.NewTicker(time.Second)
	defer flush.Stop()
	backoff := time.Second
	for {
		select {
		case <-ctx.Done():
			return nil
		case lines := <-w.queue:
			buf.Write(lines)
			if buf.Len() < 1<<20 {
				continue
			}
		case <-flush.C:
		}
		if buf.Len() == 0 {
			continue
		}
		if err := w.post(ctx, buf.Bytes()); err != nil {
			w.log.Warn("write to VictoriaMetrics failed; retrying", "err", err, "retry_in", backoff)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, time.Minute)
			if buf.Len() > 8<<20 { // give up on very old data rather than grow without bound
				buf.Reset()
			}
			continue
		}
		backoff = time.Second
		buf.Reset()
	}
}

func (w *VMWriter) post(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain")
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// PrometheusLines renders a batch in the Prometheus text format with millisecond
// timestamps, as accepted by VictoriaMetrics.
func PrometheusLines(serverID uuid.UUID, b *agentv1.MetricsBatch) []byte {
	var out bytes.Buffer
	ts := strconv.FormatInt(b.GetCollectedAt().AsTime().UnixMilli(), 10)
	base := `server_id="` + serverID.String() + `"`
	line := func(name, labels string, v float64) {
		out.WriteString(name)
		out.WriteString("{")
		out.WriteString(base)
		if labels != "" {
			out.WriteString(",")
			out.WriteString(labels)
		}
		out.WriteString("} ")
		out.WriteString(strconv.FormatFloat(v, 'g', -1, 64))
		out.WriteString(" ")
		out.WriteString(ts)
		out.WriteString("\n")
	}
	h := b.GetHost()
	line("sm_cpu_percent", "", h.GetCpuPercent())
	line("sm_cpu_count", "", float64(h.GetCpuCount()))
	line("sm_load1", "", h.GetLoad1())
	line("sm_load5", "", h.GetLoad5())
	line("sm_load15", "", h.GetLoad15())
	line("sm_memory_total_bytes", "", float64(h.GetMemoryTotalBytes()))
	line("sm_memory_available_bytes", "", float64(h.GetMemoryAvailableBytes()))
	line("sm_swap_total_bytes", "", float64(h.GetSwapTotalBytes()))
	line("sm_swap_free_bytes", "", float64(h.GetSwapFreeBytes()))
	line("sm_uptime_seconds", "", float64(h.GetUptimeSeconds()))
	for _, f := range h.GetFilesystems() {
		l := label("mount", f.GetMountPoint()) + "," + label("fstype", f.GetFsType())
		line("sm_filesystem_size_bytes", l, float64(f.GetTotalBytes()))
		line("sm_filesystem_avail_bytes", l, float64(f.GetAvailableBytes()))
	}
	for _, n := range h.GetInterfaces() {
		l := label("interface", n.GetName())
		line("sm_network_receive_bytes_total", l, float64(n.GetRxBytes()))
		line("sm_network_transmit_bytes_total", l, float64(n.GetTxBytes()))
		line("sm_network_receive_errors_total", l, float64(n.GetRxErrors()))
		line("sm_network_transmit_errors_total", l, float64(n.GetTxErrors()))
	}
	return out.Bytes()
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func label(k, v string) string { return k + `="` + labelEscaper.Replace(v) + `"` }
