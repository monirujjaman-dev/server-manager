package modules

import (
	"bufio"
	"bytes"
	"os"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
)

// Collector produces HostMetrics. CPU usage and network rates are computed from the
// difference to the previous collection, so the first call primes the counters.
type Collector struct {
	host    Host
	prevAt  time.Time
	prevCPU cpuTimes
	prevNet map[string]netCounters
}

type cpuTimes struct{ total, idle uint64 }

type netCounters struct{ rx, tx, rxErr, txErr uint64 }

// NewCollector returns a primed collector.
func NewCollector(h Host) *Collector {
	c := &Collector{host: h}
	c.prevAt = time.Now()
	c.prevCPU, _ = h.cpuTimes()
	c.prevNet, _ = h.netCounters()
	return c
}

// Collect gathers one sample.
func (c *Collector) Collect() (*agentv1.HostMetrics, error) {
	now := time.Now()
	info, err := c.host.SystemInfo()
	if err != nil {
		return nil, err
	}
	m := &agentv1.HostMetrics{
		CpuCount: info.GetCpuCount(), Load1: info.GetLoad1(), Load5: info.GetLoad5(), Load15: info.GetLoad15(),
		MemoryTotalBytes: info.GetMemoryTotalBytes(), MemoryAvailableBytes: info.GetMemoryAvailableBytes(),
		SwapTotalBytes: info.GetSwapTotalBytes(), SwapFreeBytes: info.GetSwapFreeBytes(),
		UptimeSeconds: info.GetUptimeSeconds(), Filesystems: info.GetFilesystems(),
	}
	if cpu, err := c.host.cpuTimes(); err == nil {
		if dt := cpu.total - c.prevCPU.total; cpu.total > c.prevCPU.total && dt > 0 {
			busy := dt - min(cpu.idle-c.prevCPU.idle, dt)
			m.CpuPercent = float64(busy) / float64(dt) * 100
		}
		c.prevCPU = cpu
	}
	if nets, err := c.host.netCounters(); err == nil {
		secs := now.Sub(c.prevAt).Seconds()
		for name, n := range nets {
			iface := &agentv1.NetworkInterface{Name: name, RxBytes: n.rx, TxBytes: n.tx, RxErrors: n.rxErr, TxErrors: n.txErr}
			if p, ok := c.prevNet[name]; ok && secs > 0 && n.rx >= p.rx && n.tx >= p.tx {
				iface.RxBytesPerSecond = float64(n.rx-p.rx) / secs
				iface.TxBytesPerSecond = float64(n.tx-p.tx) / secs
			}
			m.Interfaces = append(m.Interfaces, iface)
		}
		c.prevNet = nets
	}
	c.prevAt = now
	return m, nil
}

// cpuTimes reads the aggregate "cpu" line of /proc/stat.
func (h Host) cpuTimes() (cpuTimes, error) {
	b, err := os.ReadFile(h.proc("stat"))
	if err != nil {
		return cpuTimes{}, err
	}
	return parseCPUTimes(b), nil
}

func parseCPUTimes(b []byte) cpuTimes {
	line, _, _ := bytes.Cut(b, []byte("\n"))
	f := strings.Fields(string(line))
	if len(f) < 5 || f[0] != "cpu" {
		return cpuTimes{}
	}
	var t cpuTimes
	// user nice system idle iowait irq softirq steal (guest time is already in user).
	for i := 1; i < len(f) && i <= 8; i++ {
		n, _ := strconv.ParseUint(f[i], 10, 64)
		t.total += n
		if i == 4 || i == 5 {
			t.idle += n
		}
	}
	return t
}

// netCounters reads /proc/net/dev, skipping the loopback interface.
func (h Host) netCounters() (map[string]netCounters, error) {
	b, err := os.ReadFile(h.proc("net", "dev"))
	if err != nil {
		return nil, err
	}
	return parseNetDev(b), nil
}

func parseNetDev(b []byte) map[string]netCounters {
	out := make(map[string]netCounters)
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		f := strings.Fields(rest)
		if name == "lo" || len(f) < 16 {
			continue
		}
		u := func(i int) uint64 { n, _ := strconv.ParseUint(f[i], 10, 64); return n }
		out[name] = netCounters{rx: u(0), rxErr: u(2), tx: u(8), txErr: u(10)}
	}
	return out
}
