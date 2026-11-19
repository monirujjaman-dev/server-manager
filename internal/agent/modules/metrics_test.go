//go:build linux

package modules

import (
	"testing"
)

func TestParseCPUTimes(t *testing.T) {
	c := parseCPUTimes([]byte("cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 2 3 4\n"))
	if c.total != 1000 || c.idle != 850 {
		t.Fatalf("%+v", c)
	}
	if (parseCPUTimes([]byte("garbage")) != cpuTimes{}) {
		t.Fatal("garbage parsed")
	}
}

func TestParseNetDev(t *testing.T) {
	in := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  1000      10    0    0    0     0          0         0     1000      10    0    0    0     0       0          0
  eth0: 5000      50    2    0    0     0          0         0     7000      70    3    0    0     0       0          0
`
	n := parseNetDev([]byte(in))
	if _, ok := n["lo"]; ok || len(n) != 1 {
		t.Fatalf("%v", n)
	}
	if e := n["eth0"]; e.rx != 5000 || e.tx != 7000 || e.rxErr != 2 || e.txErr != 3 {
		t.Fatalf("%+v", e)
	}
}

func TestCollectorReal(t *testing.T) {
	c := NewCollector(DefaultHost())
	m, err := c.Collect()
	if err != nil {
		t.Fatal(err)
	}
	if m.GetMemoryTotalBytes() == 0 || m.GetCpuCount() == 0 || m.GetCpuPercent() < 0 || m.GetCpuPercent() > 100 {
		t.Fatalf("%+v", m)
	}
}
