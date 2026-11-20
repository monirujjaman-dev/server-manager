package modules

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
)

type fakeTimedate struct {
	st    agentv1.TimeStatusResult
	calls int
}

func (f *fakeTimedate) Status(context.Context) (*agentv1.TimeStatusResult, error) {
	return &agentv1.TimeStatusResult{Timezone: f.st.Timezone, NtpEnabled: f.st.NtpEnabled}, nil
}

func (f *fakeTimedate) SetTimezone(_ context.Context, tz string) error {
	f.calls++
	f.st.Timezone = tz
	return nil
}

func (f *fakeTimedate) SetNTP(_ context.Context, on bool) error {
	f.calls++
	f.st.NtpEnabled = on
	return nil
}

func TestTimeActions(t *testing.T) {
	td := &fakeTimedate{st: agentv1.TimeStatusResult{Timezone: "UTC"}}
	ctx := context.Background()
	res, err := SetTimezone(ctx, td, &agentv1.TimeSetTimezoneRequest{Timezone: "Asia/Dhaka"})
	if err != nil || res.GetTimezone() != "Asia/Dhaka" {
		t.Fatalf("SetTimezone = %v, %v", res, err)
	}
	if _, err := SetTimezone(ctx, td, &agentv1.TimeSetTimezoneRequest{Timezone: "../../etc/passwd"}); err == nil || td.calls != 1 {
		t.Fatalf("bad zone reached timedated: %v (calls %d)", err, td.calls)
	}
	if res, err := SetNTP(ctx, td, &agentv1.TimeSetNTPRequest{Enabled: true}); err != nil || !res.GetNtpEnabled() {
		t.Fatalf("SetNTP = %v, %v", res, err)
	}
	st := timeStatusFromProps(map[string]dbus.Variant{
		"Timezone": dbus.MakeVariant("Europe/Berlin"), "NTP": dbus.MakeVariant(true), "NTPSynchronized": dbus.MakeVariant(true),
		"CanNTP": dbus.MakeVariant(true), "LocalRTC": dbus.MakeVariant(false), "TimeUSec": dbus.MakeVariant(uint64(1_700_000_000_000_000)),
	})
	if st.GetTimezone() != "Europe/Berlin" || !st.GetNtpSynchronized() || st.GetTime().GetSeconds() != 1_700_000_000 {
		t.Fatalf("status = %v", st)
	}
}

func TestParseSwaps(t *testing.T) {
	in := "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n" +
		"/dev/dm-1                               partition\t2097148\t\t1024\t\t-2\n" +
		"/var/lib/smswap/swapfile                file\t\t1048572\t\t0\t\t-3\n"
	got := parseSwaps([]byte(in))
	if len(got) != 2 || got[0].GetPath() != "/dev/dm-1" || got[0].GetUsedBytes() != 1024<<10 ||
		got[1].GetType() != "file" || got[1].GetSizeBytes() != 1048572<<10 || got[1].GetPriority() != -3 {
		t.Fatalf("parseSwaps = %v", got)
	}
}

func TestSwapHeader(t *testing.T) {
	h := SwapHeader(64<<20, 4096)
	if len(h) != 4096 || !bytes.Equal(h[4096-10:], []byte("SWAPSPACE2")) {
		t.Fatal("signature missing")
	}
	if v := binary.NativeEndian.Uint32(h[1024:]); v != 1 {
		t.Fatalf("version %d", v)
	}
	if last := binary.NativeEndian.Uint32(h[1028:]); last != (64<<20)/4096-1 {
		t.Fatalf("last page %d", last)
	}
	if bytes.Equal(h[1036:1052], make([]byte, 16)) || h[1036+6]>>4 != 4 {
		t.Fatal("no v4 UUID")
	}
}

type fakeUnits struct{ ops []string }

func (f *fakeUnits) Control(_ context.Context, unit string, op agentv1.ServiceOperation) error {
	f.ops = append(f.ops, unit+" "+op.String())
	return nil
}

func (f *fakeUnits) Reload(context.Context) error {
	f.ops = append(f.ops, "reload")
	return nil
}

// fakeSwapProc builds a /proc tree with the given /proc/swaps entries and 100 MB available.
func fakeSwapProc(t *testing.T, swaps string) Host {
	t.Helper()
	root := t.TempDir()
	for name, content := range map[string]string{
		"swaps":             "Filename Type Size Used Priority\n" + swaps,
		"sys/vm/swappiness": "60\n",
		"meminfo":           "MemTotal: 4000000 kB\nMemAvailable: 100000 kB\n",
		"loadavg":           "0 0 0 1/1 1\n",
		"uptime":            "1 1\n",
		"mounts":            "",
	} {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return Host{ProcRoot: root}
}

// applyingUnits behaves like systemd-sysctl: a restart copies the saved value into the
// fake /proc.
type applyingUnits struct {
	fakeUnits
	conf, proc string
}

func (a *applyingUnits) Control(ctx context.Context, unit string, op agentv1.ServiceOperation) error {
	_ = a.fakeUnits.Control(ctx, unit, op)
	b, err := os.ReadFile(a.conf)
	if err != nil {
		return err
	}
	_, v, _ := bytes.Cut(b, []byte("vm.swappiness = "))
	return os.WriteFile(a.proc, v, 0o600)
}

func TestSwappiness(t *testing.T) {
	host := fakeSwapProc(t, "")
	dir := t.TempDir()
	u := &applyingUnits{conf: filepath.Join(dir, swappinessConf), proc: filepath.Join(host.ProcRoot, "sys", "vm", "swappiness")}
	s := &Swapper{Host: host, Units: u, Dir: dir}
	res, err := s.SetSwappiness(context.Background(), &agentv1.SwapSetSwappinessRequest{Swappiness: 10})
	if err != nil || res.GetSwappiness() != 10 {
		t.Fatalf("SetSwappiness = %v, %v", res, err)
	}
	if len(u.ops) != 1 || u.ops[0] != sysctlService+" SERVICE_OPERATION_RESTART" {
		t.Fatalf("ops %v", u.ops)
	}
	if _, err := s.SetSwappiness(context.Background(), &agentv1.SwapSetSwappinessRequest{Swappiness: 101}); err == nil {
		t.Fatal("swappiness 101 accepted")
	}

	// When the value does not take effect (systemd-sysctl skipped, or another file wins),
	// the operator is told it is only saved.
	s.Units = &fakeUnits{}
	_, err = s.SetSwappiness(context.Background(), &agentv1.SwapSetSwappinessRequest{Swappiness: 30})
	if err == nil || !strings.Contains(err.Error(), "saved and applies at boot") || !strings.Contains(err.Error(), "running value is 10") {
		t.Fatalf("unapplied swappiness: %v", err)
	}
	if b, _ := os.ReadFile(u.conf); !bytes.Contains(b, []byte("vm.swappiness = 30\n")) { //nolint:gosec // test file
		t.Fatalf("not saved: %q", b)
	}
}
