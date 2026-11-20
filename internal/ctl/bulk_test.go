package ctl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	operatorv1 "github.com/monirujjaman-dev/server-manager/gen/sm/operator/v1"
)

func TestParseServerList(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    []string
		wantErr string
	}{
		{in: "web-1", want: []string{"web-1"}},
		{in: "0b9f2c1e-uuid-or-anything", want: []string{"0b9f2c1e-uuid-or-anything"}},
		{in: "web-1,web-2", want: []string{"web-1", "web-2"}},
		{in: "", wantErr: "empty"},
		{in: "web-1,", wantErr: "invalid server name"},
		{in: "web-1,,web-2", wantErr: "invalid server name"},
		{in: "web-1,Web 2", wantErr: "invalid server name"},
		{in: "web-1,web-1", wantErr: "twice"},
		{in: strings.Repeat("a,", MaxServerList) + "a", wantErr: "at most"},
	} {
		got, err := ParseServerList(tc.in)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("ParseServerList(%q) error = %v, want %q", tc.in, err, tc.wantErr)
			}
			continue
		}
		if err != nil || strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("ParseServerList(%q) = %v, %v; want %v", tc.in, got, err, tc.want)
		}
	}
}

func fleetFixture() []*operatorv1.Server {
	return []*operatorv1.Server{
		{Id: "id-1", Name: "web-1", Group: "staging", Status: "online"},
		{Id: "id-2", Name: "web-2", Group: "staging", Status: "offline"},
		{Id: "id-3", Name: "db-1", Group: "prod", Status: "online"},
		{Id: "id-4", Name: "old-1", Group: "staging", Status: "revoked"},
		{Id: "id-5", Name: "solo", Status: "online"},
	}
}

func names(ts []Target) string {
	var out []string
	for _, t := range ts {
		out = append(out, t.Name)
	}
	return strings.Join(out, ",")
}

func TestSelectorResolve(t *testing.T) {
	for _, tc := range []struct {
		name          string
		sel           Selector
		run, skipped  string
		wantErrSubstr string
	}{
		{name: "group skips offline and revoked", sel: Selector{Group: "staging"}, run: "web-1", skipped: "web-2,old-1"},
		{name: "group with offline", sel: Selector{Group: "staging", IncludeOffline: true}, run: "web-1,web-2", skipped: "old-1"},
		{name: "all", sel: Selector{All: true}, run: "web-1,db-1,solo", skipped: "web-2,old-1"},
		{name: "list keeps order, accepts IDs", sel: Selector{Names: []string{"solo", "id-1"}}, run: "solo,web-1"},
		{name: "unknown group", sel: Selector{Group: "nope"}, wantErrSubstr: `no servers you can see in group "nope"`},
		{name: "invisible name is not silently dropped", sel: Selector{Names: []string{"web-1", "hidden"}}, wantErrSubstr: `"hidden" not found`},
		{name: "nothing online", sel: Selector{Names: []string{"web-2", "old-1"}}, wantErrSubstr: "none of the selected"},
		{name: "revoked even with include-offline", sel: Selector{Names: []string{"old-1"}, IncludeOffline: true}, wantErrSubstr: "none of the selected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run, skipped, err := tc.sel.Resolve(fleetFixture())
			if tc.wantErrSubstr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrSubstr) {
					t.Fatalf("error = %v, want %q", err, tc.wantErrSubstr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if names(run) != tc.run || names(skipped) != tc.skipped {
				t.Fatalf("run=%q skipped=%q, want run=%q skipped=%q", names(run), names(skipped), tc.run, tc.skipped)
			}
		})
	}
}

func targets(n int) []Target {
	ts := make([]Target, n)
	for i := range ts {
		ts[i] = Target{Name: fmt.Sprintf("srv-%02d", i), Status: "online"}
	}
	return ts
}

func TestRunBulkLimitsConcurrencyAndRunsFirstAlone(t *testing.T) {
	const parallel = 5
	var running, peak atomic.Int32
	var firstDone atomic.Bool
	var mu sync.Mutex
	var order []string
	results := RunBulk(context.Background(), targets(20), parallel, func(_ context.Context, server string) BulkResult {
		n := running.Add(1)
		defer running.Add(-1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		if server != "srv-00" && !firstDone.Load() {
			t.Errorf("%s started before the first server finished", server)
		}
		time.Sleep(5 * time.Millisecond)
		if server == "srv-00" {
			firstDone.Store(true)
		}
		if server == "srv-07" {
			return BulkResult{Err: errors.New("boom")}
		}
		return BulkResult{Job: &operatorv1.Job{Status: "succeeded"}}
	}, func(r BulkResult) {
		mu.Lock() // done is documented as serialised; the race detector checks it
		order = append(order, r.Server)
		mu.Unlock()
	})
	if p := peak.Load(); p > parallel || p < 2 {
		t.Fatalf("peak concurrency %d, want 2..%d", p, parallel)
	}
	if len(results) != 20 || len(order) != 20 || order[0] != "srv-00" {
		t.Fatalf("results=%d done calls=%d first=%v", len(results), len(order), order[:1])
	}
	for i, r := range results {
		if r.Server != fmt.Sprintf("srv-%02d", i) {
			t.Fatalf("results[%d] is %s; results must keep target order", i, r.Server)
		}
	}
	var buf bytes.Buffer
	err := PrintBulkSummary(&buf, results, []Target{{Name: "off-1", Status: "offline"}})
	if err == nil || err.Error() != "1 of 20 servers failed" {
		t.Fatalf("summary error = %v", err)
	}
	for _, want := range []string{"srv-07  failed: boom", "off-1   skipped: offline", "21 servers: 19 succeeded, 1 failed, 1 skipped"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("summary missing %q:\n%s", want, buf.String())
		}
	}
}

func TestRunBulkStopsStartingAfterCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var started atomic.Int32
	results := RunBulk(ctx, targets(10), 1, func(ctx context.Context, _ string) BulkResult {
		if started.Add(1) == 2 {
			cancel()
		}
		return BulkResult{Job: &operatorv1.Job{Status: "succeeded"}}
	}, nil)
	if n := started.Load(); n > 3 {
		t.Fatalf("%d servers started after cancel, want at most 3", n)
	}
	var notStarted int
	for _, r := range results {
		if r.Err != nil && errors.Is(r.Err, context.Canceled) {
			notStarted++
		}
	}
	if notStarted < 7 {
		t.Fatalf("%d results marked not started, want >= 7", notStarted)
	}
}
