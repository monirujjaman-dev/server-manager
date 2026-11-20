package ctl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"text/tabwriter"

	operatorv1 "github.com/monirujjaman-dev/server-manager/gen/sm/operator/v1"
)

// Bulk limits.
const (
	DefaultParallel = 5
	MaxParallel     = 20
	// MaxServerList caps an explicit comma-separated server list.
	MaxServerList = 200
)

// Server names as accepted by enrollment; a comma can never be part of one.
var serverNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)

// Selector chooses the servers an action runs on.
type Selector struct {
	Names          []string // explicit servers (names or IDs), in order
	Group          string   // every visible server in this group
	All            bool     // every visible server
	IncludeOffline bool     // also queue jobs for servers that are not online
}

// Bulk reports whether the selector can match more than one server.
func (s Selector) Bulk() bool { return s.All || s.Group != "" || len(s.Names) > 1 }

// ParseServerList splits "web-1,web-2" into names, rejecting empty entries and
// duplicates. A single name or ID is returned as is.
func ParseServerList(arg string) ([]string, error) {
	parts := strings.Split(arg, ",")
	if len(parts) == 1 {
		if arg == "" {
			return nil, errors.New("empty server name")
		}
		return parts, nil
	}
	if len(parts) > MaxServerList {
		return nil, fmt.Errorf("at most %d servers in a list; use --group", MaxServerList)
	}
	seen := map[string]bool{}
	for _, p := range parts {
		if !serverNameRe.MatchString(p) {
			return nil, fmt.Errorf("invalid server name %q in list", p)
		}
		if seen[p] {
			return nil, fmt.Errorf("server %q listed twice", p)
		}
		seen[p] = true
	}
	return parts, nil
}

// Target is one server a bulk action runs on.
type Target struct {
	Name   string
	Status string
}

// Resolve picks the targets from the servers the caller can see. Servers that are not
// online are returned separately (as skipped) unless IncludeOffline is set; revoked
// servers are always skipped. An explicit name that is not visible is an error, so a
// typo never silently shrinks the target list.
func (s Selector) Resolve(visible []*operatorv1.Server) (run, skipped []Target, err error) {
	var picked []*operatorv1.Server
	switch {
	case s.All:
		picked = visible
	case s.Group != "":
		for _, v := range visible {
			if v.GetGroup() == s.Group {
				picked = append(picked, v)
			}
		}
		if len(picked) == 0 {
			return nil, nil, fmt.Errorf("no servers you can see in group %q", s.Group)
		}
	default:
		byKey := map[string]*operatorv1.Server{}
		for _, v := range visible {
			byKey[v.GetName()], byKey[v.GetId()] = v, v
		}
		for _, n := range s.Names {
			v, ok := byKey[n]
			if !ok {
				return nil, nil, fmt.Errorf("server %q not found", n)
			}
			picked = append(picked, v)
		}
	}
	for _, v := range picked {
		t := Target{Name: v.GetName(), Status: v.GetStatus()}
		if v.GetStatus() == "revoked" || (v.GetStatus() != "online" && !s.IncludeOffline) {
			skipped = append(skipped, t)
			continue
		}
		run = append(run, t)
	}
	if len(run) == 0 {
		return nil, skipped, errors.New("none of the selected servers is online (use --include-offline to queue jobs anyway)")
	}
	return run, skipped, nil
}

// BulkResult is the outcome on one server.
type BulkResult struct {
	Server string
	Job    *operatorv1.Job // nil if the job was never created
	Err    error
	Output []byte // what the printer wrote for a successful job
}

// RunBulk calls run for each target, at most parallel at a time, and calls done
// (serialised) as each finishes. The first target runs alone so that a step-up prompt,
// if the action needs one, is answered once before the others start. When ctx is
// cancelled no new targets are started; running ones finish or fail with ctx.
func RunBulk(ctx context.Context, targets []Target, parallel int, run func(ctx context.Context, server string) BulkResult, done func(BulkResult)) []BulkResult {
	parallel = min(max(parallel, 1), MaxParallel)
	results := make([]BulkResult, len(targets))
	var mu sync.Mutex
	finish := func(i int, r BulkResult) {
		r.Server = targets[i].Name
		mu.Lock()
		defer mu.Unlock()
		results[i] = r
		if done != nil {
			done(r)
		}
	}
	if len(targets) == 0 {
		return results
	}
	finish(0, run(ctx, targets[0].Name))

	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i := 1; i < len(targets); i++ {
		select {
		case <-ctx.Done():
			finish(i, BulkResult{Err: fmt.Errorf("not started: %w", ctx.Err())})
			continue
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			finish(i, run(ctx, targets[i].Name))
		}(i)
	}
	wg.Wait()
	return results
}

// PrintBulkSummary writes one line per server and returns an error if any failed.
func PrintBulkSummary(w io.Writer, results []BulkResult, skipped []Target) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SERVER\tRESULT")
	var failed int
	for _, r := range results {
		if r.Err != nil {
			failed++
			_, _ = fmt.Fprintf(tw, "%s\tfailed: %s\n", r.Server, oneLine(r.Err.Error()))
			continue
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\n", r.Server, r.Job.GetStatus())
	}
	for _, s := range skipped {
		_, _ = fmt.Fprintf(tw, "%s\tskipped: %s\n", s.Name, s.Status)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "%d servers: %d succeeded, %d failed, %d skipped\n",
		len(results)+len(skipped), len(results)-failed, failed, len(skipped))
	if failed > 0 {
		return fmt.Errorf("%d of %d servers failed", failed, len(results))
	}
	return nil
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
