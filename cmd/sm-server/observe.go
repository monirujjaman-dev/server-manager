package main

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/internal/server"
	"github.com/monirujjaman-dev/server-manager/internal/server/store/db"
)

// staleAfter marks metrics older than this as stale in the dashboard.
const staleAfter = 2 * time.Minute

func dashboardCmd(loadConfig func() (server.Config, error)) *cobra.Command {
	var watch time.Duration
	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Show all servers with their latest CPU, memory, disk and network",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			st, _, err := openStore(ctx, loadConfig)
			if err != nil {
				return err
			}
			defer st.Close()
			for {
				rows, err := st.Dashboard(ctx)
				if err != nil {
					return err
				}
				if watch > 0 {
					_, _ = fmt.Fprint(cmd.OutOrStdout(), "\033[H\033[2J")
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Server Manager — %s (every %s, Ctrl-C to quit)\n\n", time.Now().Format(time.TimeOnly), watch)
				}
				if err := printDashboard(cmd.OutOrStdout(), rows, time.Now()); err != nil {
					return err
				}
				if watch <= 0 {
					return nil
				}
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(watch):
				}
			}
		},
	}
	cmd.Flags().DurationVarP(&watch, "watch", "w", 0, "refresh at this interval, e.g. 5s")
	return cmd
}

func printDashboard(w io.Writer, rows []db.DashboardRow, now time.Time) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tSTATUS\tCPU\tLOAD\tMEMORY\tDISK (fullest)\tNET IN/OUT\tUPTIME\tUPDATED")
	var online, alerts int
	for _, r := range rows {
		if r.Status == "online" {
			online++
		}
		if r.CollectedAt == nil {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t-\t-\t-\t-\t-\t-\tno data\n", r.Name, r.Status)
			continue
		}
		age := now.Sub(*r.CollectedAt)
		updated := age.Round(time.Second).String() + " ago"
		if age > staleAfter {
			updated += " (stale)"
		}
		mem := "-"
		if *r.MemoryTotalBytes > 0 {
			used := *r.MemoryTotalBytes - *r.MemoryAvailableBytes
			mem = fmt.Sprintf("%.0f%% of %s", float64(used)/float64(*r.MemoryTotalBytes)*100, bytesHuman(uint64(*r.MemoryTotalBytes))) //nolint:gosec // non-negative
		}
		disk := fmt.Sprintf("%.0f%% %s", *r.DiskMaxUsedPercent, *r.DiskMaxMount)
		flag := ""
		if *r.DiskMaxUsedPercent >= 90 || *r.CpuPercent >= 90 {
			flag = " !"
			alerts++
		}
		uptime := (time.Duration(*r.UptimeSeconds) * time.Second).Truncate(time.Minute).String()
		_, _ = fmt.Fprintf(tw, "%s%s\t%s\t%.0f%%\t%.2f\t%s\t%s\t%s/s / %s/s\t%s\t%s\n", r.Name, flag, r.Status, *r.CpuPercent, *r.Load1,
			mem, disk, bytesHuman(uint64(*r.NetRxBytesPerSecond)), bytesHuman(uint64(*r.NetTxBytesPerSecond)), uptime, updated)
	}
	_, _ = fmt.Fprintf(tw, "\n%d servers, %d online", len(rows), online)
	if alerts > 0 {
		_, _ = fmt.Fprintf(tw, ", %d at or above 90%% CPU or disk (!)", alerts)
	}
	_, _ = fmt.Fprintln(tw)
	return tw.Flush()
}

var priorityNames = []string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}

func parsePriority(s string) (uint32, error) {
	if n, err := strconv.ParseUint(s, 10, 32); err == nil && n <= 7 {
		return uint32(n), nil
	}
	for i, name := range priorityNames {
		if strings.EqualFold(s, name) || (name == "err" && strings.EqualFold(s, "error")) || (name == "warning" && strings.EqualFold(s, "warn")) {
			return uint32(i), nil //nolint:gosec // 0-7
		}
	}
	return 0, fmt.Errorf("unknown priority %q (use 0-7 or emerg, alert, crit, err, warning, notice, info, debug)", s)
}

func sinceSeconds(d time.Duration) (uint32, error) {
	if d < 0 || d > 30*24*time.Hour {
		return 0, errors.New("--since must be between 0 and 720h")
	}
	return uint32(d.Seconds()), nil
}

func observeCommands(loadConfig func() (server.Config, error)) []*cobra.Command {
	r := &actionRunner{loadConfig: loadConfig, timeout: 2 * time.Minute}

	var unit, grep, prio string
	var since time.Duration
	var lines uint32
	var follow bool
	logs := &cobra.Command{
		Use:   "logs <server>",
		Short: "Show journal entries (optionally for one unit), or follow new ones",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			secs, err := sinceSeconds(since)
			if err != nil {
				return err
			}
			req := &agentv1.LogQueryRequest{Unit: unit, SinceSeconds: secs, Limit: lines, Grep: grep}
			if unit != "" && !strings.Contains(unit, ".") {
				req.Unit = unit + ".service"
			}
			if prio != "" {
				p, err := parsePriority(prio)
				if err != nil {
					return err
				}
				req.MaxPriority = &p
			}
			for {
				var cursor string
				if err := r.run(cmd, args[0], &agentv1.ActionRequest{Action: &agentv1.ActionRequest_LogQuery{LogQuery: req}}, func(w io.Writer, res *agentv1.ActionResult) error {
					cursor = res.GetLogQuery().GetCursor()
					return printLogs(w, res.GetLogQuery().GetEntries())
				}); err != nil {
					return err
				}
				if !follow {
					return nil
				}
				if cursor != "" {
					req.AfterCursor = cursor
				}
				select {
				case <-cmd.Context().Done():
					return nil
				case <-time.After(2 * time.Second):
				}
			}
		},
	}
	logs.Flags().StringVarP(&unit, "unit", "u", "", "systemd unit, e.g. nginx (\".service\" is added)")
	logs.Flags().DurationVar(&since, "since", time.Hour, "how far back to look")
	logs.Flags().Uint32VarP(&lines, "lines", "n", 100, "maximum entries (max 500)")
	logs.Flags().StringVar(&grep, "grep", "", "only entries containing this text (case-insensitive)")
	logs.Flags().StringVarP(&prio, "priority", "p", "", "this priority or more severe, e.g. err or warning")
	logs.Flags().BoolVarP(&follow, "follow", "f", false, "keep printing new entries (polls every 2 s)")

	var authSince time.Duration
	var authLimit uint32
	var failedOnly bool
	logins := &cobra.Command{
		Use:   "logins <server>",
		Short: "Show SSH logins and failures, and sudo use",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			secs, err := sinceSeconds(authSince)
			if err != nil {
				return err
			}
			req := &agentv1.AuthLogRequest{SinceSeconds: secs, Limit: authLimit}
			return r.run(cmd, args[0], &agentv1.ActionRequest{Action: &agentv1.ActionRequest_AuthLog{AuthLog: req}}, func(w io.Writer, res *agentv1.ActionResult) error {
				return printAuth(w, res.GetAuthLog().GetEvents(), failedOnly)
			})
		},
	}
	logins.Flags().DurationVar(&authSince, "since", 24*time.Hour, "how far back to look")
	logins.Flags().Uint32VarP(&authLimit, "lines", "n", 100, "maximum events (max 500)")
	logins.Flags().BoolVar(&failedOnly, "failed", false, "only failed logins and denied sudo")

	return []*cobra.Command{dashboardCmd(loadConfig), logs, logins}
}

func printLogs(w io.Writer, entries []*agentv1.LogEntry) error {
	for _, e := range entries {
		src := e.GetIdentifier()
		if src == "" {
			src = e.GetUnit()
		}
		if e.GetPid() != 0 {
			src += "[" + strconv.Itoa(int(e.GetPid())) + "]"
		}
		prio := ""
		if p := e.GetPriority(); p <= 3 {
			prio = strings.ToUpper(priorityNames[p]) + " "
		}
		if _, err := fmt.Fprintf(w, "%s %s: %s%s\n", e.GetTime().AsTime().Local().Format("Jan 02 15:04:05"), src, prio, e.GetMessage()); err != nil {
			return err
		}
	}
	return nil
}

func printAuth(w io.Writer, events []*agentv1.AuthEvent, failedOnly bool) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "TIME\tEVENT\tUSER\tFROM\tDETAILS")
	shown := 0
	for _, e := range events {
		var kind, details string
		failed := false
		switch e.GetKind() {
		case agentv1.AuthEventKind_AUTH_EVENT_KIND_SSH_ACCEPTED:
			kind, details = "ssh login", e.GetMethod()
		case agentv1.AuthEventKind_AUTH_EVENT_KIND_SSH_FAILED:
			kind, details, failed = "ssh FAILED", e.GetMethod(), true
		case agentv1.AuthEventKind_AUTH_EVENT_KIND_SSH_INVALID_USER:
			kind, details, failed = "ssh INVALID USER", e.GetMethod(), true
		case agentv1.AuthEventKind_AUTH_EVENT_KIND_SUDO:
			kind, details = "sudo", "as "+e.GetTargetUser()+": "+e.GetCommand()
		case agentv1.AuthEventKind_AUTH_EVENT_KIND_SUDO_FAILED:
			kind, details, failed = "sudo DENIED", "as "+e.GetTargetUser()+": "+e.GetCommand(), true
		default:
			continue
		}
		if failedOnly && !failed {
			continue
		}
		shown++
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", e.GetTime().AsTime().Local().Format("Jan 02 15:04:05"), kind, e.GetUser(), e.GetSourceIp(), details)
	}
	_, _ = fmt.Fprintf(tw, "\n%d events\n", shown)
	return tw.Flush()
}
