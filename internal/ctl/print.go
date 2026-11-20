package ctl

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	operatorv1 "github.com/monirujjaman-dev/server-manager/gen/sm/operator/v1"
)

// StaleAfter marks metrics older than this as stale.
const StaleAfter = 2 * time.Minute

// BytesHuman formats a byte count with binary units.
func BytesHuman(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// PrintServers renders the fleet dashboard.
func PrintServers(w io.Writer, servers []*operatorv1.Server, now time.Time) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tGROUP\tSTATUS\tCPU\tLOAD\tMEMORY\tDISK (fullest)\tNET IN/OUT\tCONTAINERS\tUPTIME\tUPDATED")
	var online, alerts int
	for _, s := range servers {
		if s.GetStatus() == "online" {
			online++
		}
		m := s.GetMetrics()
		if m == nil {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t-\t-\t-\t-\t-\t-\t-\tno data\n", s.GetName(), s.GetGroup(), s.GetStatus())
			continue
		}
		age := now.Sub(m.GetCollectedAt().AsTime())
		updated := age.Round(time.Second).String() + " ago"
		if age > StaleAfter {
			updated += " (stale)"
		}
		mem := "-"
		if m.GetMemoryTotalBytes() > 0 {
			used := m.GetMemoryTotalBytes() - min(m.GetMemoryAvailableBytes(), m.GetMemoryTotalBytes())
			mem = fmt.Sprintf("%.0f%% of %s", float64(used)/float64(m.GetMemoryTotalBytes())*100, BytesHuman(m.GetMemoryTotalBytes()))
		}
		flag := ""
		if m.GetDiskMaxUsedPercent() >= 90 || m.GetCpuPercent() >= 90 {
			flag = " !"
			alerts++
		}
		uptime := (time.Duration(m.GetUptimeSeconds()) * time.Second).Truncate(time.Minute).String() //nolint:gosec // uptime fits
		containers := "-"
		if m.ContainersRunning != nil {
			containers = fmt.Sprintf("%d (%s)", m.GetContainersRunning(), BytesHuman(m.GetContainersMemoryBytes()))
		}
		_, _ = fmt.Fprintf(tw, "%s%s\t%s\t%s\t%.0f%%\t%.2f\t%s\t%.0f%% %s\t%s/s / %s/s\t%s\t%s\t%s\n", s.GetName(), flag, s.GetGroup(), s.GetStatus(),
			m.GetCpuPercent(), m.GetLoad1(), mem, m.GetDiskMaxUsedPercent(), m.GetDiskMaxMount(),
			BytesHuman(uint64(m.GetNetRxBytesPerSecond())), BytesHuman(uint64(m.GetNetTxBytesPerSecond())), containers, uptime, updated)
	}
	_, _ = fmt.Fprintf(tw, "\n%d servers, %d online", len(servers), online)
	if alerts > 0 {
		_, _ = fmt.Fprintf(tw, ", %d at or above 90%% CPU or disk (!)", alerts)
	}
	_, _ = fmt.Fprintln(tw)
	return tw.Flush()
}

// PrintSystemInfo renders system.info.
func PrintSystemInfo(w io.Writer, res *agentv1.ActionResult) error {
	s := res.GetSystemInfo()
	up := time.Duration(s.GetUptimeSeconds()) * time.Second //nolint:gosec // uptime fits
	_, _ = fmt.Fprintf(w, "host     %s\nuptime   %s\nload     %.2f %.2f %.2f (%d CPUs)\n", s.GetHostname(), up, s.GetLoad1(), s.GetLoad5(), s.GetLoad15(), s.GetCpuCount())
	used := s.GetMemoryTotalBytes() - s.GetMemoryAvailableBytes()
	_, _ = fmt.Fprintf(w, "memory   %s used of %s\nswap     %s used of %s\n\n", BytesHuman(used), BytesHuman(s.GetMemoryTotalBytes()),
		BytesHuman(s.GetSwapTotalBytes()-s.GetSwapFreeBytes()), BytesHuman(s.GetSwapTotalBytes()))
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "MOUNT\tTYPE\tSIZE\tUSED\tUSE%\tDEVICE")
	for _, f := range s.GetFilesystems() {
		used := f.GetTotalBytes() - f.GetAvailableBytes()
		pct := 0.0
		if f.GetTotalBytes() > 0 {
			pct = float64(used) / float64(f.GetTotalBytes()) * 100
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%.0f%%\t%s\n", f.GetMountPoint(), f.GetFsType(), BytesHuman(f.GetTotalBytes()), BytesHuman(used), pct, f.GetDevice())
	}
	return tw.Flush()
}

// PrintServices renders services.list.
func PrintServices(w io.Writer, res *agentv1.ActionResult) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "UNIT\tACTIVE\tSUB\tENABLED\tDESCRIPTION")
	for _, u := range res.GetServiceList().GetUnits() {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", u.GetName(), u.GetActiveState(), u.GetSubState(), u.GetUnitFileState(), u.GetDescription())
	}
	return tw.Flush()
}

// PrintServiceUnit renders the result of services.control.
func PrintServiceUnit(w io.Writer, res *agentv1.ActionResult) error {
	u := res.GetServiceControl().GetUnit()
	_, err := fmt.Fprintf(w, "%s: %s (%s), %s\n", u.GetName(), u.GetActiveState(), u.GetSubState(), u.GetUnitFileState())
	return err
}

// PrintProcesses renders processes.list.
func PrintProcesses(w io.Writer, res *agentv1.ActionResult) error {
	pl := res.GetProcessList()
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "PID\tUSER\tCPU%\tRSS\tSTATE\tSTART\tCOMMAND")
	for _, p := range pl.GetProcesses() {
		cmdline := p.GetCommandLine()
		if cmdline == "" {
			cmdline = "[" + p.GetName() + "]"
		}
		if len(cmdline) > 80 {
			cmdline = cmdline[:77] + "..."
		}
		_, _ = fmt.Fprintf(tw, "%d\t%s\t%.1f\t%s\t%s\t%d\t%s\n", p.GetPid(), p.GetUser(), p.GetCpuPercent(), BytesHuman(p.GetRssBytes()), p.GetState(), p.GetStartTicks(), cmdline)
	}
	_, _ = fmt.Fprintf(tw, "\n%d of %d processes\n", len(pl.GetProcesses()), pl.GetTotal())
	return tw.Flush()
}

// PriorityNames are syslog priorities by number.
var PriorityNames = []string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}

// ParsePriority accepts 0-7 or a priority name.
func ParsePriority(s string) (uint32, error) {
	if n, err := strconv.ParseUint(s, 10, 32); err == nil && n <= 7 {
		return uint32(n), nil
	}
	for i, name := range PriorityNames {
		if strings.EqualFold(s, name) || (name == "err" && strings.EqualFold(s, "error")) || (name == "warning" && strings.EqualFold(s, "warn")) {
			return uint32(i), nil //nolint:gosec // 0-7
		}
	}
	return 0, fmt.Errorf("unknown priority %q (use 0-7 or emerg, alert, crit, err, warning, notice, info, debug)", s)
}

// PrintLogs renders journal entries.
func PrintLogs(w io.Writer, entries []*agentv1.LogEntry) error {
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
			prio = strings.ToUpper(PriorityNames[p]) + " "
		}
		if _, err := fmt.Fprintf(w, "%s %s: %s%s\n", e.GetTime().AsTime().Local().Format("Jan 02 15:04:05"), src, prio, e.GetMessage()); err != nil {
			return err
		}
	}
	return nil
}

// PrintAuth renders SSH and sudo events.
func PrintAuth(w io.Writer, events []*agentv1.AuthEvent, failedOnly bool) error {
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

// PrintAudit renders audit events.
func PrintAudit(w io.Writer, events []*operatorv1.AuditEvent) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tTIME\tACTOR\tACTION\tRESULT\tSERVER\tDETAILS")
	for _, e := range events {
		var parts []string
		for k, v := range e.GetParams() {
			parts = append(parts, k+"="+v)
		}
		sort.Strings(parts)
		details := strings.Join(parts, " ")
		if len(details) > 120 {
			details = details[:117] + "..."
		}
		_, _ = fmt.Fprintf(tw, "%d\t%s\t%s:%s\t%s\t%s\t%s\t%s\n", e.GetId(), e.GetTime().AsTime().Local().Format(time.DateTime),
			e.GetActorType(), e.GetActorId(), e.GetAction(), e.GetResult(), e.GetServerId(), details)
	}
	return tw.Flush()
}
