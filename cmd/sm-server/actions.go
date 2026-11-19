package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/internal/command"
	"github.com/monirujjaman-dev/server-manager/internal/server"
	"github.com/monirujjaman-dev/server-manager/internal/server/fleet"
	"github.com/monirujjaman-dev/server-manager/internal/server/jobs"
)

// actionRunner submits one action, waits for its result and prints it.
type actionRunner struct {
	loadConfig func() (server.Config, error)
	timeout    time.Duration
	yes        bool
}

func (r *actionRunner) run(cmd *cobra.Command, serverName string, req *agentv1.ActionRequest, print func(io.Writer, *agentv1.ActionResult) error) error {
	info, err := command.Describe(req)
	if err != nil {
		return err
	}
	if (info.Risk == command.RiskMedium || info.Risk == command.RiskHigh || info.Risk == command.RiskCritical) && !r.yes {
		return fmt.Errorf("%s is a %s-risk action; repeat with --yes to confirm", info.Name, info.Risk)
	}
	ctx := cmd.Context()
	st, _, err := openStore(ctx, r.loadConfig)
	if err != nil {
		return err
	}
	defer st.Close()
	srv, err := fleet.Resolve(ctx, st.Queries, serverName)
	if err != nil {
		return err
	}
	job, err := jobs.Submit(ctx, st, srv.ID, req, localActor(), r.timeout)
	if err != nil {
		return err
	}
	if srv.Status != "online" {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s is %s; the job waits up to %s for it to connect\n", srv.Name, srv.Status, r.timeout)
	}
	wctx, cancel := context.WithTimeout(ctx, r.timeout+jobs.ResultTimeout)
	defer cancel()
	job, err = jobs.Wait(wctx, st.Queries, job.ID)
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("no result yet for job %s (status %s); see `sm-server audit list`", job.ID, job.Status)
	} else if err != nil {
		return err
	}
	if job.Status != jobs.StatusSucceeded {
		return fmt.Errorf("job %s %s: %s", job.ID, job.Status, job.Error)
	}
	res, err := jobs.Result(job)
	if err != nil {
		return err
	}
	return print(cmd.OutOrStdout(), res.GetResult())
}

func actionCommands(loadConfig func() (server.Config, error)) []*cobra.Command {
	r := &actionRunner{loadConfig: loadConfig}
	flags := func(c *cobra.Command) *cobra.Command {
		c.Flags().DurationVar(&r.timeout, "timeout", 2*time.Minute, "how long the job may wait for the server to be online")
		c.Flags().BoolVarP(&r.yes, "yes", "y", false, "confirm a medium- or high-risk action")
		return c
	}

	system := &cobra.Command{Use: "system", Short: "Inspect a server"}
	system.AddCommand(flags(&cobra.Command{
		Use: "info <server>", Short: "Show uptime, load, memory and disks", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return r.run(cmd, args[0], &agentv1.ActionRequest{Action: &agentv1.ActionRequest_SystemInfo{SystemInfo: &agentv1.SystemInfoRequest{}}}, printSystemInfo)
		},
	}))

	services := &cobra.Command{Use: "services", Short: "List and control systemd services"}
	var filter string
	list := flags(&cobra.Command{
		Use: "list <server>", Short: "List services", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return r.run(cmd, args[0], &agentv1.ActionRequest{Action: &agentv1.ActionRequest_ServiceList{ServiceList: &agentv1.ServiceListRequest{Filter: filter}}}, printServices)
		},
	})
	list.Flags().StringVar(&filter, "filter", "", "only units whose name contains this text")
	services.AddCommand(list)
	for _, op := range []struct {
		name string
		op   agentv1.ServiceOperation
	}{
		{"start", agentv1.ServiceOperation_SERVICE_OPERATION_START},
		{"stop", agentv1.ServiceOperation_SERVICE_OPERATION_STOP},
		{"restart", agentv1.ServiceOperation_SERVICE_OPERATION_RESTART},
		{"reload", agentv1.ServiceOperation_SERVICE_OPERATION_RELOAD},
		{"enable", agentv1.ServiceOperation_SERVICE_OPERATION_ENABLE},
		{"disable", agentv1.ServiceOperation_SERVICE_OPERATION_DISABLE},
	} {
		services.AddCommand(flags(&cobra.Command{
			Use: op.name + " <server> <unit>", Short: strings.ToUpper(op.name[:1]) + op.name[1:] + " a service", Args: cobra.ExactArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				req := &agentv1.ActionRequest{Action: &agentv1.ActionRequest_ServiceControl{ServiceControl: &agentv1.ServiceControlRequest{
					Unit: command.NormalizeUnit(args[1]), Operation: op.op,
				}}}
				return r.run(cmd, args[0], req, func(w io.Writer, res *agentv1.ActionResult) error {
					u := res.GetServiceControl().GetUnit()
					_, err := fmt.Fprintf(w, "%s: %s (%s), %s\n", u.GetName(), u.GetActiveState(), u.GetSubState(), u.GetUnitFileState())
					return err
				})
			},
		}))
	}

	processes := &cobra.Command{Use: "processes", Aliases: []string{"ps"}, Short: "List and signal processes"}
	var sortBy string
	var limit uint32
	plist := flags(&cobra.Command{
		Use: "list <server>", Short: "List processes (CPU sampled over 0.3 s)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sortOrder := map[string]agentv1.ProcessSort{"cpu": agentv1.ProcessSort_PROCESS_SORT_CPU, "mem": agentv1.ProcessSort_PROCESS_SORT_MEMORY, "pid": agentv1.ProcessSort_PROCESS_SORT_PID}[sortBy]
			if sortOrder == agentv1.ProcessSort_PROCESS_SORT_UNSPECIFIED {
				return errors.New("--sort must be cpu, mem or pid")
			}
			return r.run(cmd, args[0], &agentv1.ActionRequest{Action: &agentv1.ActionRequest_ProcessList{ProcessList: &agentv1.ProcessListRequest{Sort: sortOrder, Limit: limit}}}, printProcesses)
		},
	})
	plist.Flags().StringVar(&sortBy, "sort", "cpu", "sort by cpu, mem or pid")
	plist.Flags().Uint32Var(&limit, "limit", 25, "number of processes (max 500)")
	var sigName string
	var startTicks uint64
	kill := flags(&cobra.Command{
		Use: "kill <server> <pid>", Short: "Send a signal to a process", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var pid int32
			if _, err := fmt.Sscan(args[1], &pid); err != nil {
				return fmt.Errorf("invalid PID %q", args[1])
			}
			sig, ok := agentv1.Signal_value["SIGNAL_"+strings.ToUpper(strings.TrimPrefix(strings.ToUpper(sigName), "SIG"))]
			if !ok {
				return fmt.Errorf("unsupported signal %q (TERM, KILL, HUP, INT, QUIT, USR1, USR2)", sigName)
			}
			req := &agentv1.ActionRequest{Action: &agentv1.ActionRequest_ProcessSignal{ProcessSignal: &agentv1.ProcessSignalRequest{
				Pid: pid, Signal: agentv1.Signal(sig), StartTicks: startTicks,
			}}}
			return r.run(cmd, args[0], req, func(w io.Writer, _ *agentv1.ActionResult) error {
				_, err := fmt.Fprintf(w, "sent %s to %d\n", strings.ToUpper(sigName), pid)
				return err
			})
		},
	})
	kill.Flags().StringVarP(&sigName, "signal", "s", "TERM", "signal: TERM, KILL, HUP, INT, QUIT, USR1, USR2")
	kill.Flags().Uint64Var(&startTicks, "start", 0, "START value from `processes list`; refuses if the PID was reused")
	processes.AddCommand(plist, kill)

	return []*cobra.Command{system, services, processes}
}

func bytesHuman(n uint64) string {
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

func printSystemInfo(w io.Writer, res *agentv1.ActionResult) error {
	s := res.GetSystemInfo()
	up := time.Duration(s.GetUptimeSeconds()) * time.Second //nolint:gosec // uptime fits
	_, _ = fmt.Fprintf(w, "host     %s\nuptime   %s\nload     %.2f %.2f %.2f (%d CPUs)\n", s.GetHostname(), up, s.GetLoad1(), s.GetLoad5(), s.GetLoad15(), s.GetCpuCount())
	used := s.GetMemoryTotalBytes() - s.GetMemoryAvailableBytes()
	_, _ = fmt.Fprintf(w, "memory   %s used of %s\nswap     %s used of %s\n\n", bytesHuman(used), bytesHuman(s.GetMemoryTotalBytes()),
		bytesHuman(s.GetSwapTotalBytes()-s.GetSwapFreeBytes()), bytesHuman(s.GetSwapTotalBytes()))
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "MOUNT\tTYPE\tSIZE\tUSED\tUSE%\tDEVICE")
	for _, f := range s.GetFilesystems() {
		used := f.GetTotalBytes() - f.GetAvailableBytes()
		pct := 0.0
		if f.GetTotalBytes() > 0 {
			pct = float64(used) / float64(f.GetTotalBytes()) * 100
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%.0f%%\t%s\n", f.GetMountPoint(), f.GetFsType(), bytesHuman(f.GetTotalBytes()), bytesHuman(used), pct, f.GetDevice())
	}
	return tw.Flush()
}

func printServices(w io.Writer, res *agentv1.ActionResult) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "UNIT\tACTIVE\tSUB\tENABLED\tDESCRIPTION")
	for _, u := range res.GetServiceList().GetUnits() {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", u.GetName(), u.GetActiveState(), u.GetSubState(), u.GetUnitFileState(), u.GetDescription())
	}
	return tw.Flush()
}

func printProcesses(w io.Writer, res *agentv1.ActionResult) error {
	pl := res.GetProcessList()
	procs := pl.GetProcesses()
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "PID\tUSER\tCPU%\tRSS\tSTATE\tSTART\tCOMMAND")
	for _, p := range procs {
		cmdline := p.GetCommandLine()
		if cmdline == "" {
			cmdline = "[" + p.GetName() + "]"
		}
		if len(cmdline) > 80 {
			cmdline = cmdline[:77] + "..."
		}
		_, _ = fmt.Fprintf(tw, "%d\t%s\t%.1f\t%s\t%s\t%d\t%s\n", p.GetPid(), p.GetUser(), p.GetCpuPercent(), bytesHuman(p.GetRssBytes()), p.GetState(), p.GetStartTicks(), cmdline)
	}
	_, _ = fmt.Fprintf(tw, "\n%d of %d processes\n", len(procs), pl.GetTotal())
	return tw.Flush()
}
