// Command smctl is the Server Manager operator console.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	operatorv1 "github.com/monirujjaman-dev/server-manager/gen/sm/operator/v1"
	"github.com/monirujjaman-dev/server-manager/internal/command"
	"github.com/monirujjaman-dev/server-manager/internal/ctl"
	"github.com/monirujjaman-dev/server-manager/internal/pkg/version"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := rootCmd().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "error:", friendly(err))
		os.Exit(1)
	}
}

// friendly turns common API errors into hints.
func friendly(err error) string {
	switch connect.CodeOf(err) {
	case connect.CodeUnauthenticated:
		return "not logged in or session expired; run `smctl login`"
	case connect.CodePermissionDenied, connect.CodeNotFound, connect.CodeInvalidArgument, connect.CodeFailedPrecondition, connect.CodeResourceExhausted:
		var ce *connect.Error
		if errors.As(err, &ce) {
			return ce.Message()
		}
	}
	return err.Error()
}

type app struct {
	serverURL, caFile string
	yes               bool
	wait              time.Duration
}

// client builds an API client from flags, falling back to the saved session.
func (a *app) client(cmd *cobra.Command, needLogin bool) (*ctl.Client, error) {
	sess, err := ctl.LoadSession()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	server, ca := a.serverURL, a.caFile
	if server == "" {
		server = sess.Server
	}
	if ca == "" && server == sess.Server {
		ca = sess.CAFile
	}
	token := ""
	if server == sess.Server {
		token = sess.Token
	}
	if needLogin && token == "" {
		return nil, errors.New("not logged in; run `smctl login --server https://<control-plane>:8444`")
	}
	c, err := ctl.NewClient(server, ca, token)
	if err != nil {
		return nil, err
	}
	c.StepUp = func() (string, error) {
		return ctl.ReadLine(cmd.ErrOrStderr(), "This action needs a fresh MFA code. Code: ")
	}
	return c, nil
}

// run executes one action and prints its result.
func (a *app) run(cmd *cobra.Command, server string, req *agentv1.ActionRequest, print func(io.Writer, *agentv1.ActionResult) error) error {
	info, err := command.Describe(req)
	if err != nil {
		return err
	}
	if info.Risk != command.RiskRead && info.Risk != command.RiskLow && !a.yes {
		return fmt.Errorf("%s is a %s-risk action; repeat with --yes to confirm", info.Name, info.Risk)
	}
	c, err := a.client(cmd, true)
	if err != nil {
		return err
	}
	job, err := c.Run(cmd.Context(), server, req, a.wait)
	if err != nil {
		return err
	}
	return print(cmd.OutOrStdout(), job.GetResult())
}

func rootCmd() *cobra.Command {
	a := &app{}
	root := &cobra.Command{
		Use:           "smctl",
		Short:         "Server Manager operator console",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Get().Version,
	}
	// cmd.Print* writes to stderr unless an output is set; results belong on stdout.
	root.SetOut(os.Stdout)
	root.SetVersionTemplate(version.String("smctl") + "\n")
	pf := root.PersistentFlags()
	pf.StringVar(&a.serverURL, "server", os.Getenv("SMCTL_SERVER"), "control-plane API URL, e.g. https://cp.internal:8444 (default: from login)")
	pf.StringVar(&a.caFile, "ca-file", os.Getenv("SMCTL_CA_FILE"), "CA certificate of the control plane (default: from login)")
	pf.BoolVarP(&a.yes, "yes", "y", false, "confirm a medium- or high-risk action")
	pf.DurationVar(&a.wait, "timeout", 2*time.Minute, "how long to wait for a result")

	root.AddCommand(sessionCommands(a)...)
	root.AddCommand(fleetCommands(a)...)
	root.AddCommand(actionCommands(a)...)
	root.AddCommand(&cobra.Command{
		Use: "version", Short: "Print version information", Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) { cmd.Println(version.String("smctl")) },
	})
	return root
}

func sessionCommands(a *app) []*cobra.Command {
	var email string
	login := &cobra.Command{
		Use:   "login",
		Short: "Log in with e-mail, password and an MFA code",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if a.serverURL == "" {
				if s, err := ctl.LoadSession(); err == nil {
					a.serverURL, a.caFile = s.Server, s.CAFile
				}
			}
			c, err := a.client(cmd, false)
			if err != nil {
				return err
			}
			out := cmd.ErrOrStderr()
			if email == "" {
				if email, err = ctl.ReadLine(out, "E-mail: "); err != nil {
					return err
				}
			}
			pw, err := ctl.ReadSecret(out, "Password: ")
			if err != nil {
				return err
			}
			code, err := ctl.ReadLine(out, "MFA code: ")
			if err != nil {
				return err
			}
			resp, err := c.Auth.Login(cmd.Context(), connect.NewRequest(&operatorv1.LoginRequest{Email: email, Password: pw, TotpCode: code}))
			if err != nil {
				if connect.CodeOf(err) == connect.CodeUnauthenticated {
					return errors.New("invalid e-mail, password or code")
				}
				return err
			}
			if err := ctl.SaveSession(ctl.Session{
				Server: a.serverURL, CAFile: a.caFile, Token: resp.Msg.GetToken(), Email: resp.Msg.GetEmail(),
				ExpiresAt: resp.Msg.GetExpiresAt().AsTime(),
			}); err != nil {
				return err
			}
			cmd.Printf("logged in as %s until %s\n", resp.Msg.GetEmail(), resp.Msg.GetExpiresAt().AsTime().Local().Format(time.DateTime))
			return nil
		},
	}
	login.Flags().StringVar(&email, "email", "", "account e-mail (prompted if empty)")

	logout := &cobra.Command{
		Use: "logout", Short: "End the session", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if c, err := a.client(cmd, true); err == nil {
				_, _ = c.Auth.Logout(cmd.Context(), connect.NewRequest(&operatorv1.LogoutRequest{}))
			}
			// Keep the server and CA so the next `smctl login` needs no flags.
			s, err := ctl.LoadSession()
			if err != nil {
				return ctl.DeleteSession()
			}
			s.Token, s.ExpiresAt = "", time.Time{}
			return ctl.SaveSession(s)
		},
	}

	whoami := &cobra.Command{
		Use: "whoami", Short: "Show the logged-in user and roles", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.client(cmd, true)
			if err != nil {
				return err
			}
			resp, err := c.Auth.WhoAmI(cmd.Context(), connect.NewRequest(&operatorv1.WhoAmIRequest{}))
			if err != nil {
				return err
			}
			cmd.Printf("%s (%s)\n", resp.Msg.GetEmail(), resp.Msg.GetUserId())
			if len(resp.Msg.GetRoles()) == 0 {
				cmd.Println("no roles: ask an administrator for one")
			}
			for _, r := range resp.Msg.GetRoles() {
				where := r.GetGroup()
				if where == "" {
					where = "all servers"
				}
				cmd.Printf("  %s on %s\n", r.GetRole(), where)
			}
			return nil
		},
	}

	health := &cobra.Command{
		Use: "health", Short: "Check that the control plane is serving (no login needed)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.client(cmd, false)
			if err != nil {
				return err
			}
			res, err := ctl.Health(cmd.Context(), c)
			if err != nil {
				return err
			}
			status := "SERVING"
			if !res.Serving {
				status = "NOT SERVING"
			}
			cmd.Printf("%s  latency=%s  clock_skew=%s\n", status, res.Latency.Round(time.Millisecond), res.Skew.Round(time.Millisecond))
			if !res.Serving {
				return errors.New("control plane is not serving")
			}
			return nil
		},
	}
	return []*cobra.Command{login, logout, whoami, health}
}

func fleetCommands(a *app) []*cobra.Command {
	var watch time.Duration
	list := func(cmd *cobra.Command, _ []string) error {
		c, err := a.client(cmd, true)
		if err != nil {
			return err
		}
		for {
			resp, err := c.Fleet.ListServers(cmd.Context(), connect.NewRequest(&operatorv1.ListServersRequest{}))
			if err != nil {
				return err
			}
			if watch > 0 {
				_, _ = fmt.Fprint(cmd.OutOrStdout(), "\033[H\033[2J")
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Server Manager — %s (every %s, Ctrl-C to quit)\n\n", time.Now().Format(time.TimeOnly), watch)
			}
			if err := ctl.PrintServers(cmd.OutOrStdout(), resp.Msg.GetServers(), time.Now()); err != nil {
				return err
			}
			if watch <= 0 {
				return nil
			}
			select {
			case <-cmd.Context().Done():
				return nil
			case <-time.After(watch):
			}
		}
	}
	dashboard := &cobra.Command{Use: "dashboard", Short: "Show all servers you can see with live metrics", Args: cobra.NoArgs, RunE: list}
	dashboard.Flags().DurationVarP(&watch, "watch", "w", 0, "refresh at this interval, e.g. 5s")

	servers := &cobra.Command{Use: "servers", Short: "List and revoke servers"}
	servers.AddCommand(&cobra.Command{Use: "list", Short: "List servers", Args: cobra.NoArgs, RunE: list})
	var reason string
	revoke := &cobra.Command{
		Use: "revoke <server>", Short: "Revoke a server (admin, step-up)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !a.yes {
				return errors.New("revoking is a high-risk action; repeat with --yes to confirm")
			}
			c, err := a.client(cmd, true)
			if err != nil {
				return err
			}
			if err := c.WithStepUp(cmd.Context(), func() error {
				_, err := c.Fleet.RevokeServer(cmd.Context(), connect.NewRequest(&operatorv1.RevokeServerRequest{Server: args[0], Reason: reason}))
				return err
			}); err != nil {
				return err
			}
			cmd.Printf("revoked %s\n", args[0])
			return nil
		},
	}
	revoke.Flags().StringVar(&reason, "reason", "", "reason, recorded in the audit log")
	_ = revoke.MarkFlagRequired("reason")
	servers.AddCommand(revoke)

	var name, group string
	var ttl time.Duration
	enroll := &cobra.Command{Use: "enroll", Short: "Enroll new servers"}
	token := &cobra.Command{
		Use: "create-token", Short: "Create a one-time enrollment token (admin, step-up)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.client(cmd, true)
			if err != nil {
				return err
			}
			var resp *connect.Response[operatorv1.CreateEnrollmentTokenResponse]
			if err := c.WithStepUp(cmd.Context(), func() error {
				var err error
				resp, err = c.Fleet.CreateEnrollmentToken(cmd.Context(), connect.NewRequest(&operatorv1.CreateEnrollmentTokenRequest{
					ServerName: name, Group: group, TtlSeconds: uint32(ttl.Seconds()),
				}))
				return err
			}); err != nil {
				return err
			}
			m := resp.Msg
			api := m.GetApiUrl()
			if api == "" {
				api = "https://<control-plane-host>:8444"
			}
			ver := "<version>"
			if v := version.Get().Version; len(v) > 1 && v[0] == 'v' && v[1] >= '0' && v[1] <= '9' && !strings.Contains(v, "-") {
				ver = v[1:]
			}
			cmd.Printf("Enrollment token for %q (single use, expires %s):\n\n  %s\n\n", name, m.GetExpiresAt().AsTime().Local().Format(time.RFC1123), m.GetToken())
			cmd.Printf("Install and enroll on the new server (as root):\n\n"+
				"  curl -fsSLO https://github.com/monirujjaman-dev/server-manager/releases/download/v%s/install-agent.sh\n"+
				"  SM_ENROLL_TOKEN=%s sh install-agent.sh --version %s \\\n    --server %s --pin %s\n\n",
				ver, m.GetToken(), ver, api, m.GetPin())
			cmd.Printf("Or, with sm-agent already installed:\n\n  SM_AGENT_ENROLL_TOKEN=%s sm-agent enroll --owner smagent \\\n    --server %s --pin %s\n",
				m.GetToken(), api, m.GetPin())
			return nil
		},
	}
	token.Flags().StringVar(&name, "name", "", "server name")
	token.Flags().StringVar(&group, "group", "", "server group")
	token.Flags().DurationVar(&ttl, "ttl", 15*time.Minute, "token lifetime")
	_ = token.MarkFlagRequired("name")
	enroll.AddCommand(token)

	var after int64
	var limit uint32
	auditList := &cobra.Command{
		Use: "list", Short: "List audit events (global admin)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.client(cmd, true)
			if err != nil {
				return err
			}
			resp, err := c.Fleet.ListAuditEvents(cmd.Context(), connect.NewRequest(&operatorv1.ListAuditEventsRequest{AfterId: after, Limit: limit}))
			if err != nil {
				return err
			}
			return ctl.PrintAudit(cmd.OutOrStdout(), resp.Msg.GetEvents())
		},
	}
	auditList.Flags().Int64Var(&after, "after", 0, "show events after this ID")
	auditList.Flags().Uint32Var(&limit, "limit", 100, "maximum events")
	audit := &cobra.Command{Use: "audit", Short: "Inspect the audit log"}
	audit.AddCommand(auditList)

	return []*cobra.Command{dashboard, servers, enroll, audit}
}

func actionCommands(a *app) []*cobra.Command {
	system := &cobra.Command{Use: "system", Short: "Inspect a server"}
	system.AddCommand(&cobra.Command{
		Use: "info <server>", Short: "Show uptime, load, memory and disks", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.run(cmd, args[0], &agentv1.ActionRequest{Action: &agentv1.ActionRequest_SystemInfo{SystemInfo: &agentv1.SystemInfoRequest{}}}, ctl.PrintSystemInfo)
		},
	})

	services := &cobra.Command{Use: "services", Short: "List and control systemd services"}
	var filter string
	slist := &cobra.Command{
		Use: "list <server>", Short: "List services", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.run(cmd, args[0], &agentv1.ActionRequest{Action: &agentv1.ActionRequest_ServiceList{ServiceList: &agentv1.ServiceListRequest{Filter: filter}}}, ctl.PrintServices)
		},
	}
	slist.Flags().StringVar(&filter, "filter", "", "only units whose name contains this text")
	services.AddCommand(slist)
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
		services.AddCommand(&cobra.Command{
			Use: op.name + " <server> <unit>", Short: strings.ToUpper(op.name[:1]) + op.name[1:] + " a service", Args: cobra.ExactArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				return a.run(cmd, args[0], &agentv1.ActionRequest{Action: &agentv1.ActionRequest_ServiceControl{ServiceControl: &agentv1.ServiceControlRequest{
					Unit: command.NormalizeUnit(args[1]), Operation: op.op,
				}}}, ctl.PrintServiceUnit)
			},
		})
	}

	processes := &cobra.Command{Use: "processes", Aliases: []string{"ps"}, Short: "List and signal processes"}
	var sortBy string
	var plimit uint32
	plist := &cobra.Command{
		Use: "list <server>", Short: "List processes", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			order := map[string]agentv1.ProcessSort{"cpu": agentv1.ProcessSort_PROCESS_SORT_CPU, "mem": agentv1.ProcessSort_PROCESS_SORT_MEMORY, "pid": agentv1.ProcessSort_PROCESS_SORT_PID}[sortBy]
			if order == agentv1.ProcessSort_PROCESS_SORT_UNSPECIFIED {
				return errors.New("--sort must be cpu, mem or pid")
			}
			return a.run(cmd, args[0], &agentv1.ActionRequest{Action: &agentv1.ActionRequest_ProcessList{ProcessList: &agentv1.ProcessListRequest{Sort: order, Limit: plimit}}}, ctl.PrintProcesses)
		},
	}
	plist.Flags().StringVar(&sortBy, "sort", "cpu", "sort by cpu, mem or pid")
	plist.Flags().Uint32Var(&plimit, "limit", 25, "number of processes (max 500)")
	var sigName string
	var startTicks uint64
	kill := &cobra.Command{
		Use: "kill <server> <pid>", Short: "Send a signal to a process", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var pid int32
			if _, err := fmt.Sscan(args[1], &pid); err != nil {
				return fmt.Errorf("invalid PID %q", args[1])
			}
			sig, ok := agentv1.Signal_value["SIGNAL_"+strings.TrimPrefix(strings.ToUpper(sigName), "SIG")]
			if !ok {
				return fmt.Errorf("unsupported signal %q (TERM, KILL, HUP, INT, QUIT, USR1, USR2)", sigName)
			}
			return a.run(cmd, args[0], &agentv1.ActionRequest{Action: &agentv1.ActionRequest_ProcessSignal{ProcessSignal: &agentv1.ProcessSignalRequest{
				Pid: pid, Signal: agentv1.Signal(sig), StartTicks: startTicks,
			}}}, func(w io.Writer, _ *agentv1.ActionResult) error {
				_, err := fmt.Fprintf(w, "sent %s to %d\n", strings.ToUpper(sigName), pid)
				return err
			})
		},
	}
	kill.Flags().StringVarP(&sigName, "signal", "s", "TERM", "TERM, KILL, HUP, INT, QUIT, USR1, USR2")
	kill.Flags().Uint64Var(&startTicks, "start", 0, "START value from `processes list`; refuses if the PID was reused")
	processes.AddCommand(plist, kill)

	var unit, grep, prio string
	var since time.Duration
	var lines uint32
	var follow bool
	logs := &cobra.Command{
		Use: "logs <server>", Short: "Show journal entries, optionally for one unit, or follow them", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if since < 0 || since > 30*24*time.Hour {
				return errors.New("--since must be between 0 and 720h")
			}
			req := &agentv1.LogQueryRequest{Unit: unit, SinceSeconds: uint32(since.Seconds()), Limit: lines, Grep: grep}
			if unit != "" && !strings.Contains(unit, ".") {
				req.Unit = unit + ".service"
			}
			if prio != "" {
				p, err := ctl.ParsePriority(prio)
				if err != nil {
					return err
				}
				req.MaxPriority = &p
			}
			for {
				var cursor string
				if err := a.run(cmd, args[0], &agentv1.ActionRequest{Action: &agentv1.ActionRequest_LogQuery{LogQuery: req}}, func(w io.Writer, res *agentv1.ActionResult) error {
					cursor = res.GetLogQuery().GetCursor()
					return ctl.PrintLogs(w, res.GetLogQuery().GetEntries())
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
	logs.Flags().StringVarP(&unit, "unit", "u", "", "systemd unit, e.g. nginx")
	logs.Flags().DurationVar(&since, "since", time.Hour, "how far back to look")
	logs.Flags().Uint32VarP(&lines, "lines", "n", 100, "maximum entries (max 500)")
	logs.Flags().StringVar(&grep, "grep", "", "only entries containing this text")
	logs.Flags().StringVarP(&prio, "priority", "p", "", "this priority or more severe, e.g. err")
	logs.Flags().BoolVarP(&follow, "follow", "f", false, "keep printing new entries (polls every 2 s)")

	var authSince time.Duration
	var authLimit uint32
	var failedOnly bool
	logins := &cobra.Command{
		Use: "logins <server>", Short: "Show SSH logins and failures, and sudo use", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if authSince < 0 || authSince > 30*24*time.Hour {
				return errors.New("--since must be between 0 and 720h")
			}
			req := &agentv1.AuthLogRequest{SinceSeconds: uint32(authSince.Seconds()), Limit: authLimit}
			return a.run(cmd, args[0], &agentv1.ActionRequest{Action: &agentv1.ActionRequest_AuthLog{AuthLog: req}}, func(w io.Writer, res *agentv1.ActionResult) error {
				return ctl.PrintAuth(w, res.GetAuthLog().GetEvents(), failedOnly)
			})
		},
	}
	logins.Flags().DurationVar(&authSince, "since", 24*time.Hour, "how far back to look")
	logins.Flags().Uint32VarP(&authLimit, "lines", "n", 100, "maximum events (max 500)")
	logins.Flags().BoolVar(&failedOnly, "failed", false, "only failed logins and denied sudo")

	return []*cobra.Command{system, services, processes, logs, logins}
}
