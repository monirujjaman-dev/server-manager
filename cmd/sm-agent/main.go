// Command sm-agent runs on every managed server and connects out to the control plane.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/monirujjaman-dev/server-manager/internal/agent"
	"github.com/monirujjaman-dev/server-manager/internal/pkg/config"
	"github.com/monirujjaman-dev/server-manager/internal/pkg/logging"
	"github.com/monirujjaman-dev/server-manager/internal/pkg/version"
	"github.com/monirujjaman-dev/server-manager/internal/privd"
)

const envPrefix = "SM_AGENT_"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := rootCmd().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// requireLinux stops commands that need Linux kernel interfaces (/proc, systemd,
// SO_PEERCRED). `sm-agent enroll` works anywhere.
func requireLinux() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("sm-agent runs on Linux servers only (this is %s); run it on the managed server, in WSL or in a Linux VM", runtime.GOOS)
	}
	return nil
}

func rootCmd() *cobra.Command {
	var configPath, privdConfig string
	root := &cobra.Command{
		Use:           "sm-agent",
		Short:         "Server Manager agent",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Get().Version,
	}
	// cmd.Print* writes to stderr unless an output is set; results belong on stdout.
	root.SetOut(os.Stdout)
	root.SetVersionTemplate(version.String("sm-agent") + "\n")
	root.PersistentFlags().StringVarP(&configPath, "config", "c", os.Getenv(envPrefix+"CONFIG"), "path to config file (env SM_AGENT_CONFIG)")

	root.AddCommand(&cobra.Command{
		Use:   "run",
		Short: "Connect to the control plane and serve requests",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireLinux(); err != nil {
				return err
			}
			cfg := agent.DefaultConfig()
			if err := config.Load(configPath, envPrefix, &cfg); err != nil {
				return err
			}
			log, err := logging.New(os.Stderr, cfg.Log)
			if err != nil {
				return err
			}
			a, err := agent.New(cfg, log)
			if err != nil {
				return err
			}
			log.Info("starting", "version", version.Get().Version, "server_url", cfg.ServerURL)
			return a.Run(cmd.Context())
		},
	})

	var eo agent.EnrollOptions
	enroll := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll this server with the control plane (run once, as root)",
		Long: `Enroll this server using a one-time token from ` + "`sm-server enroll create-token`" + `.

The agent key is generated here and never leaves this server. The control plane is
authenticated by its public-key pin; after enrollment the agent verifies it with the CA
certificate it receives. Writes agent.key, agent.crt, ca.crt and agent.yaml to --dir.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if eo.Token == "" {
				eo.Token = os.Getenv(envPrefix + "ENROLL_TOKEN")
			}
			res, err := agent.Enroll(cmd.Context(), eo)
			if err != nil {
				return err
			}
			cmd.Printf("enrolled as %s (%s)\nagent gateway: %s\nconfiguration: %s\n\nStart the agent with:\n  sm-agent run --config %s\n",
				res.ServerName, res.ServerID, res.AgentURL, res.ConfigPath, res.ConfigPath)
			return nil
		},
	}
	enroll.Flags().StringVar(&eo.APIURL, "server", "", "control-plane API URL, e.g. https://cp.internal:8444")
	enroll.Flags().StringVar(&eo.Pin, "pin", "", "SHA-256 public-key pin of the control plane")
	enroll.Flags().StringVar(&eo.Token, "token", "", "one-time enrollment token (or env SM_AGENT_ENROLL_TOKEN)")
	enroll.Flags().StringVar(&eo.Dir, "dir", "/etc/sm-agent", "directory for the agent's key, certificates and config")
	enroll.Flags().StringVar(&eo.AgentURL, "agent-url", "", "override the agent gateway URL returned by the control plane")
	enroll.Flags().StringVar(&eo.Owner, "owner", "", "user that runs the agent and owns --dir (e.g. smagent)")
	_ = enroll.MarkFlagRequired("server")
	_ = enroll.MarkFlagRequired("pin")

	privdCmd := &cobra.Command{
		Use:   "privd",
		Short: "Run the privileged helper (root, local UNIX socket only)",
		Long: `Run the privileged helper. It must run as root, listens only on a local UNIX socket,
accepts connections only from the agent user, and executes privileged actions only
after verifying the control plane's signature itself.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireLinux(); err != nil {
				return err
			}
			cfg := privd.DefaultConfig()
			if err := config.Load(privdConfig, "SM_PRIVD_", &cfg); err != nil {
				return err
			}
			log, err := logging.New(os.Stderr, cfg.Log)
			if err != nil {
				return err
			}
			if os.Geteuid() != 0 {
				return errors.New("sm-agent privd must run as root")
			}
			gid, err := privd.AgentGID(cfg.AgentUser)
			if err != nil {
				return fmt.Errorf("agent user %q: %w", cfg.AgentUser, err)
			}
			srv, err := privd.New(cfg, log, privd.Options{})
			if err != nil {
				return err
			}
			ln, err := privd.Listen(cmd.Context(), cfg.Socket, gid)
			if err != nil {
				return err
			}
			log.Info("privileged helper listening", "socket", cfg.Socket, "agent_user", cfg.AgentUser)
			return srv.Serve(cmd.Context(), ln)
		},
	}
	privdCmd.Flags().StringVar(&privdConfig, "privd-config", os.Getenv("SM_PRIVD_CONFIG"), "helper config file (env SM_PRIVD_CONFIG)")

	root.AddCommand(enroll, privdCmd, &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		Run:   func(cmd *cobra.Command, _ []string) { cmd.Println(version.String("sm-agent")) },
	})
	return root
}
