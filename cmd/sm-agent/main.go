// Command sm-agent runs on every managed server and connects out to the control plane.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/monirujjaman-dev/server-manager/internal/agent"
	"github.com/monirujjaman-dev/server-manager/internal/pkg/config"
	"github.com/monirujjaman-dev/server-manager/internal/pkg/logging"
	"github.com/monirujjaman-dev/server-manager/internal/pkg/version"
	"github.com/monirujjaman-dev/server-manager/internal/pki"
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

func rootCmd() *cobra.Command {
	var configPath string
	root := &cobra.Command{
		Use:           "sm-agent",
		Short:         "Server Manager agent",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Get().Version,
	}
	root.SetVersionTemplate(version.String("sm-agent") + "\n")
	root.PersistentFlags().StringVarP(&configPath, "config", "c", os.Getenv(envPrefix+"CONFIG"), "path to config file (env SM_AGENT_CONFIG)")

	root.AddCommand(&cobra.Command{
		Use:   "run",
		Short: "Connect to the control plane and serve requests",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
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

	var keyDir string
	keygen := &cobra.Command{
		Use:   "keygen",
		Short: "Generate the agent key pair and a certificate request",
		Long: `Generate an Ed25519 key (agent.key, mode 0600) and a certificate request (agent.csr).
Only agent.csr is sent to the control plane; agent.key never leaves this server.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := os.MkdirAll(keyDir, 0o700); err != nil {
				return err
			}
			key, csr, err := pki.NewAgentKey()
			if err != nil {
				return err
			}
			keyPath := filepath.Join(keyDir, "agent.key")
			if err := pki.WriteKeyFile(keyPath, key, false); err != nil {
				return fmt.Errorf("write key (refusing to overwrite an existing key): %w", err)
			}
			csrPath := filepath.Join(keyDir, "agent.csr")
			if err := pki.WriteCSRFile(csrPath, csr); err != nil {
				return err
			}
			cmd.Printf("key: %s\ncertificate request: %s\n", keyPath, csrPath)
			return nil
		},
	}
	keygen.Flags().StringVar(&keyDir, "dir", "/etc/sm-agent", "directory for agent.key and agent.csr")

	root.AddCommand(keygen, &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		Run:   func(cmd *cobra.Command, _ []string) { cmd.Println(version.String("sm-agent")) },
	})
	return root
}
