// Command sm-server is the Server Manager control plane.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/monirujjaman-dev/server-manager/internal/pkg/config"
	"github.com/monirujjaman-dev/server-manager/internal/pkg/logging"
	"github.com/monirujjaman-dev/server-manager/internal/pkg/version"
	"github.com/monirujjaman-dev/server-manager/internal/server"
)

const envPrefix = "SM_"

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
		Use:           "sm-server",
		Short:         "Server Manager control plane",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Get().Version,
	}
	root.SetVersionTemplate(version.String("sm-server") + "\n")
	root.PersistentFlags().StringVarP(&configPath, "config", "c", os.Getenv(envPrefix+"CONFIG"), "path to config file (env SM_CONFIG)")

	loadConfig := func() (server.Config, error) {
		cfg := server.DefaultConfig()
		if err := config.Load(configPath, envPrefix, &cfg); err != nil {
			return cfg, err
		}
		return cfg, nil
	}

	root.AddCommand(&cobra.Command{
		Use:   "serve",
		Short: "Run the control plane",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			log, err := logging.New(os.Stderr, cfg.Log)
			if err != nil {
				return err
			}
			log.Info("starting", "version", version.Get().Version)
			srv, err := server.New(cmd.Context(), cfg, log)
			if err != nil {
				return err
			}
			defer srv.Close()
			return srv.Run(cmd.Context())
		},
	})
	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		Run:   func(cmd *cobra.Command, _ []string) { cmd.Println(version.String("sm-server")) },
	})
	root.AddCommand(migrateCmd(loadConfig), pkiCmd(loadConfig), enrollCmd(loadConfig), serversCmd(loadConfig), groupsCmd(loadConfig), auditCmd(loadConfig))
	return root
}
