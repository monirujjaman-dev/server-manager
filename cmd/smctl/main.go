// Command smctl is the Server Manager operator console.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/monirujjaman-dev/server-manager/internal/ctl"
	"github.com/monirujjaman-dev/server-manager/internal/pkg/version"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := rootCmd().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var serverURL, caFile string
	root := &cobra.Command{
		Use:           "smctl",
		Short:         "Server Manager operator console",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Get().Version,
	}
	root.SetVersionTemplate(version.String("smctl") + "\n")
	root.PersistentFlags().StringVar(&serverURL, "server", os.Getenv("SMCTL_SERVER"), "control-plane API URL, e.g. https://cp.internal:8444 (env SMCTL_SERVER)")
	root.PersistentFlags().StringVar(&caFile, "ca-file", os.Getenv("SMCTL_CA_FILE"), "CA certificate for the control plane (env SMCTL_CA_FILE)")

	root.AddCommand(&cobra.Command{
		Use:   "health",
		Short: "Check that the control plane is serving",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if serverURL == "" {
				return errors.New("--server is required")
			}
			res, err := ctl.Health(cmd.Context(), serverURL, caFile)
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
	}, &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		Run:   func(cmd *cobra.Command, _ []string) { cmd.Println(version.String("smctl")) },
	})
	return root
}
