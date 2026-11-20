package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/internal/command"
	"github.com/monirujjaman-dev/server-manager/internal/ctl"
)

func timeCommand(a *app) *cobra.Command {
	tc := &cobra.Command{Use: "time", Short: "Show and set the time zone and NTP"}
	tc.AddCommand(a.addBulkFlags(&cobra.Command{
		Use: "status <servers>", Short: "Show the time zone, clock and NTP state", Args: a.serverArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			server, _ := a.splitServer(args)
			return a.run(cmd, server, &agentv1.ActionRequest{Action: &agentv1.ActionRequest_TimeStatus{TimeStatus: &agentv1.TimeStatusRequest{}}},
				ctl.PrintTime(func(r *agentv1.ActionResult) *agentv1.TimeStatusResult { return r.GetTimeStatus() }))
		},
	}))
	tc.AddCommand(a.addBulkFlags(&cobra.Command{
		Use: "set-timezone <servers> <zone>", Short: "Set the time zone, e.g. Europe/Berlin or UTC", Args: a.serverArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			server, rest := a.splitServer(args)
			if err := command.ValidateTimezone(rest[0]); err != nil {
				return err
			}
			return a.run(cmd, server, &agentv1.ActionRequest{Action: &agentv1.ActionRequest_TimeSetTimezone{TimeSetTimezone: &agentv1.TimeSetTimezoneRequest{Timezone: rest[0]}}},
				ctl.PrintTime(func(r *agentv1.ActionResult) *agentv1.TimeStatusResult { return r.GetTimeSetTimezone() }))
		},
	}))
	tc.AddCommand(a.addBulkFlags(&cobra.Command{
		Use: "ntp <servers> on|off", Short: "Turn NTP time synchronisation on or off", Args: a.serverArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			server, rest := a.splitServer(args)
			var on bool
			switch rest[0] {
			case "on":
				on = true
			case "off":
			default:
				return fmt.Errorf("want on or off, not %q", rest[0])
			}
			return a.run(cmd, server, &agentv1.ActionRequest{Action: &agentv1.ActionRequest_TimeSetNtp{TimeSetNtp: &agentv1.TimeSetNTPRequest{Enabled: on}}},
				ctl.PrintTime(func(r *agentv1.ActionResult) *agentv1.TimeStatusResult { return r.GetTimeSetNtp() }))
		},
	}))
	return tc
}

// parseSize reads a swap size such as 2G, 512M or 2048 (MiB).
func parseSize(s string) (uint32, error) {
	mult := uint64(1)
	switch u := strings.ToUpper(strings.TrimSuffix(strings.ToUpper(s), "B")); {
	case strings.HasSuffix(u, "G"):
		mult, s = 1024, strings.TrimSuffix(u, "G")
	case strings.HasSuffix(u, "M"):
		s = strings.TrimSuffix(u, "M")
	default:
		s = u
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n*mult < command.MinSwapMiB || n*mult > command.MaxSwapMiB {
		return 0, fmt.Errorf("size must be between %d MiB and %d GiB, e.g. 2G or 512M", command.MinSwapMiB, command.MaxSwapMiB>>10)
	}
	return uint32(n * mult), nil //nolint:gosec // bounded by MaxSwapMiB above
}

func swapCommand(a *app) *cobra.Command {
	sc := &cobra.Command{Use: "swap", Short: "Show swap and manage a swapfile", Long: `Show swap devices and manage one swapfile per server.

The privileged helper manages a single swapfile at ` + "/var/lib/smswap/swapfile" + `, activated by a systemd swap
unit so it survives reboots. Swap partitions and swapfiles it did not create are shown
but never changed. Swapfiles are supported on ext4 and xfs.`}
	printSwap := func(get func(*agentv1.ActionResult) *agentv1.SwapStatusResult) func(w io.Writer, r *agentv1.ActionResult) error {
		return func(w io.Writer, r *agentv1.ActionResult) error { return ctl.PrintSwap(w, get(r)) }
	}
	sc.AddCommand(a.addBulkFlags(&cobra.Command{
		Use: "status <servers>", Short: "Show swap devices, usage and swappiness", Args: a.serverArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			server, _ := a.splitServer(args)
			return a.run(cmd, server, &agentv1.ActionRequest{Action: &agentv1.ActionRequest_SwapStatus{SwapStatus: &agentv1.SwapStatusRequest{}}},
				printSwap(func(r *agentv1.ActionResult) *agentv1.SwapStatusResult { return r.GetSwapStatus() }))
		},
	}))
	for _, op := range []struct {
		use, short string
		op         agentv1.SwapOperation
		sized      bool
	}{
		{"create <servers> <size>", "Create and enable the managed swapfile, e.g. 2G", agentv1.SwapOperation_SWAP_OPERATION_CREATE, true},
		{"resize <servers> <size>", "Replace the managed swapfile with one of a new size", agentv1.SwapOperation_SWAP_OPERATION_RESIZE, true},
		{"remove <servers>", "Turn off and delete the managed swapfile", agentv1.SwapOperation_SWAP_OPERATION_REMOVE, false},
	} {
		n := 1
		if op.sized {
			n = 2
		}
		sc.AddCommand(a.addBulkFlags(&cobra.Command{
			Use: op.use, Short: op.short, Args: a.serverArgs(n),
			RunE: func(cmd *cobra.Command, args []string) error {
				server, rest := a.splitServer(args)
				req := &agentv1.SwapConfigureRequest{Operation: op.op}
				if op.sized {
					mib, err := parseSize(rest[0])
					if err != nil {
						return err
					}
					req.SizeMib = mib
				}
				return a.run(cmd, server, &agentv1.ActionRequest{Action: &agentv1.ActionRequest_SwapConfigure{SwapConfigure: req}},
					printSwap(func(r *agentv1.ActionResult) *agentv1.SwapStatusResult { return r.GetSwapConfigure() }))
			},
		}))
	}
	sc.AddCommand(a.addBulkFlags(&cobra.Command{
		Use: "swappiness <servers> <0-100>", Short: "Set vm.swappiness (persisted in /etc/sysctl.d)", Args: a.serverArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			server, rest := a.splitServer(args)
			v, err := strconv.ParseUint(rest[0], 10, 32)
			if err != nil || v > 100 {
				return fmt.Errorf("swappiness must be 0-100, not %q", rest[0])
			}
			return a.run(cmd, server, &agentv1.ActionRequest{Action: &agentv1.ActionRequest_SwapSetSwappiness{SwapSetSwappiness: &agentv1.SwapSetSwappinessRequest{Swappiness: uint32(v)}}},
				printSwap(func(r *agentv1.ActionResult) *agentv1.SwapStatusResult { return r.GetSwapSetSwappiness() }))
		},
	}))
	return sc
}
