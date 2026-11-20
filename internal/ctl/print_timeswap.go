package ctl

import (
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
)

func onOff(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// PrintTime renders time.status and the result of time.set_*.
func PrintTime(get func(*agentv1.ActionResult) *agentv1.TimeStatusResult) func(io.Writer, *agentv1.ActionResult) error {
	return func(w io.Writer, res *agentv1.ActionResult) error {
		t := get(res)
		now := "-"
		if t.GetTime() != nil {
			loc, err := time.LoadLocation(t.GetTimezone())
			if err != nil {
				loc = time.UTC
			}
			now = t.GetTime().AsTime().In(loc).Format("2006-01-02 15:04:05 MST")
		}
		_, err := fmt.Fprintf(w, "time zone     %s\nlocal time    %s\nNTP enabled   %s\nsynchronised  %s\n",
			cell(t.GetTimezone()), now, onOff(t.GetNtpEnabled()), onOff(t.GetNtpSynchronized()))
		if err == nil && !t.GetCanNtp() && !t.GetNtpEnabled() {
			_, err = fmt.Fprintln(w, "(no NTP service is installed; install systemd-timesyncd or chrony)")
		}
		if err == nil && t.GetLocalRtc() {
			_, err = fmt.Fprintln(w, "warning: the hardware clock is kept in local time")
		}
		return err
	}
}

// PrintSwap renders swap.status and the result of swap changes.
func PrintSwap(w io.Writer, s *agentv1.SwapStatusResult) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "DEVICE\tTYPE\tSIZE\tUSED\tPRIORITY\tMANAGED")
	for _, d := range s.GetDevices() {
		managed := ""
		if d.GetPath() == s.GetManagedPath() {
			managed = "yes"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\n", cell(d.GetPath()), cell(d.GetType()), BytesHuman(d.GetSizeBytes()),
			BytesHuman(d.GetUsedBytes()), d.GetPriority(), managed)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(s.GetDevices()) == 0 {
		_, _ = fmt.Fprintln(w, "(no swap in use)")
	}
	if s.GetManagedSizeBytes() > 0 && !s.GetManagedActive() {
		_, _ = fmt.Fprintf(w, "managed swapfile %s (%s) exists but is not active\n", cell(s.GetManagedPath()), BytesHuman(s.GetManagedSizeBytes()))
	}
	_, err := fmt.Fprintf(w, "swappiness %d\n", s.GetSwappiness())
	return err
}
