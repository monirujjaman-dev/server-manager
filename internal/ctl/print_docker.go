package ctl

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
)

// Every string below comes from the managed server's Docker daemon and goes through
// cell() (or Sanitize) before it is printed.

func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		id = id[:12]
	}
	return cell(id)
}

func ago(t time.Time, now time.Time) string {
	if t.IsZero() || t.Unix() <= 0 {
		return "-"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func ports(ps []*agentv1.DockerPort) string {
	var out []string
	for _, p := range ps {
		if p.GetPublicPort() == 0 {
			out = append(out, fmt.Sprintf("%d/%s", p.GetPrivatePort(), cell(p.GetProtocol())))
			continue
		}
		out = append(out, fmt.Sprintf("%s:%d->%d/%s", cell(p.GetIp()), p.GetPublicPort(), p.GetPrivatePort(), cell(p.GetProtocol())))
	}
	if len(out) == 0 {
		return "-"
	}
	return strings.Join(out, ", ")
}

func truncated(w io.Writer, yes bool) {
	if yes {
		_, _ = fmt.Fprintln(w, "(list truncated)")
	}
}

// PrintContainers renders docker.list.
func PrintContainers(w io.Writer, res *agentv1.ActionResult) error {
	r := res.GetDockerContainerList()
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tNAME\tIMAGE\tSTATE\tSTATUS\tCREATED\tPORTS")
	now := time.Now()
	for _, c := range r.GetContainers() {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", shortID(c.GetId()), cell(c.GetName()), cell(c.GetImage()), cell(c.GetState()),
			cell(c.GetStatus()), ago(c.GetCreated().AsTime(), now), ports(c.GetPorts()))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	truncated(w, r.GetTruncated())
	return nil
}

// PrintContainer renders the result of docker.start/stop/restart/remove.
func PrintContainer(verb string) func(io.Writer, *agentv1.ActionResult) error {
	return func(w io.Writer, res *agentv1.ActionResult) error {
		c := res.GetDockerContainerControl().GetContainer()
		if verb == "removed" {
			_, err := fmt.Fprintf(w, "removed %s (%s)\n", cell(c.GetName()), shortID(c.GetId()))
			return err
		}
		_, err := fmt.Fprintf(w, "%s %s (%s): %s\n", verb, cell(c.GetName()), shortID(c.GetId()), cell(c.GetStatus()))
		return err
	}
}

// PrintDockerLogs renders docker.logs.
func PrintDockerLogs(w io.Writer, res *agentv1.ActionResult) error {
	for _, l := range res.GetDockerLogs().GetLines() {
		ts := "-"
		if l.GetTime() != nil {
			ts = l.GetTime().AsTime().Local().Format(time.DateTime)
		}
		mark := " "
		if l.GetStream() == "stderr" {
			mark = "!"
		}
		if _, err := fmt.Fprintf(w, "%s %s %s\n", ts, mark, cell(l.GetMessage())); err != nil {
			return err
		}
	}
	return nil
}

// PrintDockerStats renders docker.stats.
func PrintDockerStats(w io.Writer, res *agentv1.ActionResult) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', tabwriter.AlignRight)
	_, _ = fmt.Fprintln(tw, "NAME\tCPU %\tMEM USAGE / LIMIT\tMEM %\tNET I/O\tBLOCK I/O\tPIDS\t")
	for _, s := range res.GetDockerStats().GetStats() {
		memPct := 0.0
		if s.GetMemoryLimitBytes() > 0 {
			memPct = float64(s.GetMemoryUsageBytes()) / float64(s.GetMemoryLimitBytes()) * 100
		}
		_, _ = fmt.Fprintf(tw, "%s\t%.1f\t%s / %s\t%.1f\t%s / %s\t%s / %s\t%d\t\n", cell(s.GetName()), s.GetCpuPercent(),
			BytesHuman(s.GetMemoryUsageBytes()), BytesHuman(s.GetMemoryLimitBytes()), memPct,
			BytesHuman(s.GetNetRxBytes()), BytesHuman(s.GetNetTxBytes()),
			BytesHuman(s.GetBlockReadBytes()), BytesHuman(s.GetBlockWriteBytes()), s.GetPids())
	}
	return tw.Flush()
}

// PrintImages renders docker.images.
func PrintImages(w io.Writer, res *agentv1.ActionResult) error {
	r := res.GetDockerImageList()
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tTAGS\tSIZE\tCREATED\tCONTAINERS")
	now := time.Now()
	for _, im := range r.GetImages() {
		tags := cell(strings.Join(im.GetTags(), ", "))
		if tags == "" {
			tags = "<none>"
		}
		used := "-"
		if im.GetContainers() >= 0 {
			used = fmt.Sprint(im.GetContainers())
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", shortID(im.GetId()), tags, BytesHuman(im.GetSizeBytes()), ago(im.GetCreated().AsTime(), now), used)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	truncated(w, r.GetTruncated())
	return nil
}

// PrintVolumes renders docker.volumes.
func PrintVolumes(w io.Writer, res *agentv1.ActionResult) error {
	r := res.GetDockerVolumeList()
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tDRIVER\tCREATED\tMOUNTPOINT")
	for _, v := range r.GetVolumes() {
		created := cell(v.GetCreatedAt())
		if t, err := time.Parse(time.RFC3339, v.GetCreatedAt()); err == nil {
			created = ago(t, time.Now())
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", cell(v.GetName()), cell(v.GetDriver()), created, cell(v.GetMountpoint()))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	truncated(w, r.GetTruncated())
	return nil
}

// PrintNetworks renders docker.networks.
func PrintNetworks(w io.Writer, res *agentv1.ActionResult) error {
	r := res.GetDockerNetworkList()
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tNAME\tDRIVER\tSCOPE\tINTERNAL")
	for _, n := range r.GetNetworks() {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%v\n", shortID(n.GetId()), cell(n.GetName()), cell(n.GetDriver()), cell(n.GetScope()), n.GetInternal())
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	truncated(w, r.GetTruncated())
	return nil
}

// PrintPrune renders docker.prune.
func PrintPrune(w io.Writer, res *agentv1.ActionResult) error {
	r := res.GetDockerPrune()
	for _, d := range r.GetDeleted() {
		_, _ = fmt.Fprintf(w, "deleted %s\n", shortIfHash(d))
	}
	if n := int(r.GetDeletedCount()) - len(r.GetDeleted()); n > 0 {
		_, _ = fmt.Fprintf(w, "... and %d more\n", n)
	}
	_, err := fmt.Fprintf(w, "%d removed, %s reclaimed\n", r.GetDeletedCount(), BytesHuman(r.GetSpaceReclaimedBytes()))
	return err
}

func shortIfHash(s string) string {
	if strings.HasPrefix(s, "sha256:") {
		return shortID(s)
	}
	return cell(s)
}
