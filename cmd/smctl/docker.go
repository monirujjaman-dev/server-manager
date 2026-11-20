package main

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/internal/command"
	"github.com/monirujjaman-dev/server-manager/internal/ctl"
)

func dockerReq(r any) *agentv1.ActionRequest {
	switch r := r.(type) {
	case *agentv1.DockerContainerListRequest:
		return &agentv1.ActionRequest{Action: &agentv1.ActionRequest_DockerContainerList{DockerContainerList: r}}
	case *agentv1.DockerContainerControlRequest:
		return &agentv1.ActionRequest{Action: &agentv1.ActionRequest_DockerContainerControl{DockerContainerControl: r}}
	case *agentv1.DockerLogsRequest:
		return &agentv1.ActionRequest{Action: &agentv1.ActionRequest_DockerLogs{DockerLogs: r}}
	case *agentv1.DockerStatsRequest:
		return &agentv1.ActionRequest{Action: &agentv1.ActionRequest_DockerStats{DockerStats: r}}
	case *agentv1.DockerImageListRequest:
		return &agentv1.ActionRequest{Action: &agentv1.ActionRequest_DockerImageList{DockerImageList: r}}
	case *agentv1.DockerVolumeListRequest:
		return &agentv1.ActionRequest{Action: &agentv1.ActionRequest_DockerVolumeList{DockerVolumeList: r}}
	case *agentv1.DockerNetworkListRequest:
		return &agentv1.ActionRequest{Action: &agentv1.ActionRequest_DockerNetworkList{DockerNetworkList: r}}
	case *agentv1.DockerPruneRequest:
		return &agentv1.ActionRequest{Action: &agentv1.ActionRequest_DockerPrune{DockerPrune: r}}
	}
	panic(fmt.Sprintf("unknown docker request %T", r))
}

// followInterval paces `docker logs --follow`; every poll is a signed, audited job.
const followInterval = 5 * time.Second

var pruneTargets = map[string]agentv1.DockerPruneTarget{
	"containers":  agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_CONTAINERS,
	"images":      agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_IMAGES,
	"networks":    agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_NETWORKS,
	"volumes":     agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_VOLUMES,
	"build-cache": agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_BUILD_CACHE,
}

func dockerCommand(a *app) *cobra.Command {
	docker := &cobra.Command{Use: "docker", Short: "Manage Docker containers, images, volumes and networks"}

	var all bool
	ps := a.addBulkFlags(&cobra.Command{
		Use: "ps <servers>", Aliases: []string{"list"}, Short: "List containers", Args: a.serverArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			server, _ := a.splitServer(args)
			return a.run(cmd, server, dockerReq(&agentv1.DockerContainerListRequest{All: all}), ctl.PrintContainers)
		},
	})
	ps.Flags().BoolVar(&all, "stopped", false, "also list containers that are not running")
	docker.AddCommand(ps)

	var timeout time.Duration
	for _, op := range []struct {
		name, verb string
		op         agentv1.DockerContainerOperation
	}{
		{"start", "started", agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_START},
		{"stop", "stopped", agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_STOP},
		{"restart", "restarted", agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_RESTART},
	} {
		c := a.addBulkFlags(&cobra.Command{
			Use: op.name + " <servers> <container>", Short: capitalize(op.name) + " a container",
			Args: a.serverArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				server, rest := a.splitServer(args)
				req := &agentv1.DockerContainerControlRequest{Container: rest[0], Operation: op.op}
				if op.op != agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_START {
					if timeout < 0 || timeout > command.MaxDockerStopTimeout*time.Second {
						return fmt.Errorf("--time must be between 0 and %ds", command.MaxDockerStopTimeout)
					}
					req.TimeoutSeconds = uint32(timeout.Seconds())
				}
				return a.run(cmd, server, dockerReq(req), ctl.PrintContainer(op.verb))
			},
		})
		if op.op != agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_START {
			c.Flags().DurationVarP(&timeout, "time", "t", 0, "wait this long before killing the container (default: Docker's, max 90s)")
		}
		docker.AddCommand(c)
	}

	var force, volumes bool
	rm := &cobra.Command{
		Use: "rm <server> <container>", Short: "Remove a container (admin, step-up)", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runOne(cmd, args[0], dockerReq(&agentv1.DockerContainerControlRequest{
				Container: args[1], Operation: agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_REMOVE,
				Force: force, RemoveVolumes: volumes,
			}), ctl.PrintContainer("removed"))
		},
	}
	rm.Flags().BoolVarP(&force, "force", "f", false, "also remove a running container")
	rm.Flags().BoolVarP(&volumes, "volumes", "v", false, "also remove its anonymous volumes (critical: owner, step-up)")
	docker.AddCommand(rm)

	var tail uint32
	var since time.Duration
	var follow bool
	logs := &cobra.Command{
		Use: "logs <server> <container>", Short: "Show a container's logs", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if since < 0 || since > 30*24*time.Hour {
				return errors.New("--since must be between 0 and 720h")
			}
			req := &agentv1.DockerLogsRequest{Container: args[1], Tail: tail, SinceSeconds: uint32(since.Seconds())}
			var last time.Time // newest line printed so far
			for {
				polled := time.Now()
				err := a.runOne(cmd, args[0], dockerReq(req), func(w io.Writer, res *agentv1.ActionResult) error {
					lines := res.GetDockerLogs().GetLines()
					// When following, skip what was already printed (Docker's since has
					// one-second resolution, so the last second comes back again).
					fresh := lines[:0]
					for _, l := range lines {
						if last.IsZero() || l.GetTime().AsTime().After(last) {
							fresh = append(fresh, l)
						}
					}
					if len(fresh) > 0 {
						last = fresh[len(fresh)-1].GetTime().AsTime()
					} else if last.IsZero() {
						last = polled.Add(-time.Second)
					}
					res.GetDockerLogs().Lines = fresh
					return ctl.PrintDockerLogs(w, res)
				})
				if err != nil || !follow {
					return err
				}
				select {
				case <-cmd.Context().Done():
					return nil
				case <-time.After(followInterval):
				}
				req.Tail = 500
				req.SinceSeconds = uint32(max(time.Since(last).Seconds(), 1)) + 1
			}
		},
	}
	logs.Flags().Uint32VarP(&tail, "lines", "n", 100, "number of recent lines (max 500)")
	logs.Flags().DurationVar(&since, "since", 0, "only lines newer than this, e.g. 1h")
	logs.Flags().BoolVarP(&follow, "follow", "f", false, "keep printing new lines (polls every 5 s; each poll is an audited job)")
	docker.AddCommand(logs)

	stats := a.addBulkFlags(&cobra.Command{
		Use: "stats <servers> [container]", Short: "Show CPU, memory, network and disk use of running containers",
		Args: func(cmd *cobra.Command, args []string) error {
			if err := a.serverArgs(1)(cmd, args); err == nil {
				return nil
			}
			return a.serverArgs(2)(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			server, rest := a.splitServer(args)
			req := &agentv1.DockerStatsRequest{}
			if len(rest) == 1 {
				req.Container = rest[0]
			}
			return a.run(cmd, server, dockerReq(req), ctl.PrintDockerStats)
		},
	})
	docker.AddCommand(stats)

	for _, l := range []struct {
		use, short string
		req        any
		print      func(io.Writer, *agentv1.ActionResult) error
	}{
		{"images", "List images", &agentv1.DockerImageListRequest{}, ctl.PrintImages},
		{"volumes", "List volumes", &agentv1.DockerVolumeListRequest{}, ctl.PrintVolumes},
		{"networks", "List networks", &agentv1.DockerNetworkListRequest{}, ctl.PrintNetworks},
	} {
		docker.AddCommand(a.addBulkFlags(&cobra.Command{
			Use: l.use + " <servers>", Short: l.short, Args: a.serverArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				server, _ := a.splitServer(args)
				return a.run(cmd, server, dockerReq(l.req), l.print)
			},
		}))
	}

	var allImages, allVolumes bool
	prune := a.addBulkFlags(&cobra.Command{
		Use:   "prune <servers> containers|images|networks|volumes|build-cache",
		Short: "Remove unused Docker objects (volumes: critical, owner and step-up)",
		Args:  a.serverArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			server, rest := a.splitServer(args)
			target, ok := pruneTargets[rest[0]]
			if !ok {
				return fmt.Errorf("unknown prune target %q (containers, images, networks, volumes, build-cache)", rest[0])
			}
			return a.run(cmd, server, dockerReq(&agentv1.DockerPruneRequest{Target: target, AllImages: allImages, AllVolumes: allVolumes}), ctl.PrintPrune)
		},
	})
	prune.Flags().BoolVar(&allImages, "all-images", false, "images: remove every image without a container, not only dangling ones")
	prune.Flags().BoolVar(&allVolumes, "all-volumes", false, "volumes: also remove named volumes")
	docker.AddCommand(prune)
	return docker
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return string(s[0]-'a'+'A') + s[1:]
}
