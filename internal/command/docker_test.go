package command

import (
	"strings"
	"testing"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
)

func dockerCtl(c *agentv1.DockerContainerControlRequest) *agentv1.ActionRequest {
	return &agentv1.ActionRequest{Action: &agentv1.ActionRequest_DockerContainerControl{DockerContainerControl: c}}
}

func dockerPrune(p *agentv1.DockerPruneRequest) *agentv1.ActionRequest {
	return &agentv1.ActionRequest{Action: &agentv1.ActionRequest_DockerPrune{DockerPrune: p}}
}

const (
	opStart   = agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_START
	opStop    = agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_STOP
	opRestart = agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_RESTART
	opRemove  = agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_REMOVE
)

func TestDockerRisk(t *testing.T) {
	for _, tc := range []struct {
		req  *agentv1.ActionRequest
		name string
		risk Risk
	}{
		{&agentv1.ActionRequest{Action: &agentv1.ActionRequest_DockerContainerList{DockerContainerList: &agentv1.DockerContainerListRequest{}}}, "docker.list", RiskRead},
		{&agentv1.ActionRequest{Action: &agentv1.ActionRequest_DockerLogs{DockerLogs: &agentv1.DockerLogsRequest{}}}, "docker.logs", RiskRead},
		{&agentv1.ActionRequest{Action: &agentv1.ActionRequest_DockerStats{DockerStats: &agentv1.DockerStatsRequest{}}}, "docker.stats", RiskRead},
		{&agentv1.ActionRequest{Action: &agentv1.ActionRequest_DockerImageList{DockerImageList: &agentv1.DockerImageListRequest{}}}, "docker.images", RiskRead},
		{&agentv1.ActionRequest{Action: &agentv1.ActionRequest_DockerVolumeList{DockerVolumeList: &agentv1.DockerVolumeListRequest{}}}, "docker.volumes", RiskRead},
		{&agentv1.ActionRequest{Action: &agentv1.ActionRequest_DockerNetworkList{DockerNetworkList: &agentv1.DockerNetworkListRequest{}}}, "docker.networks", RiskRead},
		{dockerCtl(&agentv1.DockerContainerControlRequest{Operation: opStart}), "docker.start", RiskLow},
		{dockerCtl(&agentv1.DockerContainerControlRequest{Operation: opRestart}), "docker.restart", RiskLow},
		{dockerCtl(&agentv1.DockerContainerControlRequest{Operation: opStop}), "docker.stop", RiskMedium},
		{dockerCtl(&agentv1.DockerContainerControlRequest{Operation: opRemove}), "docker.remove", RiskHigh},
		{dockerCtl(&agentv1.DockerContainerControlRequest{Operation: opRemove, RemoveVolumes: true}), "docker.remove", RiskCritical},
		// Unknown values must never rate below the worst real case.
		{dockerCtl(&agentv1.DockerContainerControlRequest{Operation: 99}), "docker.remove", RiskCritical},
		{dockerCtl(&agentv1.DockerContainerControlRequest{}), "docker.remove", RiskCritical},
		{dockerPrune(&agentv1.DockerPruneRequest{Target: 42}), "docker.prune", RiskCritical},
		{dockerPrune(&agentv1.DockerPruneRequest{}), "docker.prune", RiskCritical},
		{dockerPrune(&agentv1.DockerPruneRequest{Target: agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_IMAGES}), "docker.prune", RiskMedium},
		{dockerPrune(&agentv1.DockerPruneRequest{Target: agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_NETWORKS}), "docker.prune", RiskMedium},
		{dockerPrune(&agentv1.DockerPruneRequest{Target: agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_BUILD_CACHE}), "docker.prune", RiskMedium},
		// Pruning is never rated below removing one of the objects it deletes.
		{dockerPrune(&agentv1.DockerPruneRequest{Target: agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_CONTAINERS}), "docker.prune", RiskHigh},
		{dockerPrune(&agentv1.DockerPruneRequest{Target: agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_IMAGES, AllImages: true}), "docker.prune", RiskHigh},
		{dockerPrune(&agentv1.DockerPruneRequest{Target: agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_VOLUMES}), "docker.prune", RiskCritical},
	} {
		info, err := Describe(tc.req)
		if err != nil {
			t.Fatal(err)
		}
		if info.Name != tc.name || info.Risk != tc.risk || !info.Privileged {
			t.Errorf("Describe = %+v, want %s/%s privileged", info, tc.name, tc.risk)
		}
	}
}

func TestDockerValidate(t *testing.T) {
	good := map[string]*agentv1.ActionRequest{
		"start by name":     dockerCtl(&agentv1.DockerContainerControlRequest{Container: "web_app-1.blue", Operation: opStart}),
		"stop by id prefix": dockerCtl(&agentv1.DockerContainerControlRequest{Container: "3f2a9c", Operation: opStop, TimeoutSeconds: 30}),
		"remove forced":     dockerCtl(&agentv1.DockerContainerControlRequest{Container: "web", Operation: opRemove, Force: true, RemoveVolumes: true}),
		"logs":              {Action: &agentv1.ActionRequest_DockerLogs{DockerLogs: &agentv1.DockerLogsRequest{Container: "web", Tail: 500, SinceSeconds: 3600}}},
		"stats all":         {Action: &agentv1.ActionRequest_DockerStats{DockerStats: &agentv1.DockerStatsRequest{}}},
		"prune all images":  dockerPrune(&agentv1.DockerPruneRequest{Target: agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_IMAGES, AllImages: true}),
		"prune named vols":  dockerPrune(&agentv1.DockerPruneRequest{Target: agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_VOLUMES, AllVolumes: true}),
	}
	for name, req := range good {
		if err := Validate(req); err != nil {
			t.Errorf("%s rejected: %v", name, err)
		}
	}
	bad := map[string]*agentv1.ActionRequest{
		"empty container":    dockerCtl(&agentv1.DockerContainerControlRequest{Operation: opStart}),
		"path traversal":     dockerCtl(&agentv1.DockerContainerControlRequest{Container: "../../images/x", Operation: opStart}),
		"query injection":    dockerCtl(&agentv1.DockerContainerControlRequest{Container: "web?force=1", Operation: opRemove}),
		"leading slash":      dockerCtl(&agentv1.DockerContainerControlRequest{Container: "/web", Operation: opStart}),
		"leading dash":       dockerCtl(&agentv1.DockerContainerControlRequest{Container: "-web", Operation: opStart}),
		"trailing newline":   dockerCtl(&agentv1.DockerContainerControlRequest{Container: "web\n", Operation: opStart}),
		"nul byte":           dockerCtl(&agentv1.DockerContainerControlRequest{Container: "web\x00x", Operation: opStart}),
		"space":              dockerCtl(&agentv1.DockerContainerControlRequest{Container: "web app", Operation: opStart}),
		"escaped slash":      dockerCtl(&agentv1.DockerContainerControlRequest{Container: "a%2f..", Operation: opStart}),
		"dot dot":            dockerCtl(&agentv1.DockerContainerControlRequest{Container: "..", Operation: opStart}),
		"unicode":            dockerCtl(&agentv1.DockerContainerControlRequest{Container: "wéb", Operation: opStart}),
		"too long":           dockerCtl(&agentv1.DockerContainerControlRequest{Container: strings.Repeat("a", 129), Operation: opStart}),
		"no operation":       dockerCtl(&agentv1.DockerContainerControlRequest{Container: "web"}),
		"unknown operation":  dockerCtl(&agentv1.DockerContainerControlRequest{Container: "web", Operation: 99}),
		"force on stop":      dockerCtl(&agentv1.DockerContainerControlRequest{Container: "web", Operation: opStop, Force: true}),
		"volumes on start":   dockerCtl(&agentv1.DockerContainerControlRequest{Container: "web", Operation: opStart, RemoveVolumes: true}),
		"timeout on remove":  dockerCtl(&agentv1.DockerContainerControlRequest{Container: "web", Operation: opRemove, TimeoutSeconds: 5}),
		"timeout too long":   dockerCtl(&agentv1.DockerContainerControlRequest{Container: "web", Operation: opStop, TimeoutSeconds: 91}),
		"logs no container":  {Action: &agentv1.ActionRequest_DockerLogs{DockerLogs: &agentv1.DockerLogsRequest{}}},
		"logs huge tail":     {Action: &agentv1.ActionRequest_DockerLogs{DockerLogs: &agentv1.DockerLogsRequest{Container: "web", Tail: 501}}},
		"logs since":         {Action: &agentv1.ActionRequest_DockerLogs{DockerLogs: &agentv1.DockerLogsRequest{Container: "web", SinceSeconds: maxLogSince + 1}}},
		"stats bad ref":      {Action: &agentv1.ActionRequest_DockerStats{DockerStats: &agentv1.DockerStatsRequest{Container: "a b"}}},
		"prune no target":    dockerPrune(&agentv1.DockerPruneRequest{}),
		"prune bad target":   dockerPrune(&agentv1.DockerPruneRequest{Target: 42}),
		"all_images on vols": dockerPrune(&agentv1.DockerPruneRequest{Target: agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_VOLUMES, AllImages: true}),
		"all_volumes on img": dockerPrune(&agentv1.DockerPruneRequest{Target: agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_IMAGES, AllVolumes: true}),
	}
	for name, req := range bad {
		if err := Validate(req); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
