package modules

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
)

// TestDockerRealDaemon runs against a real Docker daemon when SM_TEST_DOCKER_SOCKET
// names its socket and SM_TEST_DOCKER_CONTAINER names a running container it may stop
// and start again, e.g.
//
//	docker run -d --name sm-docker-test busybox sh -c 'while :; do echo tick; sleep 1; done'
//	SM_TEST_DOCKER_SOCKET=/var/run/docker.sock SM_TEST_DOCKER_CONTAINER=sm-docker-test go test -run RealDaemon ./internal/agent/modules/
func TestDockerRealDaemon(t *testing.T) {
	socket, name := os.Getenv("SM_TEST_DOCKER_SOCKET"), os.Getenv("SM_TEST_DOCKER_CONTAINER")
	if socket == "" || name == "" {
		t.Skip("SM_TEST_DOCKER_SOCKET and SM_TEST_DOCKER_CONTAINER not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	d := NewDocker(socket)

	list, err := d.ListContainers(ctx, &agentv1.DockerContainerListRequest{All: true})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range list.GetContainers() {
		found = found || c.GetName() == name
	}
	if !found {
		t.Fatalf("%s not in container list", name)
	}
	logs, err := d.Logs(ctx, &agentv1.DockerLogsRequest{Container: name, Tail: 5})
	if err != nil || len(logs.GetLines()) == 0 || logs.GetLines()[0].GetTime() == nil {
		t.Fatalf("logs: %v %v", logs, err)
	}
	stats, err := d.Stats(ctx, &agentv1.DockerStatsRequest{Container: name})
	if err != nil || len(stats.GetStats()) != 1 || stats.GetStats()[0].GetMemoryUsageBytes() == 0 {
		t.Fatalf("stats: %v %v", stats, err)
	}
	for _, op := range []agentv1.DockerContainerOperation{
		agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_STOP,
		agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_START,
		agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_RESTART,
	} {
		res, err := d.ControlContainer(ctx, &agentv1.DockerContainerControlRequest{Container: name, Operation: op, TimeoutSeconds: 1})
		if op == agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_START {
			res, err = d.ControlContainer(ctx, &agentv1.DockerContainerControlRequest{Container: name, Operation: op})
		}
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		want := "running"
		if op == agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_STOP {
			want = "exited"
		}
		if res.GetContainer().GetState() != want {
			t.Fatalf("%s: state %q, want %q", op, res.GetContainer().GetState(), want)
		}
	}
	for _, f := range []func() error{
		func() error { _, err := d.ListImages(ctx, &agentv1.DockerImageListRequest{}); return err },
		func() error { _, err := d.ListVolumes(ctx, &agentv1.DockerVolumeListRequest{}); return err },
		func() error { _, err := d.ListNetworks(ctx, &agentv1.DockerNetworkListRequest{}); return err },
	} {
		if err := f(); err != nil {
			t.Fatal(err)
		}
	}
	_, err = d.ControlContainer(ctx, &agentv1.DockerContainerControlRequest{
		Container: "sm-no-such-container", Operation: agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_REMOVE,
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "no such container") {
		t.Fatalf("unknown container: %v", err)
	}
}
