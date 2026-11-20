package ctl

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/internal/command"
)

func answer(s string) func(io.Writer, string) (string, error) {
	return func(w io.Writer, prompt string) (string, error) {
		_, _ = io.WriteString(w, prompt)
		return s, nil
	}
}

func TestConfirm(t *testing.T) {
	stop := Confirmation{Action: "services.stop nginx.service", Risk: command.RiskMedium, Servers: []string{"web-1"}, Expect: "web-1"}
	noPrompt := func(io.Writer, string) (string, error) {
		t.Fatal("prompted although no confirmation was needed")
		return "", nil
	}
	for _, tc := range []struct {
		name    string
		c       Confirmer
		x       Confirmation
		wantErr string
	}{
		{name: "low risk never asks", c: Confirmer{ReadLine: noPrompt}, x: Confirmation{Action: "services.restart", Risk: command.RiskLow}},
		{name: "read never asks", c: Confirmer{ReadLine: noPrompt}, x: Confirmation{Action: "system.info", Risk: command.RiskRead}},
		{name: "--yes skips the prompt", c: Confirmer{Yes: true, ReadLine: noPrompt}, x: stop},
		{name: "non-interactive needs --yes", c: Confirmer{ReadLine: noPrompt}, x: stop, wantErr: "repeat with --yes"},
		{name: "typed name confirms", c: Confirmer{Interactive: true, ReadLine: answer(" web-1 ")}, x: stop},
		{name: "y is not enough", c: Confirmer{Interactive: true, ReadLine: answer("y")}, x: stop, wantErr: "did not match"},
		{name: "other server rejected", c: Confirmer{Interactive: true, ReadLine: answer("web-2")}, x: stop, wantErr: "did not match"},
		{name: "empty rejected", c: Confirmer{Interactive: true, ReadLine: answer("")}, x: stop, wantErr: "did not match"},
		{
			name: "critical asks too", c: Confirmer{Interactive: true, ReadLine: answer("3")},
			x: Confirmation{Action: "x", Risk: command.RiskCritical, Servers: []string{"a", "b", "c"}, Expect: "3"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			tc.c.Out = &out
			err := tc.c.Confirm(tc.x)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("Confirm: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("Confirm error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestConfirmShowsTargets(t *testing.T) {
	servers := []string{"a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10", "a11", "a12"}
	var out bytes.Buffer
	err := Confirmer{Interactive: true, Out: &out, ReadLine: answer("staging")}.Confirm(Confirmation{
		Action: "services.stop nginx.service", Risk: command.RiskMedium, Servers: servers, Expect: "staging",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"MEDIUM-risk", "12 servers: a1, a2", "a10 and 2 more", `Type "staging" to confirm`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("prompt missing %q:\n%s", want, out.String())
		}
	}
	readErr := errors.New("eof")
	err = Confirmer{Interactive: true, Out: io.Discard, ReadLine: func(io.Writer, string) (string, error) { return "", readErr }}.
		Confirm(Confirmation{Risk: command.RiskHigh, Servers: []string{"x"}, Expect: "x"})
	if !errors.Is(err, readErr) {
		t.Fatalf("read error not returned: %v", err)
	}
}

func TestExpectFor(t *testing.T) {
	if got := ExpectFor(Selector{Group: "staging"}, []string{"a", "b"}); got != "staging" {
		t.Errorf("group: %q", got)
	}
	if got := ExpectFor(Selector{Group: "staging"}, []string{"a"}); got != "staging" {
		t.Errorf("group with one server: %q", got)
	}
	if got := ExpectFor(Selector{Names: []string{"a", "b"}}, []string{"a", "b"}); got != "2" {
		t.Errorf("list: %q", got)
	}
	if got := ExpectFor(Selector{All: true}, []string{"a"}); got != "a" {
		t.Errorf("all with one server: %q", got)
	}
}

func TestActionLabel(t *testing.T) {
	for _, tc := range []struct {
		req  *agentv1.ActionRequest
		want string
	}{
		{&agentv1.ActionRequest{Action: &agentv1.ActionRequest_ServiceControl{ServiceControl: &agentv1.ServiceControlRequest{
			Unit: "nginx.service", Operation: agentv1.ServiceOperation_SERVICE_OPERATION_STOP,
		}}}, "services.stop nginx.service"},
		{&agentv1.ActionRequest{Action: &agentv1.ActionRequest_ProcessSignal{ProcessSignal: &agentv1.ProcessSignalRequest{
			Pid: 42, Signal: agentv1.Signal_SIGNAL_KILL,
		}}}, "processes.signal SIGKILL to PID 42"},
		{&agentv1.ActionRequest{Action: &agentv1.ActionRequest_DockerContainerControl{DockerContainerControl: &agentv1.DockerContainerControlRequest{
			Container: "web", Operation: agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_REMOVE, Force: true, RemoveVolumes: true,
		}}}, "docker.remove web (forced, with its volumes)"},
		{&agentv1.ActionRequest{Action: &agentv1.ActionRequest_DockerPrune{DockerPrune: &agentv1.DockerPruneRequest{
			Target: agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_VOLUMES, AllVolumes: true,
		}}}, "docker.prune volumes (including named volumes)"},
		{&agentv1.ActionRequest{Action: &agentv1.ActionRequest_DockerPrune{DockerPrune: &agentv1.DockerPruneRequest{
			Target: agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_BUILD_CACHE,
		}}}, "docker.prune build-cache"},
		{&agentv1.ActionRequest{Action: &agentv1.ActionRequest_SystemInfo{SystemInfo: &agentv1.SystemInfoRequest{}}}, "system.info"},
		{&agentv1.ActionRequest{}, "unknown action"},
	} {
		if got := ActionLabel(tc.req); got != tc.want {
			t.Errorf("ActionLabel = %q, want %q", got, tc.want)
		}
	}
}
