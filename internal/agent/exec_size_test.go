package agent

import (
	"strings"
	"testing"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
)

func TestLimitResult(t *testing.T) {
	small := &agentv1.CommandResult{Id: "j1", Status: agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED}
	if limitResult(small) != small {
		t.Fatal("small result replaced")
	}
	var lines []*agentv1.DockerLogLine
	for range 1000 {
		lines = append(lines, &agentv1.DockerLogLine{Message: strings.Repeat("x", 1024)})
	}
	big := &agentv1.CommandResult{Id: "j2", Status: agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED,
		Result: &agentv1.ActionResult{Result: &agentv1.ActionResult_DockerLogs{DockerLogs: &agentv1.DockerLogsResult{Lines: lines}}}}
	got := limitResult(big)
	if got.GetId() != "j2" || got.GetStatus() != agentv1.CommandStatus_COMMAND_STATUS_FAILED ||
		got.GetResult() != nil || !strings.Contains(got.GetError(), "too large") {
		t.Fatalf("oversized result = %v", got)
	}
}
