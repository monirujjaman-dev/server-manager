package ctl

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/internal/command"
)

// ErrNotConfirmed means the operator did not confirm a risky action.
var ErrNotConfirmed = errors.New("confirmation did not match; nothing was done")

// NeedsConfirmation reports whether a risk level asks for typed confirmation.
func NeedsConfirmation(risk command.Risk) bool {
	return risk != command.RiskRead && risk != command.RiskLow
}

// Confirmation describes what the operator is about to do.
type Confirmation struct {
	Action string       // e.g. "services.stop nginx.service"
	Risk   command.Risk // only medium and above prompt
	// Servers the action runs on. Expect is what must be typed: the server name for one
	// server, the group name for --group, otherwise the number of servers.
	Servers []string
	Expect  string
}

// Confirmer asks for typed confirmation of medium- and higher-risk actions.
type Confirmer struct {
	Yes         bool // --yes: confirmed in advance
	Interactive bool // standard input is a terminal
	Out         io.Writer
	ReadLine    func(w io.Writer, prompt string) (string, error)
}

// StdinIsTerminal reports whether standard input is an interactive terminal.
func StdinIsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) //nolint:gosec // file descriptors fit int
}

// Confirm returns nil if the action may go ahead.
func (c Confirmer) Confirm(x Confirmation) error {
	if !NeedsConfirmation(x.Risk) || c.Yes {
		return nil
	}
	if !c.Interactive {
		return fmt.Errorf("%s is a %s-risk action; repeat with --yes to confirm", x.Action, x.Risk)
	}
	w := c.Out
	_, _ = fmt.Fprintf(w, "%s is a %s-risk action.\n", x.Action, strings.ToUpper(string(x.Risk)))
	switch n := len(x.Servers); {
	case n == 1:
		_, _ = fmt.Fprintf(w, "It will run on %s.\n", x.Servers[0])
	case n <= 10:
		_, _ = fmt.Fprintf(w, "It will run on %d servers: %s.\n", n, strings.Join(x.Servers, ", "))
	default:
		_, _ = fmt.Fprintf(w, "It will run on %d servers: %s and %d more.\n", n, strings.Join(x.Servers[:10], ", "), n-10)
	}
	got, err := c.ReadLine(w, fmt.Sprintf("Type %q to confirm: ", x.Expect))
	if err != nil {
		return err
	}
	if strings.TrimSpace(got) != x.Expect {
		return ErrNotConfirmed
	}
	return nil
}

// ActionLabel names an action with its main parameter, e.g. "services.stop nginx.service".
func ActionLabel(req *agentv1.ActionRequest) string {
	info, err := command.Describe(req)
	if err != nil {
		return "unknown action"
	}
	switch a := req.GetAction().(type) {
	case *agentv1.ActionRequest_ServiceControl:
		op := strings.ToLower(strings.TrimPrefix(a.ServiceControl.GetOperation().String(), "SERVICE_OPERATION_"))
		return "services." + op + " " + a.ServiceControl.GetUnit()
	case *agentv1.ActionRequest_ProcessSignal:
		sig := strings.TrimPrefix(a.ProcessSignal.GetSignal().String(), "SIGNAL_")
		return fmt.Sprintf("processes.signal SIG%s to PID %d", sig, a.ProcessSignal.GetPid())
	case *agentv1.ActionRequest_DockerContainerControl:
		c := a.DockerContainerControl
		label := info.Name + " " + c.GetContainer()
		switch {
		case c.GetForce() && c.GetRemoveVolumes():
			label += " (forced, with its volumes)"
		case c.GetForce():
			label += " (forced)"
		case c.GetRemoveVolumes():
			label += " (with its volumes)"
		}
		return label
	case *agentv1.ActionRequest_SwapConfigure:
		c := a.SwapConfigure
		op := strings.ToLower(strings.TrimPrefix(c.GetOperation().String(), "SWAP_OPERATION_"))
		if c.GetSizeMib() > 0 {
			return fmt.Sprintf("swap.%s %d MiB", op, c.GetSizeMib())
		}
		return "swap." + op
	case *agentv1.ActionRequest_SwapSetSwappiness:
		return fmt.Sprintf("swap.set_swappiness %d", a.SwapSetSwappiness.GetSwappiness())
	case *agentv1.ActionRequest_TimeSetTimezone:
		return info.Name + " " + a.TimeSetTimezone.GetTimezone()
	case *agentv1.ActionRequest_DockerPrune:
		p := a.DockerPrune
		label := info.Name + " " + strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(p.GetTarget().String(), "DOCKER_PRUNE_TARGET_"), "_", "-"))
		switch {
		case p.GetAllImages():
			label += " (all unused images)"
		case p.GetAllVolumes():
			label += " (including named volumes)"
		}
		return label
	}
	return info.Name
}

// ExpectFor returns what the operator must type for a selector and its targets.
func ExpectFor(sel Selector, servers []string) string {
	switch {
	case sel.Group != "":
		return sel.Group
	case len(servers) == 1:
		return servers[0]
	default:
		return strconv.Itoa(len(servers))
	}
}
