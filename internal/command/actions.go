package command

import (
	"errors"
	"fmt"
	"regexp"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
)

// Risk levels (see docs/ARCHITECTURE.md §4).
type Risk string

// Risk values, matching the jobs.risk CHECK constraint.
const (
	RiskRead     Risk = "read"
	RiskLow      Risk = "low"
	RiskMedium   Risk = "medium"
	RiskHigh     Risk = "high"
	RiskCritical Risk = "critical"
)

// Info describes an action.
type Info struct {
	Name       string
	Risk       Risk
	Privileged bool // executed by the privileged helper
}

var (
	unitRe       = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9@._:-]{0,250}\.service$`)
	unitSuffixRe = regexp.MustCompile(`\.[a-z]+$`)
)

// Describe returns the action's metadata.
func Describe(req *agentv1.ActionRequest) (Info, error) {
	switch a := req.GetAction().(type) {
	case *agentv1.ActionRequest_SystemInfo:
		return Info{Name: "system.info", Risk: RiskRead}, nil
	case *agentv1.ActionRequest_ServiceList:
		return Info{Name: "services.list", Risk: RiskRead}, nil
	case *agentv1.ActionRequest_ServiceControl:
		risk := RiskLow
		switch a.ServiceControl.GetOperation() {
		case agentv1.ServiceOperation_SERVICE_OPERATION_STOP, agentv1.ServiceOperation_SERVICE_OPERATION_DISABLE:
			risk = RiskMedium
		}
		return Info{Name: "services.control", Risk: risk, Privileged: true}, nil
	case *agentv1.ActionRequest_ProcessList:
		return Info{Name: "processes.list", Risk: RiskRead}, nil
	case *agentv1.ActionRequest_ProcessSignal:
		return Info{Name: "processes.signal", Risk: RiskMedium, Privileged: true}, nil
	case nil:
		return Info{}, errors.New("empty action")
	default:
		return Info{}, fmt.Errorf("unknown action %T", a)
	}
}

// Validate checks an action's parameters. It is enforced by the control plane on
// submit, by the agent and again by the privileged helper.
func Validate(req *agentv1.ActionRequest) error {
	if _, err := Describe(req); err != nil {
		return err
	}
	switch a := req.GetAction().(type) {
	case *agentv1.ActionRequest_ServiceList:
		if len(a.ServiceList.GetFilter()) > 128 {
			return errors.New("filter too long")
		}
	case *agentv1.ActionRequest_ServiceControl:
		if !unitRe.MatchString(a.ServiceControl.GetUnit()) {
			return fmt.Errorf("invalid unit name %q (want e.g. nginx.service)", a.ServiceControl.GetUnit())
		}
		if _, ok := agentv1.ServiceOperation_name[int32(a.ServiceControl.GetOperation())]; !ok ||
			a.ServiceControl.GetOperation() == agentv1.ServiceOperation_SERVICE_OPERATION_UNSPECIFIED {
			return errors.New("invalid service operation")
		}
	case *agentv1.ActionRequest_ProcessList:
		if a.ProcessList.GetLimit() > 500 {
			return errors.New("limit must be at most 500")
		}
	case *agentv1.ActionRequest_ProcessSignal:
		if a.ProcessSignal.GetPid() <= 1 {
			return errors.New("refusing to signal PID 0 or 1")
		}
		if _, ok := agentv1.Signal_name[int32(a.ProcessSignal.GetSignal())]; !ok ||
			a.ProcessSignal.GetSignal() == agentv1.Signal_SIGNAL_UNSPECIFIED {
			return errors.New("invalid signal")
		}
	}
	return nil
}

// NormalizeUnit appends ".service" when a bare name such as "nginx" is given.
func NormalizeUnit(name string) string {
	if name != "" && !unitSuffixRe.MatchString(name) {
		return name + ".service"
	}
	return name
}
