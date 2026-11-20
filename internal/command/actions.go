package command

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

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
	anyUnitRe    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9@._:-]{0,250}\.(service|socket|timer|mount|automount|target|scope|slice|path|device|swap)$`)
	// Journal cursors are "s=...;i=...;b=..." made of hex and these separators.
	cursorRe = regexp.MustCompile(`^[a-zA-Z0-9=;_-]*$`)
)

const maxLogSince = 30 * 24 * 3600

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
	case *agentv1.ActionRequest_LogQuery:
		return Info{Name: "logs.query", Risk: RiskRead}, nil
	case *agentv1.ActionRequest_AuthLog:
		return Info{Name: "logs.auth", Risk: RiskRead}, nil
	// Docker: the socket is root-equivalent, so every action runs in the helper.
	case *agentv1.ActionRequest_DockerContainerList:
		return Info{Name: "docker.list", Risk: RiskRead, Privileged: true}, nil
	case *agentv1.ActionRequest_DockerContainerControl:
		c := a.DockerContainerControl
		switch c.GetOperation() {
		case agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_START:
			return Info{Name: "docker.start", Risk: RiskLow, Privileged: true}, nil
		case agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_RESTART:
			return Info{Name: "docker.restart", Risk: RiskLow, Privileged: true}, nil
		case agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_STOP:
			return Info{Name: "docker.stop", Risk: RiskMedium, Privileged: true}, nil
		case agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_REMOVE:
			risk := RiskHigh
			if c.GetRemoveVolumes() {
				risk = RiskCritical
			}
			return Info{Name: "docker.remove", Risk: risk, Privileged: true}, nil
		default: // refused by Validate; never rate an unknown value below the worst case
			return Info{Name: "docker.remove", Risk: RiskCritical, Privileged: true}, nil
		}
	case *agentv1.ActionRequest_DockerLogs:
		return Info{Name: "docker.logs", Risk: RiskRead, Privileged: true}, nil
	case *agentv1.ActionRequest_DockerStats:
		return Info{Name: "docker.stats", Risk: RiskRead, Privileged: true}, nil
	case *agentv1.ActionRequest_DockerImageList:
		return Info{Name: "docker.images", Risk: RiskRead, Privileged: true}, nil
	case *agentv1.ActionRequest_DockerVolumeList:
		return Info{Name: "docker.volumes", Risk: RiskRead, Privileged: true}, nil
	case *agentv1.ActionRequest_DockerNetworkList:
		return Info{Name: "docker.networks", Risk: RiskRead, Privileged: true}, nil
	case *agentv1.ActionRequest_DockerPrune:
		return Info{Name: "docker.prune", Risk: pruneRisk(a.DockerPrune), Privileged: true}, nil
	case *agentv1.ActionRequest_TimeStatus:
		return Info{Name: "time.status", Risk: RiskRead}, nil
	case *agentv1.ActionRequest_TimeSetTimezone:
		return Info{Name: "time.set_timezone", Risk: RiskLow, Privileged: true}, nil
	case *agentv1.ActionRequest_TimeSetNtp:
		// Turning NTP off lets clocks drift until signed commands (60 s validity) and
		// certificate checks start failing, so that direction asks for confirmation.
		if !a.TimeSetNtp.GetEnabled() {
			return Info{Name: "time.set_ntp", Risk: RiskMedium, Privileged: true}, nil
		}
		return Info{Name: "time.set_ntp", Risk: RiskLow, Privileged: true}, nil
	case *agentv1.ActionRequest_SwapStatus:
		return Info{Name: "swap.status", Risk: RiskRead}, nil
	case *agentv1.ActionRequest_SwapConfigure:
		return Info{Name: "swap.configure", Risk: RiskMedium, Privileged: true}, nil
	case *agentv1.ActionRequest_SwapSetSwappiness:
		return Info{Name: "swap.set_swappiness", Risk: RiskMedium, Privileged: true}, nil
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
	case *agentv1.ActionRequest_LogQuery:
		q := a.LogQuery
		if q.GetUnit() != "" && !anyUnitRe.MatchString(q.GetUnit()) {
			return fmt.Errorf("invalid unit name %q", q.GetUnit())
		}
		if q.GetLimit() > 500 || len(q.GetGrep()) > 256 || q.GetSinceSeconds() > maxLogSince {
			return errors.New("limit (max 500), grep (max 256 bytes) or since (max 30 days) out of range")
		}
		if q.MaxPriority != nil && q.GetMaxPriority() > 7 {
			return errors.New("priority must be 0-7")
		}
		if len(q.GetAfterCursor()) > 1024 || !cursorRe.MatchString(q.GetAfterCursor()) {
			return errors.New("invalid journal cursor")
		}
	case *agentv1.ActionRequest_AuthLog:
		if a.AuthLog.GetLimit() > 500 || a.AuthLog.GetSinceSeconds() > maxLogSince {
			return errors.New("limit (max 500) or since (max 30 days) out of range")
		}
	case *agentv1.ActionRequest_ProcessSignal:
		if a.ProcessSignal.GetPid() <= 1 {
			return errors.New("refusing to signal PID 0 or 1")
		}
		if _, ok := agentv1.Signal_name[int32(a.ProcessSignal.GetSignal())]; !ok ||
			a.ProcessSignal.GetSignal() == agentv1.Signal_SIGNAL_UNSPECIFIED {
			return errors.New("invalid signal")
		}
	case *agentv1.ActionRequest_DockerContainerControl:
		return validateDockerControl(a.DockerContainerControl)
	case *agentv1.ActionRequest_TimeSetTimezone:
		return ValidateTimezone(a.TimeSetTimezone.GetTimezone())
	case *agentv1.ActionRequest_SwapConfigure:
		c := a.SwapConfigure
		switch c.GetOperation() {
		case agentv1.SwapOperation_SWAP_OPERATION_CREATE, agentv1.SwapOperation_SWAP_OPERATION_RESIZE:
			if c.GetSizeMib() < MinSwapMiB || c.GetSizeMib() > MaxSwapMiB {
				return fmt.Errorf("swap size must be %d-%d MiB", MinSwapMiB, MaxSwapMiB)
			}
		case agentv1.SwapOperation_SWAP_OPERATION_REMOVE:
			if c.GetSizeMib() != 0 {
				return errors.New("size does not apply to remove")
			}
		default:
			return errors.New("invalid swap operation")
		}
	case *agentv1.ActionRequest_SwapSetSwappiness:
		if a.SwapSetSwappiness.GetSwappiness() > 100 {
			return errors.New("swappiness must be 0-100")
		}
	case *agentv1.ActionRequest_DockerLogs:
		if err := ValidateContainerRef(a.DockerLogs.GetContainer()); err != nil {
			return err
		}
		if a.DockerLogs.GetTail() > 500 || a.DockerLogs.GetSinceSeconds() > maxLogSince {
			return errors.New("tail (max 500) or since (max 30 days) out of range")
		}
	case *agentv1.ActionRequest_DockerStats:
		if c := a.DockerStats.GetContainer(); c != "" {
			return ValidateContainerRef(c)
		}
	case *agentv1.ActionRequest_DockerPrune:
		p := a.DockerPrune
		t := p.GetTarget()
		if _, ok := agentv1.DockerPruneTarget_name[int32(t)]; !ok || t == agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_UNSPECIFIED {
			return errors.New("invalid prune target")
		}
		if p.GetAllImages() && t != agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_IMAGES {
			return errors.New("all_images only applies to images")
		}
		if p.GetAllVolumes() && t != agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_VOLUMES {
			return errors.New("all_volumes only applies to volumes")
		}
	}
	return nil
}

// pruneRisk rates a prune at least as high as removing one of the objects it deletes:
// stopped containers lose their writable layer (like docker.remove, high), all unused
// images may include local builds that cannot be pulled again (high), and volumes hold
// data (critical). Unknown targets, refused by Validate, rate critical.
func pruneRisk(p *agentv1.DockerPruneRequest) Risk {
	switch p.GetTarget() {
	case agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_NETWORKS, agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_BUILD_CACHE:
		return RiskMedium
	case agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_IMAGES:
		if p.GetAllImages() {
			return RiskHigh
		}
		return RiskMedium
	case agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_CONTAINERS:
		return RiskHigh
	default:
		return RiskCritical
	}
}

// Swap size limits for the managed swapfile.
const (
	MinSwapMiB = 64
	MaxSwapMiB = 64 << 10
)

// tzPartRe is one component of an IANA time zone name ("America", "Buenos_Aires",
// "GMT+3"). No "." or "..", so a name can never leave /usr/share/zoneinfo.
var tzPartRe = regexp.MustCompile(`^[A-Za-z0-9_+-]{1,30}$`)

// ValidateTimezone checks the shape of an IANA time zone name; timedated checks that it
// exists.
func ValidateTimezone(tz string) error {
	parts := strings.Split(tz, "/")
	if len(tz) > 64 || len(parts) > 3 {
		return fmt.Errorf("invalid time zone %q", tz)
	}
	for _, p := range parts {
		if !tzPartRe.MatchString(p) || p[0] == '-' || p[0] == '+' {
			return fmt.Errorf("invalid time zone %q (want e.g. Europe/Berlin or UTC)", tz)
		}
	}
	return nil
}

// containerRe matches Docker container names and (prefixes of) hex IDs. It also keeps
// the reference safe to place in an Engine API URL path.
var containerRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

// MaxDockerStopTimeout bounds stop/restart waits so they finish within the command
// timeout.
const MaxDockerStopTimeout = 90

// ValidateContainerRef checks a container name or ID.
func ValidateContainerRef(ref string) error {
	if !containerRe.MatchString(ref) {
		return fmt.Errorf("invalid container name or ID %q", ref)
	}
	return nil
}

func validateDockerControl(c *agentv1.DockerContainerControlRequest) error {
	if err := ValidateContainerRef(c.GetContainer()); err != nil {
		return err
	}
	op := c.GetOperation()
	if _, ok := agentv1.DockerContainerOperation_name[int32(op)]; !ok ||
		op == agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_UNSPECIFIED {
		return errors.New("invalid container operation")
	}
	isRemove := op == agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_REMOVE
	if (c.GetForce() || c.GetRemoveVolumes()) && !isRemove {
		return errors.New("force and remove_volumes only apply to remove")
	}
	stopLike := op == agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_STOP ||
		op == agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_RESTART
	if c.GetTimeoutSeconds() != 0 && !stopLike {
		return errors.New("timeout only applies to stop and restart")
	}
	if c.GetTimeoutSeconds() > MaxDockerStopTimeout {
		return fmt.Errorf("timeout must be at most %d seconds", MaxDockerStopTimeout)
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
