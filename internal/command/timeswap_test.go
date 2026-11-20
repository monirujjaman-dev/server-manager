package command

import (
	"strings"
	"testing"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
)

func TestTimezoneValidation(t *testing.T) {
	for _, tz := range []string{"UTC", "Europe/Berlin", "America/Argentina/Buenos_Aires", "Etc/GMT+3", "America/Port-au-Prince"} {
		if err := ValidateTimezone(tz); err != nil {
			t.Errorf("%s rejected: %v", tz, err)
		}
	}
	// Exactly 64 bytes of valid parts pass; 65 do not.
	if err := ValidateTimezone(strings.Repeat("a", 30) + "/" + strings.Repeat("b", 30) + "/ab"); err != nil {
		t.Errorf("64-byte zone rejected: %v", err)
	}
	for _, tz := range []string{strings.Repeat("a", 30) + "/" + strings.Repeat("b", 30) + "/abc", "Europe/" + strings.Repeat("x", 31),
		"Europe/Berlin\x00", "+0300", "Europe/+x", "", "/etc/passwd", "../../etc/shadow", "Europe/../../x", "Europe//Berlin", "Europe/Berlin/", ".hidden",
		"a/b/c/d", "Europe/Berlin\n", "-x", "Europe/Ber lin", strings.Repeat("a", 65)} {
		if err := ValidateTimezone(tz); err == nil {
			t.Errorf("%q accepted", tz)
		}
	}
}

func TestTimeSwapActions(t *testing.T) {
	swap := func(op agentv1.SwapOperation, mib uint32) *agentv1.ActionRequest {
		return &agentv1.ActionRequest{Action: &agentv1.ActionRequest_SwapConfigure{SwapConfigure: &agentv1.SwapConfigureRequest{Operation: op, SizeMib: mib}}}
	}
	swappiness := func(v uint32) *agentv1.ActionRequest {
		return &agentv1.ActionRequest{Action: &agentv1.ActionRequest_SwapSetSwappiness{SwapSetSwappiness: &agentv1.SwapSetSwappinessRequest{Swappiness: v}}}
	}
	tz := &agentv1.ActionRequest{Action: &agentv1.ActionRequest_TimeSetTimezone{TimeSetTimezone: &agentv1.TimeSetTimezoneRequest{Timezone: "UTC"}}}
	for _, ok := range []*agentv1.ActionRequest{
		tz, swap(agentv1.SwapOperation_SWAP_OPERATION_CREATE, 2048), swap(agentv1.SwapOperation_SWAP_OPERATION_RESIZE, MaxSwapMiB),
		swap(agentv1.SwapOperation_SWAP_OPERATION_REMOVE, 0), swappiness(0), swappiness(100),
	} {
		if err := Validate(ok); err != nil {
			t.Errorf("%v rejected: %v", ok, err)
		}
	}
	for name, bad := range map[string]*agentv1.ActionRequest{
		"too small":        swap(agentv1.SwapOperation_SWAP_OPERATION_CREATE, MinSwapMiB-1),
		"too big":          swap(agentv1.SwapOperation_SWAP_OPERATION_RESIZE, MaxSwapMiB+1),
		"no op":            swap(0, 1024),
		"unknown op":       swap(9, 1024),
		"size on remove":   swap(agentv1.SwapOperation_SWAP_OPERATION_REMOVE, 1024),
		"swappiness 101":   swappiness(101),
		"bad timezone":     {Action: &agentv1.ActionRequest_TimeSetTimezone{TimeSetTimezone: &agentv1.TimeSetTimezoneRequest{Timezone: "../x"}}},
	} {
		if Validate(bad) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for req, want := range map[*agentv1.ActionRequest]Info{
		tz: {Name: "time.set_timezone", Risk: RiskLow, Privileged: true},
		swap(agentv1.SwapOperation_SWAP_OPERATION_REMOVE, 0): {Name: "swap.configure", Risk: RiskMedium, Privileged: true},
		swappiness(10): {Name: "swap.set_swappiness", Risk: RiskMedium, Privileged: true},
		{Action: &agentv1.ActionRequest_TimeSetNtp{TimeSetNtp: &agentv1.TimeSetNTPRequest{Enabled: true}}}:  {Name: "time.set_ntp", Risk: RiskLow, Privileged: true},
		{Action: &agentv1.ActionRequest_TimeSetNtp{TimeSetNtp: &agentv1.TimeSetNTPRequest{Enabled: false}}}: {Name: "time.set_ntp", Risk: RiskMedium, Privileged: true},
		{Action: &agentv1.ActionRequest_SwapStatus{SwapStatus: &agentv1.SwapStatusRequest{}}}: {Name: "swap.status", Risk: RiskRead},
		{Action: &agentv1.ActionRequest_TimeStatus{TimeStatus: &agentv1.TimeStatusRequest{}}}: {Name: "time.status", Risk: RiskRead},
	} {
		if got, _ := Describe(req); got != want {
			t.Errorf("Describe = %+v, want %+v", got, want)
		}
	}
}
