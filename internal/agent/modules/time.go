package modules

import (
	"context"
	"fmt"
	"time"

	"github.com/godbus/dbus/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/internal/command"
)

// Timedate is the part of systemd-timedated the time module uses; tests provide a fake.
type Timedate interface {
	Status(ctx context.Context) (*agentv1.TimeStatusResult, error)
	SetTimezone(ctx context.Context, tz string) error
	SetNTP(ctx context.Context, enabled bool) error
}

// TimeStatus implements time.status.
func TimeStatus(ctx context.Context, td Timedate) (*agentv1.TimeStatusResult, error) {
	return td.Status(ctx)
}

// SetTimezone implements time.set_timezone and returns the state afterwards.
func SetTimezone(ctx context.Context, td Timedate, req *agentv1.TimeSetTimezoneRequest) (*agentv1.TimeStatusResult, error) {
	if err := command.ValidateTimezone(req.GetTimezone()); err != nil {
		return nil, err
	}
	if err := td.SetTimezone(ctx, req.GetTimezone()); err != nil {
		return nil, err
	}
	return td.Status(ctx)
}

// SetNTP implements time.set_ntp and returns the state afterwards.
func SetNTP(ctx context.Context, td Timedate, req *agentv1.TimeSetNTPRequest) (*agentv1.TimeStatusResult, error) {
	if err := td.SetNTP(ctx, req.GetEnabled()); err != nil {
		return nil, err
	}
	return td.Status(ctx)
}

// DBusTimedate talks to org.freedesktop.timedate1 on the system bus. Reading its
// properties needs no privileges; the set methods are called by the privileged helper
// (as root, so polkit allows them without interaction).
type DBusTimedate struct{}

const (
	timedateDest  = "org.freedesktop.timedate1"
	timedatePath  = dbus.ObjectPath("/org/freedesktop/timedate1")
	timedateIface = "org.freedesktop.timedate1"
)

func (DBusTimedate) object(ctx context.Context) (*dbus.Conn, dbus.BusObject, error) {
	c, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return nil, nil, fmt.Errorf("connect to the system bus: %w", err)
	}
	return c, c.Object(timedateDest, timedatePath), nil
}

// Status implements Timedate.
func (d DBusTimedate) Status(ctx context.Context) (*agentv1.TimeStatusResult, error) {
	c, obj, err := d.object(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	var props map[string]dbus.Variant
	if err := obj.CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, timedateIface).Store(&props); err != nil {
		return nil, fmt.Errorf("timedated: %w", err)
	}
	return timeStatusFromProps(props), nil
}

func timeStatusFromProps(props map[string]dbus.Variant) *agentv1.TimeStatusResult {
	str := func(k string) string { s, _ := props[k].Value().(string); return s }
	flag := func(k string) bool { b, _ := props[k].Value().(bool); return b }
	out := &agentv1.TimeStatusResult{
		Timezone: str("Timezone"), LocalRtc: flag("LocalRTC"), NtpEnabled: flag("NTP"),
		NtpSynchronized: flag("NTPSynchronized"), CanNtp: flag("CanNTP"),
	}
	if us, ok := props["TimeUSec"].Value().(uint64); ok && us > 0 {
		out.Time = timestamppb.New(time.UnixMicro(int64(min(us, uint64(1)<<62)))) //nolint:gosec // bounded
	} else {
		out.Time = timestamppb.Now()
	}
	return out
}

// SetTimezone implements Timedate.
func (d DBusTimedate) SetTimezone(ctx context.Context, tz string) error {
	c, obj, err := d.object(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	if err := obj.CallWithContext(ctx, timedateIface+".SetTimezone", 0, tz, false).Err; err != nil {
		return fmt.Errorf("set time zone %q: %w", tz, err)
	}
	return nil
}

// SetNTP implements Timedate.
func (d DBusTimedate) SetNTP(ctx context.Context, enabled bool) error {
	c, obj, err := d.object(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	if err := obj.CallWithContext(ctx, timedateIface+".SetNTP", 0, enabled, false).Err; err != nil {
		return fmt.Errorf("set NTP: %w", err)
	}
	return nil
}
