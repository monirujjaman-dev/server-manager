package modules

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
)

// Systemd is the part of systemd the modules use; tests provide a fake.
type Systemd interface {
	ListServices(ctx context.Context) ([]*agentv1.ServiceUnit, error)
	Control(ctx context.Context, unit string, op agentv1.ServiceOperation) error
	Unit(ctx context.Context, unit string) (*agentv1.ServiceUnit, error)
}

// ListServices returns service units matching the optional filter, sorted by name.
func ListServices(ctx context.Context, sd Systemd, req *agentv1.ServiceListRequest) (*agentv1.ServiceListResult, error) {
	units, err := sd.ListServices(ctx)
	if err != nil {
		return nil, err
	}
	filter := strings.ToLower(req.GetFilter())
	out := units[:0]
	for _, u := range units {
		if filter == "" || strings.Contains(strings.ToLower(u.GetName()), filter) {
			out = append(out, u)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetName() < out[j].GetName() })
	return &agentv1.ServiceListResult{Units: out}, nil
}

// ControlService runs a start/stop/restart/reload/enable/disable and returns the unit's
// state afterwards. Unknown units are refused rather than created.
func ControlService(ctx context.Context, sd Systemd, req *agentv1.ServiceControlRequest) (*agentv1.ServiceControlResult, error) {
	before, err := sd.Unit(ctx, req.GetUnit())
	if err != nil {
		return nil, err
	}
	if before.GetLoadState() == "not-found" {
		return nil, fmt.Errorf("unit %s not found", req.GetUnit())
	}
	if err := sd.Control(ctx, req.GetUnit(), req.GetOperation()); err != nil {
		return nil, err
	}
	after, err := sd.Unit(ctx, req.GetUnit())
	if err != nil {
		return nil, err
	}
	return &agentv1.ServiceControlResult{Unit: after}, nil
}

// DBusSystemd talks to systemd over the system D-Bus.
type DBusSystemd struct{}

func (DBusSystemd) conn(ctx context.Context) (*dbus.Conn, error) {
	c, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("connect to systemd: %w", err)
	}
	return c, nil
}

// ListServices implements Systemd.
func (d DBusSystemd) ListServices(ctx context.Context) ([]*agentv1.ServiceUnit, error) {
	c, err := d.conn(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	units, err := c.ListUnitsByPatternsContext(ctx, nil, []string{"*.service"})
	if err != nil {
		return nil, err
	}
	fileState := map[string]string{}
	if files, err := c.ListUnitFilesByPatternsContext(ctx, nil, []string{"*.service"}); err == nil {
		for _, f := range files {
			fileState[baseName(f.Path)] = f.Type
		}
	}
	out := make([]*agentv1.ServiceUnit, 0, len(units))
	for _, u := range units {
		out = append(out, &agentv1.ServiceUnit{
			Name: u.Name, Description: u.Description, LoadState: u.LoadState,
			ActiveState: u.ActiveState, SubState: u.SubState, UnitFileState: fileState[u.Name],
		})
	}
	return out, nil
}

// Unit implements Systemd.
func (d DBusSystemd) Unit(ctx context.Context, unit string) (*agentv1.ServiceUnit, error) {
	c, err := d.conn(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	units, err := c.ListUnitsByNamesContext(ctx, []string{unit})
	if err != nil {
		return nil, err
	}
	if len(units) == 0 {
		return &agentv1.ServiceUnit{Name: unit, LoadState: "not-found"}, nil
	}
	u := units[0]
	state := ""
	if p, err := c.GetUnitPropertyContext(ctx, unit, "UnitFileState"); err == nil {
		state = strings.Trim(p.Value.String(), `"`)
	}
	return &agentv1.ServiceUnit{
		Name: u.Name, Description: u.Description, LoadState: u.LoadState,
		ActiveState: u.ActiveState, SubState: u.SubState, UnitFileState: state,
	}, nil
}

// Control implements Systemd. Job-based operations wait up to 90 s for systemd.
func (d DBusSystemd) Control(ctx context.Context, unit string, op agentv1.ServiceOperation) error {
	c, err := d.conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	done := make(chan string, 1)
	switch op {
	case agentv1.ServiceOperation_SERVICE_OPERATION_START:
		_, err = c.StartUnitContext(ctx, unit, "replace", done)
	case agentv1.ServiceOperation_SERVICE_OPERATION_STOP:
		_, err = c.StopUnitContext(ctx, unit, "replace", done)
	case agentv1.ServiceOperation_SERVICE_OPERATION_RESTART:
		_, err = c.RestartUnitContext(ctx, unit, "replace", done)
	case agentv1.ServiceOperation_SERVICE_OPERATION_RELOAD:
		_, err = c.ReloadUnitContext(ctx, unit, "replace", done)
	case agentv1.ServiceOperation_SERVICE_OPERATION_ENABLE:
		if _, _, err = c.EnableUnitFilesContext(ctx, []string{unit}, false, false); err == nil {
			err = c.ReloadContext(ctx)
		}
		return err
	case agentv1.ServiceOperation_SERVICE_OPERATION_DISABLE:
		if _, err = c.DisableUnitFilesContext(ctx, []string{unit}, false); err == nil {
			err = c.ReloadContext(ctx)
		}
		return err
	default:
		return errors.New("unsupported operation")
	}
	if err != nil {
		return err
	}
	select {
	case res := <-done:
		if res != "done" {
			return fmt.Errorf("systemd job finished with %q", res)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("timed out waiting for systemd: %w", ctx.Err())
	}
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
