package server_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	operatorv1 "github.com/monirujjaman-dev/server-manager/gen/sm/operator/v1"
	"github.com/monirujjaman-dev/server-manager/internal/ctl"
	"github.com/monirujjaman-dev/server-manager/internal/pki"
	"github.com/monirujjaman-dev/server-manager/internal/server/auth"
)

type operator struct {
	email  string
	secret []byte
	step   int64 // last TOTP step used
}

func (o *operator) nextCode() string {
	now := time.Now().Unix() / 30
	if o.step < now-1 {
		o.step = now - 1
	}
	o.step++ // the server accepts one step of clock skew, and each step only once
	return auth.TOTPCode(o.secret, o.step)
}

func TestOperatorAPIAuthAndRBAC(t *testing.T) {
	cp := startControlPlane(t)
	defer cp.stop()
	ctx := context.Background()
	st := cp.srv.Store()

	// Two groups with one server each.
	for _, g := range []string{"prod", "staging"} {
		if _, err := st.CreateServerGroup(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	cp.enrollAgentInGroup(t, "web-prod", "prod")
	cp.enrollAgentInGroup(t, "web-staging", "staging")

	mkUser := func(email string, grants map[string]auth.Role) *operator {
		secret, _, _ := auth.NewTOTP(email)
		u, err := cp.srv.Auth().CreateUser(ctx, email, "", "a long password!", secret, "test")
		if err != nil {
			t.Fatal(err)
		}
		for group, role := range grants {
			if err := auth.Grant(ctx, st, u.ID, group, role, "test"); err != nil {
				t.Fatal(err)
			}
		}
		return &operator{email: email, secret: secret}
	}
	viewer := mkUser("viewer@example.com", map[string]auth.Role{"staging": auth.RoleViewer})
	op := mkUser("op@example.com", map[string]auth.Role{"staging": auth.RoleOperator})
	admin := mkUser("admin@example.com", map[string]auth.Role{"": auth.RoleAdmin})

	caFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := pki.WriteCertFile(caFile, cp.ca.Root); err != nil {
		t.Fatal(err)
	}
	apiURL := "https://" + cp.apiLn.Addr().String()
	login := func(o *operator) *ctl.Client {
		t.Helper()
		anon, err := ctl.NewClient(apiURL, caFile, "")
		if err != nil {
			t.Fatal(err)
		}
		resp, err := anon.Auth.Login(ctx, connect.NewRequest(&operatorv1.LoginRequest{Email: o.email, Password: "a long password!", TotpCode: o.nextCode()}))
		if err != nil {
			t.Fatalf("login %s: %v", o.email, err)
		}
		c, err := ctl.NewClient(apiURL, caFile, resp.Msg.GetToken())
		if err != nil {
			t.Fatal(err)
		}
		c.StepUp = func() (string, error) { return o.nextCode(), nil }
		return c
	}
	sysinfo := &agentv1.ActionRequest{Action: &agentv1.ActionRequest_SystemInfo{SystemInfo: &agentv1.SystemInfoRequest{}}}
	restart := &agentv1.ActionRequest{Action: &agentv1.ActionRequest_ServiceControl{ServiceControl: &agentv1.ServiceControlRequest{
		Unit: "nginx.service", Operation: agentv1.ServiceOperation_SERVICE_OPERATION_RESTART,
	}}}
	run := func(c *ctl.Client, server string, req *agentv1.ActionRequest) (*operatorv1.Job, error) {
		resp, err := c.Action.Run(ctx, connect.NewRequest(&operatorv1.RunRequest{Server: server, Request: req, WaitSeconds: 1}))
		if err != nil {
			return nil, err
		}
		return resp.Msg.GetJob(), nil
	}

	t.Run("no session, bad token and wrong code are rejected", func(t *testing.T) {
		anon, _ := ctl.NewClient(apiURL, caFile, "")
		if _, err := anon.Fleet.ListServers(ctx, connect.NewRequest(&operatorv1.ListServersRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("anonymous: %v", err)
		}
		forged, _ := ctl.NewClient(apiURL, caFile, auth.TokenPrefix+"forged")
		if _, err := forged.Fleet.ListServers(ctx, connect.NewRequest(&operatorv1.ListServersRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("forged token: %v", err)
		}
		if _, err := anon.Auth.Login(ctx, connect.NewRequest(&operatorv1.LoginRequest{Email: viewer.email, Password: "a long password!", TotpCode: "000000"})); connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("wrong code: %v", err)
		}
	})

	vc := login(viewer)
	oc := login(op)
	ac := login(admin)

	t.Run("servers are scoped to the caller's groups", func(t *testing.T) {
		resp, err := vc.Fleet.ListServers(ctx, connect.NewRequest(&operatorv1.ListServersRequest{}))
		if err != nil || len(resp.Msg.GetServers()) != 1 || resp.Msg.GetServers()[0].GetName() != "web-staging" {
			t.Fatalf("viewer sees %v, %v", resp, err)
		}
		if _, err := run(vc, "web-prod", sysinfo); connect.CodeOf(err) != connect.CodeNotFound {
			t.Fatalf("other group's server: %v", err)
		}
		resp, _ = ac.Fleet.ListServers(ctx, connect.NewRequest(&operatorv1.ListServersRequest{}))
		if len(resp.Msg.GetServers()) != 2 {
			t.Fatalf("admin sees %d servers", len(resp.Msg.GetServers()))
		}
	})

	t.Run("roles limit actions by risk", func(t *testing.T) {
		if job, err := run(vc, "web-staging", sysinfo); err != nil || job.GetAction() != "system.info" {
			t.Fatalf("viewer read: %v %v", job, err)
		}
		if _, err := run(vc, "web-staging", restart); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("viewer restart: %v", err)
		}
		if job, err := run(oc, "web-staging", restart); err != nil || job.GetRisk() != "low" {
			t.Fatalf("operator restart: %v %v", job, err) // queued; the agent is not running here
		}
	})

	t.Run("audit log needs global admin", func(t *testing.T) {
		if _, err := oc.Fleet.ListAuditEvents(ctx, connect.NewRequest(&operatorv1.ListAuditEventsRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("operator: %v", err)
		}
		resp, err := ac.Fleet.ListAuditEvents(ctx, connect.NewRequest(&operatorv1.ListAuditEventsRequest{Limit: 1000}))
		if err != nil || len(resp.Msg.GetEvents()) == 0 {
			t.Fatalf("admin: %v %v", resp, err)
		}
		found := false
		for _, e := range resp.Msg.GetEvents() {
			if e.GetAction() == "services.control" && e.GetActorId() == op.email && e.GetResult() == "requested" {
				found = true
			}
		}
		if !found {
			t.Fatal("operator's restart request not audited under their e-mail")
		}
	})

	t.Run("high-risk actions need recent MFA", func(t *testing.T) {
		// Age the admin's MFA beyond the step-up window.
		if _, err := st.Pool.Exec(ctx, "UPDATE sessions SET mfa_at = now() - interval '1 hour' WHERE user_id = (SELECT id FROM users WHERE email = $1)", admin.email); err != nil {
			t.Fatal(err)
		}
		_, err := ac.Fleet.RevokeServer(ctx, connect.NewRequest(&operatorv1.RevokeServerRequest{Server: "web-prod", Reason: "test"}))
		if !ctl.NeedsStepUp(err) {
			t.Fatalf("revoke without step-up: %v", err)
		}
		if err := ac.WithStepUp(ctx, func() error {
			_, err := ac.Fleet.RevokeServer(ctx, connect.NewRequest(&operatorv1.RevokeServerRequest{Server: "web-prod", Reason: "test"}))
			return err
		}); err != nil {
			t.Fatalf("revoke with step-up: %v", err)
		}
		if _, err := oc.Fleet.RevokeServer(ctx, connect.NewRequest(&operatorv1.RevokeServerRequest{Server: "web-staging", Reason: "x"})); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("operator revoke: %v", err)
		}
		resp, err := ac.Fleet.CreateEnrollmentToken(ctx, connect.NewRequest(&operatorv1.CreateEnrollmentTokenRequest{ServerName: "db-1"}))
		if err != nil || resp.Msg.GetPin() != cp.pin || resp.Msg.GetToken() == "" {
			t.Fatalf("enrollment token: %v %v", resp, err)
		}
	})

	t.Run("logout ends the session; disabling a user ends theirs", func(t *testing.T) {
		if _, err := vc.Auth.Logout(ctx, connect.NewRequest(&operatorv1.LogoutRequest{})); err != nil {
			t.Fatal(err)
		}
		if _, err := vc.Auth.WhoAmI(ctx, connect.NewRequest(&operatorv1.WhoAmIRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("after logout: %v", err)
		}
		u, _ := auth.FindUser(ctx, st.Queries, op.email)
		if err := auth.SetDisabled(ctx, st, u.ID, true, "test"); err != nil {
			t.Fatal(err)
		}
		_, err := oc.Auth.WhoAmI(ctx, connect.NewRequest(&operatorv1.WhoAmIRequest{}))
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("disabled user: %v", err)
		}
	})
}
