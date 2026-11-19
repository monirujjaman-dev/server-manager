package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/monirujjaman-dev/server-manager/internal/command"
	"github.com/monirujjaman-dev/server-manager/internal/server/secretbox"
	"github.com/monirujjaman-dev/server-manager/internal/server/store"
	"github.com/monirujjaman-dev/server-manager/internal/server/store/db"
	"github.com/monirujjaman-dev/server-manager/internal/server/store/storetest"
)

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword("correct horse battery", h) || VerifyPassword("wrong", h) || VerifyPassword("x", "$bcrypt$...") {
		t.Fatal("verify")
	}
	if CheckPassword("short") == nil || CheckPassword("long enough pw") != nil {
		t.Fatal("policy")
	}
}

func TestTOTPRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	// RFC 6238 Appendix B (SHA1, 8 digits), truncated to the last 6 digits.
	for ts, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"} {
		if got := TOTPCode(secret, ts/30); got != want {
			t.Errorf("t=%d: %s, want %s", ts, got, want)
		}
	}
	now := time.Unix(1111111109, 0)
	if step, ok := MatchTOTP(secret, "081804", now.Add(25*time.Second)); !ok || step != 1111111109/30 {
		t.Fatal("skew window")
	}
	if _, ok := MatchTOTP(secret, "081804", now.Add(2*time.Minute)); ok {
		t.Fatal("old code accepted")
	}
}

type env struct {
	st   *store.Store
	svc  *Service
	user db.User
	sec  []byte
	now  time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, _ := storetest.Open(t)
	box, _, err := secretbox.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := &env{st: st, svc: NewService(st, box, slog.New(slog.DiscardHandler)), now: time.Now()}
	e.svc.now = func() time.Time { return e.now }
	e.sec, _, _ = NewTOTP("alice@example.com")
	e.user, err = e.svc.CreateUser(context.Background(), "alice@example.com", "Alice", "a long password!", e.sec, "test")
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) code() string { return TOTPCode(e.sec, e.now.Unix()/30) }

func (e *env) login(pw, code string) (string, Principal, error) {
	ip := netip.MustParseAddr("192.0.2.1")
	return e.svc.Login(context.Background(), "ALICE@example.com", pw, code, &ip, "test")
}

func TestLoginAndSession(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tok, p, err := e.login("a long password!", e.code())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.login("a long password!", e.code()); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("reused code: %v", err)
	}
	got, err := e.svc.Authenticate(ctx, tok, nil)
	if err != nil || got.UserID != e.user.ID || got.Email != "alice@example.com" {
		t.Fatalf("authenticate: %+v %v", got, err)
	}
	if _, err := e.svc.Authenticate(ctx, tok+"x", nil); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("tampered token accepted")
	}

	// Step-up needs a new (unused) code.
	if err := e.svc.StepUp(ctx, p, e.code()); !errors.Is(err, ErrBadCode) {
		t.Fatalf("step-up with used code: %v", err)
	}
	e.now = e.now.Add(30 * time.Second)
	if err := e.svc.StepUp(ctx, p, e.code()); err != nil {
		t.Fatal(err)
	}

	// Idle timeout.
	e.now = e.now.Add(SessionIdle + time.Minute)
	if _, err := e.svc.Authenticate(ctx, tok, nil); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("idle session accepted")
	}
}

func TestLogoutAndResetRevokeSessions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tok, p, err := e.login("a long password!", e.code())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Logout(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Authenticate(ctx, tok, nil); err == nil {
		t.Fatal("session usable after logout")
	}
	e.now = e.now.Add(30 * time.Second)
	tok, _, err = e.login("a long password!", e.code())
	if err != nil {
		t.Fatal(err)
	}
	newSec, _, _ := NewTOTP("alice")
	if err := e.svc.ResetCredentials(ctx, e.user.ID, "another long password", newSec, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Authenticate(ctx, tok, nil); err == nil {
		t.Fatal("session usable after credential reset")
	}
}

func TestLoginFailuresAndLockout(t *testing.T) {
	e := newEnv(t)
	ip := netip.MustParseAddr("192.0.2.9")
	if _, _, err := e.svc.Login(context.Background(), "nobody@example.com", "x", "123456", &ip, ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown user: %v", err)
	}
	for range maxFailures {
		if _, _, err := e.login("wrong password!!", e.code()); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatal(err)
		}
	}
	// Correct credentials are refused while locked, with the same error.
	if _, _, err := e.login("a long password!", e.code()); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("locked account: %v", err)
	}
	e.now = e.now.Add(lockDuration + time.Minute)
	if _, _, err := e.login("a long password!", e.code()); err != nil {
		t.Fatalf("after lock expiry: %v", err)
	}
	if err := e.st.SetUserDisabled(context.Background(), db.SetUserDisabledParams{ID: e.user.ID, Disabled: true}); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(time.Minute)
	if _, _, err := e.login("a long password!", e.code()); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("disabled account: %v", err)
	}
}

func TestRateLimit(t *testing.T) {
	e := newEnv(t)
	var last error
	for range 12 {
		_, _, last = e.login("wrong password!!", "000000")
	}
	if !errors.Is(last, ErrRateLimited) {
		t.Fatalf("got %v", last)
	}
}

func TestGrantsAndAuthorize(t *testing.T) {
	prod, staging := uuid.New(), uuid.New()
	g := Grants{Global: RoleViewer, Groups: map[uuid.UUID]Role{staging: RoleOperator, prod: RoleViewer}}
	now := time.Now()
	fresh := Principal{MFAAt: now}
	stale := Principal{MFAAt: now.Add(-time.Hour)}
	srv := func(group *uuid.UUID) db.Server { return db.Server{Name: "s", GroupID: group} }
	cases := []struct {
		name  string
		g     Grants
		p     Principal
		group *uuid.UUID
		risk  command.Risk
		want  error
	}{
		{"viewer reads anywhere", g, stale, &prod, command.RiskRead, nil},
		{"viewer cannot restart", g, stale, &prod, command.RiskLow, ErrForbidden},
		{"operator restarts in staging", g, stale, &staging, command.RiskMedium, nil},
		{"operator role does not cover high", g, fresh, &staging, command.RiskHigh, ErrForbidden},
		{"ungrouped server uses global role", g, stale, nil, command.RiskLow, ErrForbidden},
		{"admin high needs step-up", Grants{Global: RoleAdmin}, stale, nil, command.RiskHigh, ErrStepUpRequired},
		{"admin high with fresh MFA", Grants{Global: RoleAdmin}, fresh, nil, command.RiskHigh, nil},
		{"critical needs owner", Grants{Global: RoleAdmin}, fresh, nil, command.RiskCritical, ErrForbidden},
		{"no grants", Grants{}, fresh, nil, command.RiskRead, ErrForbidden},
	}
	for _, c := range cases {
		err := AuthorizeAction(c.g, c.p, srv(c.group), c.risk, now)
		if (c.want == nil) != (err == nil) || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}
