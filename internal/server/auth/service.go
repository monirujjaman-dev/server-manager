package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/time/rate"

	"github.com/monirujjaman-dev/server-manager/internal/server/audit"
	"github.com/monirujjaman-dev/server-manager/internal/server/ratelimit"
	"github.com/monirujjaman-dev/server-manager/internal/server/secretbox"
	"github.com/monirujjaman-dev/server-manager/internal/server/store"
	"github.com/monirujjaman-dev/server-manager/internal/server/store/db"
)

// Session and lockout policy.
const (
	SessionLifetime = 8 * time.Hour
	SessionIdle     = 30 * time.Minute
	// StepUpWindow: high and critical actions need a TOTP check this recent.
	StepUpWindow = 5 * time.Minute
	maxFailures  = 5
	lockDuration = 15 * time.Minute
	TokenPrefix  = "smses_"
	totpIssuer   = "Server Manager"
	touchEvery   = time.Minute
)

// Errors. ErrInvalidCredentials is deliberately the only login error, so a caller
// cannot tell unknown accounts, wrong passwords, wrong codes and locked accounts apart.
var (
	ErrInvalidCredentials = errors.New("invalid email, password or code")
	ErrRateLimited        = errors.New("too many login attempts; try again later")
	ErrUnauthenticated    = errors.New("not logged in or session expired")
	ErrBadCode            = errors.New("invalid or reused code")
	ErrEmailInUse         = errors.New("a user with this e-mail already exists")
)

// Principal is an authenticated operator.
type Principal struct {
	UserID    uuid.UUID
	Email     string
	SessionID uuid.UUID
	MFAAt     time.Time
	SourceIP  *netip.Addr
}

// Actor is the audit identity of the principal.
func (p Principal) Actor() string { return p.Email }

// RecentMFA reports whether the principal passed TOTP within StepUpWindow.
func (p Principal) RecentMFA(now time.Time) bool { return now.Sub(p.MFAAt) <= StepUpWindow }

// Service authenticates operators.
type Service struct {
	st      *store.Store
	box     *secretbox.Box
	log     *slog.Logger
	limiter *ratelimit.IPLimiter
	now     func() time.Time
}

// NewService creates the service.
func NewService(st *store.Store, box *secretbox.Box, log *slog.Logger) *Service {
	return &Service{st: st, box: box, log: log, limiter: ratelimit.New(rate.Every(6*time.Second), 10), now: time.Now}
}

func totpContext(userID uuid.UUID) string { return "totp:" + userID.String() }

// NewTOTP generates a secret and its provisioning URI for account.
func NewTOTP(account string) ([]byte, string, error) {
	secret, err := NewTOTPSecret()
	if err != nil {
		return nil, "", err
	}
	return secret, ProvisioningURI(totpIssuer, account, secret), nil
}

// CreateUser stores a new local user with password and TOTP secret. Callers verify a
// code from the user's authenticator before calling, so a mistyped secret cannot lock
// the user out.
func (s *Service) CreateUser(ctx context.Context, email, name, password string, totpSecret []byte, actor string) (db.User, error) {
	email = strings.TrimSpace(email)
	if !strings.Contains(email, "@") || len(email) > 254 {
		return db.User{}, errors.New("invalid e-mail address")
	}
	if err := CheckPassword(password); err != nil {
		return db.User{}, err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return db.User{}, err
	}
	tx, err := s.st.Pool.Begin(ctx)
	if err != nil {
		return db.User{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.st.WithTx(tx)
	u, err := q.CreateUser(ctx, db.CreateUserParams{Email: email, Name: name, AuthProvider: "local", PasswordHash: &hash})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return db.User{}, ErrEmailInUse
	} else if err != nil {
		return db.User{}, err
	}
	enc, err := s.box.Seal(totpSecret, totpContext(u.ID))
	if err != nil {
		return db.User{}, err
	}
	if err := q.SetUserCredentials(ctx, db.SetUserCredentialsParams{ID: u.ID, PasswordHash: &hash, TotpSecretEnc: enc}); err != nil {
		return db.User{}, err
	}
	if _, err := audit.Append(ctx, q, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor, Action: "user.create",
		Params: map[string]string{"user_id": u.ID.String(), "email": email}, Result: audit.Succeeded,
	}); err != nil {
		return db.User{}, err
	}
	return u, tx.Commit(ctx)
}

// ResetCredentials replaces password and TOTP secret and ends all of the user's sessions.
func (s *Service) ResetCredentials(ctx context.Context, userID uuid.UUID, password string, totpSecret []byte, actor string) error {
	if err := CheckPassword(password); err != nil {
		return err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	enc, err := s.box.Seal(totpSecret, totpContext(userID))
	if err != nil {
		return err
	}
	tx, err := s.st.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.st.WithTx(tx)
	if err := q.SetUserCredentials(ctx, db.SetUserCredentialsParams{ID: userID, PasswordHash: &hash, TotpSecretEnc: enc}); err != nil {
		return err
	}
	n, err := q.RevokeUserSessions(ctx, userID)
	if err != nil {
		return err
	}
	if _, err := audit.Append(ctx, q, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor, Action: "user.reset_credentials",
		Params: map[string]string{"user_id": userID.String(), "sessions_revoked": fmt.Sprint(n)}, Result: audit.Succeeded,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Login checks password and TOTP and returns a bearer token for a new session.
func (s *Service) Login(ctx context.Context, email, password, code string, ip *netip.Addr, userAgent string) (string, Principal, error) {
	if ip != nil && !s.limiter.Allow(*ip) {
		return "", Principal{}, ErrRateLimited
	}
	u, err := s.st.GetUserByEmail(ctx, strings.TrimSpace(email))
	if errors.Is(err, pgx.ErrNoRows) {
		VerifyPassword(password, dummyHash) // same work as for a real account
		s.auditLogin(ctx, email, ip, "unknown user")
		return "", Principal{}, ErrInvalidCredentials
	} else if err != nil {
		return "", Principal{}, err
	}
	now := s.now()
	fail := func(reason string) (string, Principal, error) {
		if _, err := s.st.RecordLoginFailure(ctx, db.RecordLoginFailureParams{
			ID: u.ID, MaxFailures: maxFailures, LockSeconds: lockDuration.Seconds(),
		}); err != nil {
			s.log.Error("record login failure", "err", err)
		}
		s.auditLogin(ctx, u.Email, ip, reason)
		return "", Principal{}, ErrInvalidCredentials
	}
	hash := dummyHash
	if u.PasswordHash != nil {
		hash = *u.PasswordHash
	}
	pwOK := VerifyPassword(password, hash)
	switch {
	case u.DisabledAt != nil:
		return fail("account disabled")
	case u.LockedUntil != nil && now.Before(*u.LockedUntil):
		return fail("account locked")
	case !pwOK || u.PasswordHash == nil:
		return fail("wrong password")
	case u.TotpSecretEnc == nil:
		return fail("no MFA enrolled")
	}
	secret, err := s.box.Open(u.TotpSecretEnc, totpContext(u.ID))
	if err != nil {
		return "", Principal{}, fmt.Errorf("decrypt TOTP secret: %w", err)
	}
	step, ok := MatchTOTP(secret, code, now)
	if !ok || step <= u.TotpLastStep {
		return fail("wrong or reused code")
	}

	token, hashTok, err := newSessionToken()
	if err != nil {
		return "", Principal{}, err
	}
	tx, err := s.st.Pool.Begin(ctx)
	if err != nil {
		return "", Principal{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.st.WithTx(tx)
	// Atomic: of two concurrent logins with the same code, only one gets the step.
	if n, err := q.UseTOTPStep(ctx, db.UseTOTPStepParams{ID: u.ID, TotpLastStep: step}); err != nil {
		return "", Principal{}, err
	} else if n == 0 {
		_ = tx.Rollback(ctx)
		return fail("reused code")
	}
	if err := q.RecordLoginSuccess(ctx, db.RecordLoginSuccessParams{ID: u.ID, TotpLastStep: step}); err != nil {
		return "", Principal{}, err
	}
	if len(userAgent) > 256 {
		userAgent = userAgent[:256]
	}
	sess, err := q.CreateSession(ctx, db.CreateSessionParams{
		TokenHash: hashTok, UserID: u.ID, ExpiresAt: now.Add(SessionLifetime), SourceIP: ip, UserAgent: userAgent,
	})
	if err != nil {
		return "", Principal{}, err
	}
	if _, err := audit.Append(ctx, q, audit.Event{
		ActorType: audit.ActorUser, ActorID: u.Email, SourceIP: ip, Action: "user.login",
		Params: map[string]string{"session_id": sess.ID.String()}, Result: audit.Succeeded,
	}); err != nil {
		return "", Principal{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", Principal{}, err
	}
	return token, Principal{UserID: u.ID, Email: u.Email, SessionID: sess.ID, MFAAt: sess.MfaAt, SourceIP: ip}, nil
}

func (s *Service) auditLogin(ctx context.Context, email string, ip *netip.Addr, reason string) {
	s.log.Warn("login rejected", "email", email, "reason", reason)
	tx, err := s.st.Pool.Begin(ctx)
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if len(email) > 254 {
		email = email[:254]
	}
	if _, err := audit.Append(ctx, s.st.WithTx(tx), audit.Event{
		ActorType: audit.ActorUser, ActorID: email, SourceIP: ip, Action: "user.login",
		Params: map[string]string{"reason": reason}, Result: audit.Denied,
	}); err == nil {
		_ = tx.Commit(ctx)
	}
}

func newSessionToken() (string, []byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	tok := TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(tok))
	return tok, h[:], nil
}

// Authenticate validates a bearer token.
func (s *Service) Authenticate(ctx context.Context, token string, ip *netip.Addr) (Principal, error) {
	if !strings.HasPrefix(token, TokenPrefix) || len(token) > 128 {
		return Principal{}, ErrUnauthenticated
	}
	h := sha256.Sum256([]byte(token))
	sess, err := s.st.GetSessionByToken(ctx, h[:])
	if errors.Is(err, pgx.ErrNoRows) {
		return Principal{}, ErrUnauthenticated
	} else if err != nil {
		return Principal{}, err
	}
	now := s.now()
	if sess.RevokedAt != nil || sess.UserDisabledAt != nil || now.After(sess.ExpiresAt) || now.Sub(sess.LastSeenAt) > SessionIdle {
		return Principal{}, ErrUnauthenticated
	}
	if now.Sub(sess.LastSeenAt) > touchEvery {
		if err := s.st.TouchSession(ctx, sess.ID); err != nil {
			s.log.Warn("touch session", "err", err)
		}
	}
	return Principal{UserID: sess.UserID, Email: sess.Email, SessionID: sess.ID, MFAAt: sess.MfaAt, SourceIP: ip}, nil
}

// StepUp re-checks a TOTP code and refreshes the session's MFA time.
func (s *Service) StepUp(ctx context.Context, p Principal, code string) error {
	u, err := s.st.GetUser(ctx, p.UserID)
	if err != nil {
		return err
	}
	if u.TotpSecretEnc == nil {
		return ErrBadCode
	}
	secret, err := s.box.Open(u.TotpSecretEnc, totpContext(u.ID))
	if err != nil {
		return err
	}
	step, ok := MatchTOTP(secret, code, s.now())
	if !ok {
		return ErrBadCode
	}
	if n, err := s.st.UseTOTPStep(ctx, db.UseTOTPStepParams{ID: u.ID, TotpLastStep: step}); err != nil {
		return err
	} else if n == 0 {
		return ErrBadCode
	}
	return s.st.SessionStepUp(ctx, p.SessionID)
}

// Logout revokes the session.
func (s *Service) Logout(ctx context.Context, p Principal) error {
	return s.st.RevokeSession(ctx, p.SessionID)
}
