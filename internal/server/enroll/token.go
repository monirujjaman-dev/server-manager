// Package enroll implements token-based agent enrollment and certificate renewal.
package enroll

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/monirujjaman-dev/server-manager/internal/server/audit"
	"github.com/monirujjaman-dev/server-manager/internal/server/store"
	"github.com/monirujjaman-dev/server-manager/internal/server/store/db"
)

// TokenPrefix marks enrollment tokens so they are easy to recognise in logs and to
// detect with secret scanners.
const TokenPrefix = "smenr_"

const tokenBytes = 32

// Token lifetime bounds.
const (
	DefaultTokenTTL = 15 * time.Minute
	MaxTokenTTL     = 24 * time.Hour
)

var serverNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)

// Errors returned by CreateToken.
var (
	ErrInvalidName  = errors.New("server name must be 1-63 characters of a-z, 0-9, '.' and '-', starting with a letter or digit")
	ErrNameInUse    = errors.New("server name is already used or reserved by a pending token")
	ErrGroupMissing = errors.New("server group does not exist")
	ErrTokenFormat  = errors.New("malformed enrollment token")
)

// newToken returns a random token and its SHA-256 hash.
func newToken() (string, []byte, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	tok := TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(tok))
	return tok, h[:], nil
}

// hashToken validates the token format and returns its SHA-256 hash.
func hashToken(tok string) ([]byte, error) {
	raw, ok := strings.CutPrefix(tok, TokenPrefix)
	if !ok {
		return nil, ErrTokenFormat
	}
	if b, err := base64.RawURLEncoding.DecodeString(raw); err != nil || len(b) != tokenBytes {
		return nil, ErrTokenFormat
	}
	h := sha256.Sum256([]byte(tok))
	return h[:], nil
}

// TokenRequest describes a token to create.
type TokenRequest struct {
	ServerName string
	GroupName  string // optional
	TTL        time.Duration
	Actor      string
}

// Token is a newly created enrollment token. Value is shown once and never stored.
type Token struct {
	Value      string
	ServerName string
	ExpiresAt  time.Time
}

// CreateToken creates a single-use token that enrolls one server under ServerName.
func CreateToken(ctx context.Context, st *store.Store, req TokenRequest) (Token, error) {
	if !serverNameRe.MatchString(req.ServerName) {
		return Token{}, ErrInvalidName
	}
	if req.TTL == 0 {
		req.TTL = DefaultTokenTTL
	}
	if req.TTL < time.Minute || req.TTL > MaxTokenTTL {
		return Token{}, fmt.Errorf("token TTL must be between 1m and %s", MaxTokenTTL)
	}
	if req.Actor == "" {
		return Token{}, errors.New("actor is required")
	}
	tok, hash, err := newToken()
	if err != nil {
		return Token{}, err
	}

	tx, err := st.Pool.Begin(ctx)
	if err != nil {
		return Token{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := st.WithTx(tx)

	var groupID *uuid.UUID
	if req.GroupName != "" {
		g, err := q.GetServerGroupByName(ctx, req.GroupName)
		if errors.Is(err, pgx.ErrNoRows) {
			return Token{}, ErrGroupMissing
		} else if err != nil {
			return Token{}, err
		}
		groupID = &g.ID
	}
	inUse, err := q.ServerNameInUse(ctx, req.ServerName)
	if err != nil {
		return Token{}, err
	}
	if inUse {
		return Token{}, ErrNameInUse
	}
	row, err := q.CreateEnrollmentToken(ctx, db.CreateEnrollmentTokenParams{
		TokenHash: hash, ServerName: req.ServerName, GroupID: groupID, CreatedBy: req.Actor,
		ExpiresAt: time.Now().Add(req.TTL),
	})
	if err != nil {
		return Token{}, err
	}
	if _, err := audit.Append(ctx, q, audit.Event{
		ActorType: audit.ActorUser, ActorID: req.Actor, Action: "enrollment.token_create",
		Params: map[string]string{
			"token_id": row.ID.String(), "server_name": req.ServerName, "group": req.GroupName,
			"expires_at": row.ExpiresAt.UTC().Format(time.RFC3339),
		},
		Result: audit.Succeeded,
	}); err != nil {
		return Token{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Token{}, err
	}
	return Token{Value: tok, ServerName: row.ServerName, ExpiresAt: row.ExpiresAt}, nil
}
