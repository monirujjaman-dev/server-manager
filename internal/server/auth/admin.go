package auth

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/monirujjaman-dev/server-manager/internal/server/audit"
	"github.com/monirujjaman-dev/server-manager/internal/server/store"
	"github.com/monirujjaman-dev/server-manager/internal/server/store/db"
)

// ErrUserNotFound is returned when no user has the e-mail address.
var ErrUserNotFound = errors.New("user not found")

// FindUser looks a user up by e-mail.
func FindUser(ctx context.Context, q *db.Queries, email string) (db.User, error) {
	u, err := q.GetUserByEmail(ctx, email)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, ErrUserNotFound
	}
	return u, err
}

func resolveGroup(ctx context.Context, q *db.Queries, name string) (*uuid.UUID, error) {
	if name == "" {
		return nil, nil
	}
	g, err := q.GetServerGroupByName(ctx, name)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("server group does not exist")
	} else if err != nil {
		return nil, err
	}
	return &g.ID, nil
}

// Grant sets the user's role on a group ("" = all servers), audited.
func Grant(ctx context.Context, st *store.Store, userID uuid.UUID, group string, role Role, actor string) error {
	tx, err := st.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := st.WithTx(tx)
	gid, err := resolveGroup(ctx, q, group)
	if err != nil {
		return err
	}
	if _, err := q.UpsertRoleBinding(ctx, db.UpsertRoleBindingParams{UserID: userID, GroupID: gid, Role: string(role), CreatedBy: actor}); err != nil {
		return err
	}
	if _, err := audit.Append(ctx, q, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor, Action: "user.grant",
		Params: map[string]string{"user_id": userID.String(), "group": group, "role": string(role)}, Result: audit.Succeeded,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RemoveGrant deletes the user's role on a group ("" = the global role), audited.
func RemoveGrant(ctx context.Context, st *store.Store, userID uuid.UUID, group string, actor string) error {
	tx, err := st.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := st.WithTx(tx)
	gid, err := resolveGroup(ctx, q, group)
	if err != nil {
		return err
	}
	n, err := q.DeleteRoleBinding(ctx, db.DeleteRoleBindingParams{UserID: userID, GroupID: gid})
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("the user has no role there")
	}
	if _, err := audit.Append(ctx, q, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor, Action: "user.revoke_role",
		Params: map[string]string{"user_id": userID.String(), "group": group}, Result: audit.Succeeded,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// SetDisabled disables or re-enables a user; disabling ends all sessions.
func SetDisabled(ctx context.Context, st *store.Store, userID uuid.UUID, disabled bool, actor string) error {
	tx, err := st.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := st.WithTx(tx)
	if err := q.SetUserDisabled(ctx, db.SetUserDisabledParams{ID: userID, Disabled: disabled}); err != nil {
		return err
	}
	if disabled {
		if _, err := q.RevokeUserSessions(ctx, userID); err != nil {
			return err
		}
	}
	action := "user.enable"
	if disabled {
		action = "user.disable"
	}
	if _, err := audit.Append(ctx, q, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor, Action: action,
		Params: map[string]string{"user_id": userID.String()}, Result: audit.Succeeded,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
