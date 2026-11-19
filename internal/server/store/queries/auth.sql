-- name: GetUser :one
SELECT * FROM users WHERE id = $1;

-- name: ListUsers :many
SELECT * FROM users ORDER BY lower(email);

-- name: SetUserCredentials :exec
UPDATE users SET password_hash = $2, totp_secret_enc = $3, totp_last_step = 0,
    failed_logins = 0, locked_until = NULL
WHERE id = $1;

-- name: SetUserDisabled :exec
UPDATE users SET disabled_at = CASE WHEN sqlc.arg(disabled)::boolean THEN now() ELSE NULL END
WHERE id = $1;

-- name: RecordLoginFailure :one
-- Locks the account for lock_seconds after max_failures consecutive failures.
UPDATE users SET
    failed_logins = failed_logins + 1,
    locked_until = CASE WHEN failed_logins + 1 >= sqlc.arg(max_failures)::int
                        THEN now() + make_interval(secs => sqlc.arg(lock_seconds)::float8)
                        ELSE locked_until END
WHERE id = $1
RETURNING failed_logins, locked_until;

-- name: RecordLoginSuccess :exec
UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = now(), totp_last_step = $2
WHERE id = $1;

-- name: UseTOTPStep :execrows
-- Accepts a TOTP time step only once per user (replay protection).
UPDATE users SET totp_last_step = $2 WHERE id = $1 AND totp_last_step < $2;

-- name: CreateSession :one
INSERT INTO sessions (token_hash, user_id, expires_at, mfa_at, source_ip, user_agent)
VALUES ($1, $2, $3, now(), $4, $5)
RETURNING *;

-- name: GetSessionByToken :one
SELECT s.*, u.email, u.disabled_at AS user_disabled_at
FROM sessions s JOIN users u ON u.id = s.user_id
WHERE s.token_hash = $1;

-- name: TouchSession :exec
UPDATE sessions SET last_seen_at = now() WHERE id = $1;

-- name: SessionStepUp :exec
UPDATE sessions SET mfa_at = now() WHERE id = $1;

-- name: RevokeSession :exec
UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL;

-- name: RevokeUserSessions :execrows
UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL;

-- name: UpsertRoleBinding :one
INSERT INTO role_bindings (user_id, group_id, role, created_by) VALUES ($1, $2, $3, $4)
ON CONFLICT (user_id, COALESCE(group_id, '00000000-0000-0000-0000-000000000000'::uuid))
DO UPDATE SET role = EXCLUDED.role, created_by = EXCLUDED.created_by, created_at = now()
RETURNING *;

-- name: DeleteRoleBinding :execrows
DELETE FROM role_bindings WHERE user_id = $1 AND group_id IS NOT DISTINCT FROM sqlc.narg(group_id)::uuid;

-- name: ListRoleBindings :many
SELECT rb.*, g.name AS group_name
FROM role_bindings rb LEFT JOIN server_groups g ON g.id = rb.group_id
WHERE rb.user_id = $1;

-- name: ListAllRoleBindings :many
SELECT rb.*, u.email, g.name AS group_name
FROM role_bindings rb JOIN users u ON u.id = rb.user_id LEFT JOIN server_groups g ON g.id = rb.group_id
ORDER BY lower(u.email), g.name NULLS FIRST;
