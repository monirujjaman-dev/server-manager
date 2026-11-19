-- +goose Up

ALTER TABLE users
    ADD COLUMN totp_secret_enc  bytea,
    ADD COLUMN totp_last_step   bigint      NOT NULL DEFAULT 0,
    ADD COLUMN failed_logins    integer     NOT NULL DEFAULT 0,
    ADD COLUMN locked_until     timestamptz,
    ADD COLUMN last_login_at    timestamptz;

-- Roles: viewer < operator < admin < owner. group_id NULL means every server.
CREATE TABLE role_bindings (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    group_id    uuid        REFERENCES server_groups (id) ON DELETE CASCADE,
    role        text        NOT NULL CHECK (role IN ('viewer', 'operator', 'admin', 'owner')),
    created_by  text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX role_bindings_user_group_idx
    ON role_bindings (user_id, COALESCE(group_id, '00000000-0000-0000-0000-000000000000'::uuid));

-- Sessions. Only the SHA-256 of the bearer token is stored.
CREATE TABLE sessions (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash    bytea       NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    user_id       uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    -- Time of the last successful TOTP check, for step-up authentication.
    mfa_at        timestamptz NOT NULL,
    source_ip     inet,
    user_agent    text        NOT NULL DEFAULT '',
    revoked_at    timestamptz
);

CREATE INDEX sessions_user_id_idx ON sessions (user_id);

-- +goose Down

DROP TABLE sessions;
DROP TABLE role_bindings;
ALTER TABLE users
    DROP COLUMN totp_secret_enc,
    DROP COLUMN totp_last_step,
    DROP COLUMN failed_logins,
    DROP COLUMN locked_until,
    DROP COLUMN last_login_at;
