-- +goose Up

CREATE TABLE server_groups (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text        NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    settings    jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE servers (
    id              uuid        PRIMARY KEY,
    name            text        NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9.-]{0,62}$'),
    group_id        uuid        REFERENCES server_groups (id) ON DELETE RESTRICT,
    hostname        text        NOT NULL DEFAULT '',
    os              text        NOT NULL DEFAULT '',
    arch            text        NOT NULL DEFAULT '',
    kernel          text        NOT NULL DEFAULT '',
    distro          text        NOT NULL DEFAULT '',
    distro_version  text        NOT NULL DEFAULT '',
    agent_version   text        NOT NULL DEFAULT '',
    labels          jsonb       NOT NULL DEFAULT '{}'::jsonb,
    status          text        NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending', 'online', 'offline', 'revoked')),
    last_seen_at    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX servers_group_id_idx ON servers (group_id);

CREATE TABLE users (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    email          text        NOT NULL,
    name           text        NOT NULL DEFAULT '',
    auth_provider  text        NOT NULL DEFAULT 'local' CHECK (auth_provider IN ('local', 'oidc')),
    password_hash  text,
    mfa_required   boolean     NOT NULL DEFAULT true,
    created_at     timestamptz NOT NULL DEFAULT now(),
    disabled_at    timestamptz
);

CREATE UNIQUE INDEX users_email_lower_idx ON users (lower(email));

-- Audit events are append-only and hash-chained:
--   hash = SHA-256(prev_hash || canonical event encoding), computed by the application.
-- server_id deliberately has no foreign key so history survives server deletion.
CREATE TABLE audit_events (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts          timestamptz NOT NULL DEFAULT now(),
    actor_type  text        NOT NULL CHECK (actor_type IN ('user', 'agent', 'system')),
    actor_id    text        NOT NULL,
    source_ip   inet,
    server_id   uuid,
    action      text        NOT NULL,
    params      jsonb       NOT NULL DEFAULT '{}'::jsonb,
    result      text        NOT NULL CHECK (result IN ('requested', 'succeeded', 'failed', 'denied')),
    prev_hash   bytea,
    hash        bytea       NOT NULL UNIQUE CHECK (length(hash) = 32)
);

CREATE INDEX audit_events_ts_idx ON audit_events (ts);
CREATE INDEX audit_events_server_id_idx ON audit_events (server_id, ts);

-- +goose StatementBegin
CREATE FUNCTION audit_events_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only (% rejected)', TG_OP;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER audit_events_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_append_only();

CREATE TRIGGER audit_events_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_append_only();

-- +goose Down

DROP TABLE audit_events;
DROP FUNCTION audit_events_append_only();
DROP TABLE users;
DROP TABLE servers;
DROP TABLE server_groups;
