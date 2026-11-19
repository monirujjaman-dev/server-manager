-- +goose Up

-- One-time enrollment tokens. Only the SHA-256 of the token is stored.
CREATE TABLE enrollment_tokens (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash   bytea       NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    server_name  text        NOT NULL CHECK (server_name ~ '^[a-z0-9][a-z0-9.-]{0,62}$'),
    group_id     uuid        REFERENCES server_groups (id) ON DELETE CASCADE,
    created_by   text        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    used_at      timestamptz,
    server_id    uuid        REFERENCES servers (id) ON DELETE SET NULL,
    CHECK (expires_at > created_at)
);

CREATE INDEX enrollment_tokens_server_name_idx ON enrollment_tokens (server_name);

-- Every agent certificate ever issued. A certificate whose serial is not in this table
-- is rejected, so only certificates issued through enrollment or renewal are accepted.
CREATE TABLE agent_certificates (
    serial      text        PRIMARY KEY CHECK (serial ~ '^[0-9a-f]{1,40}$'),
    server_id   uuid        NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    not_before  timestamptz NOT NULL,
    not_after   timestamptz NOT NULL,
    revoked_at  timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX agent_certificates_server_id_idx ON agent_certificates (server_id);

-- +goose Down

DROP TABLE agent_certificates;
DROP TABLE enrollment_tokens;
