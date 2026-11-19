-- +goose Up

-- One row per action sent to an agent. request and result hold serialized protobuf
-- (sm.agent.v1.ActionRequest / CommandResult); action is a readable copy for listings.
CREATE TABLE jobs (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id      uuid        NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    action         text        NOT NULL,
    risk           text        NOT NULL CHECK (risk IN ('read', 'low', 'medium', 'high', 'critical')),
    request        bytea       NOT NULL,
    requested_by   text        NOT NULL,
    status         text        NOT NULL DEFAULT 'pending'
                               CHECK (status IN ('pending', 'dispatched', 'succeeded', 'failed', 'rejected', 'expired')),
    error          text        NOT NULL DEFAULT '',
    result         bytea,
    created_at     timestamptz NOT NULL DEFAULT now(),
    -- A pending job not delivered by this time expires.
    expires_at     timestamptz NOT NULL,
    dispatched_at  timestamptz,
    finished_at    timestamptz
);

CREATE INDEX jobs_pending_idx ON jobs (server_id, created_at) WHERE status = 'pending';
CREATE INDEX jobs_dispatched_idx ON jobs (dispatched_at) WHERE status = 'dispatched';
CREATE INDEX jobs_server_created_idx ON jobs (server_id, created_at DESC);

-- +goose Down

DROP TABLE jobs;
