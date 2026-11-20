-- +goose Up

-- Running Docker containers per server, counted by the agent from cgroupfs.
-- NULL means the server has no Docker (or an agent that does not report it).
ALTER TABLE server_metrics
    ADD COLUMN containers_running      integer,
    ADD COLUMN containers_memory_bytes bigint;

-- +goose Down

ALTER TABLE server_metrics
    DROP COLUMN containers_running,
    DROP COLUMN containers_memory_bytes;
