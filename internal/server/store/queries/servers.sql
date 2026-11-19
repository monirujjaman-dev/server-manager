-- name: CreateServerGroup :one
INSERT INTO server_groups (name) VALUES ($1)
RETURNING *;

-- name: ListServerGroups :many
SELECT * FROM server_groups ORDER BY name;

-- name: CreateServer :one
INSERT INTO servers (id, name, group_id) VALUES ($1, $2, $3)
RETURNING *;

-- name: GetServer :one
SELECT * FROM servers WHERE id = $1;

-- name: ListServers :many
SELECT * FROM servers ORDER BY name;

-- name: UpdateServerFacts :exec
UPDATE servers SET
    hostname       = $2,
    os             = $3,
    arch           = $4,
    kernel         = $5,
    distro         = $6,
    distro_version = $7,
    agent_version  = $8,
    status         = 'online',
    last_seen_at   = now(),
    updated_at     = now()
WHERE id = $1 AND status <> 'revoked';

-- name: MarkServerSeen :exec
UPDATE servers SET last_seen_at = now(), status = 'online'
WHERE id = $1 AND status <> 'revoked';

-- name: SetServerStatus :exec
UPDATE servers SET status = $2, updated_at = now() WHERE id = $1;
