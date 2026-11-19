-- name: InsertAuditEvent :one
INSERT INTO audit_events (ts, actor_type, actor_id, source_ip, server_id, action, params, result, prev_hash, hash)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING id;

-- name: LatestAuditHash :one
SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1;

-- name: ListAuditEvents :many
SELECT * FROM audit_events
WHERE id > sqlc.arg(after_id)
ORDER BY id
LIMIT sqlc.arg(max_rows);
