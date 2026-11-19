-- name: CreateEnrollmentToken :one
INSERT INTO enrollment_tokens (token_hash, server_name, group_id, created_by, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, server_name, group_id, created_at, expires_at;

-- name: ServerNameInUse :one
-- True when a server has the name or an unused, unexpired token reserves it.
SELECT (EXISTS (SELECT 1 FROM servers WHERE name = sqlc.arg(name)::text)
    OR EXISTS (SELECT 1 FROM enrollment_tokens
               WHERE server_name = sqlc.arg(name)::text AND used_at IS NULL AND expires_at > now()))::boolean AS in_use;

-- name: ConsumeEnrollmentToken :one
-- Atomically marks a valid token as used. Returns no rows for unknown, used or expired tokens.
UPDATE enrollment_tokens SET used_at = now()
WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
RETURNING id, server_name, group_id;

-- name: SetEnrollmentTokenServer :exec
UPDATE enrollment_tokens SET server_id = $2 WHERE id = $1;

-- name: InsertAgentCertificate :exec
INSERT INTO agent_certificates (serial, server_id, not_before, not_after)
VALUES ($1, $2, $3, $4);

-- name: CertificateRejected :one
-- True when the certificate is revoked, belongs to a revoked server, or is unknown.
SELECT COALESCE((
    SELECT c.revoked_at IS NOT NULL OR s.status = 'revoked'
    FROM agent_certificates c JOIN servers s ON s.id = c.server_id
    WHERE c.serial = $1
), true)::boolean AS rejected;

-- name: RevokeServerCertificates :execrows
UPDATE agent_certificates SET revoked_at = now()
WHERE server_id = $1 AND revoked_at IS NULL;
