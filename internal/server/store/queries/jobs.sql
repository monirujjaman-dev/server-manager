-- name: CreateJob :one
INSERT INTO jobs (server_id, action, risk, request, requested_by, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetJob :one
SELECT * FROM jobs WHERE id = $1;

-- name: ClaimPendingJobs :many
-- Atomically moves a server's deliverable jobs to dispatched, oldest first.
UPDATE jobs SET status = 'dispatched', dispatched_at = now()
WHERE id IN (
    SELECT j.id FROM jobs j
    WHERE j.server_id = $1 AND j.status = 'pending' AND j.expires_at > now()
    ORDER BY j.created_at
    LIMIT sqlc.arg(max_jobs)
    FOR UPDATE SKIP LOCKED
)
RETURNING *;

-- name: ReleaseJob :exec
-- Puts a claimed job back when it could not be sent.
UPDATE jobs SET status = 'pending', dispatched_at = NULL
WHERE id = $1 AND status = 'dispatched';

-- name: CompleteJob :one
-- Only the server a job was dispatched to can complete it, and only once.
UPDATE jobs SET status = $3, error = $4, result = $5, finished_at = now()
WHERE id = $1 AND server_id = $2 AND status = 'dispatched'
RETURNING *;

-- name: ExpirePendingJobs :many
UPDATE jobs SET status = 'expired', error = 'not delivered before expiry', finished_at = now()
WHERE status = 'pending' AND expires_at <= now()
RETURNING *;

-- name: FailStaleDispatchedJobs :many
-- Jobs sent but never answered: the outcome is unknown, so they are not retried.
UPDATE jobs SET status = 'failed', error = 'no result from agent; outcome unknown', finished_at = now()
WHERE status = 'dispatched' AND dispatched_at < now() - make_interval(secs => sqlc.arg(older_than_seconds)::float8)
RETURNING *;

-- name: ServersWithPendingJobs :many
SELECT DISTINCT server_id FROM jobs WHERE status = 'pending' AND expires_at > now();

-- name: NotifyJobs :exec
SELECT pg_notify('sm_jobs', sqlc.arg(server_id)::text);
