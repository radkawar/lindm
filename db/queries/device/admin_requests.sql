-- name: InsertAdminRequest :exec
INSERT INTO device_admin_requests (
    actor_id,
    method,
    request_id,
    request_digest,
    created_at
) VALUES (
    sqlc.arg('actor_id'),
    sqlc.arg('method'),
    sqlc.arg('request_id'),
    sqlc.arg('request_digest'),
    sqlc.arg('created_at')
)
ON CONFLICT (actor_id, method, request_id) DO NOTHING;

-- name: GetAdminRequestForUpdate :one
SELECT
    actor_id,
    method,
    request_id,
    request_digest,
    grant_id,
    device_id,
    expires_at,
    completed
FROM device_admin_requests
WHERE actor_id = sqlc.arg('actor_id')
  AND method = sqlc.arg('method')
  AND request_id = sqlc.arg('request_id')
FOR UPDATE;

-- name: CompleteAdminRequest :exec
UPDATE device_admin_requests
SET
    grant_id = sqlc.arg('grant_id'),
    device_id = sqlc.arg('device_id'),
    expires_at = sqlc.arg('expires_at'),
    completed = true
WHERE actor_id = sqlc.arg('actor_id')
  AND method = sqlc.arg('method')
  AND request_id = sqlc.arg('request_id')
  AND NOT completed;
