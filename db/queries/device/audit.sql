-- name: InsertAuditEvent :exec
INSERT INTO audit_events (id, actor_id, action, resource_id, reason, target_device_id, details)
VALUES (sqlc.arg('id'), sqlc.narg('actor_id'), sqlc.arg('action'), sqlc.arg('resource_id'), sqlc.arg('reason'), sqlc.narg('target_device_id'), COALESCE(sqlc.narg('details')::jsonb, '{}'::jsonb));

-- name: ListAuditEvents :many
SELECT a.*, COALESCE(d.hostname, '')::text AS device_hostname
FROM audit_events a
LEFT JOIN devices d ON d.id = a.target_device_id
WHERE sqlc.narg('cursor_id')::uuid IS NULL
   OR (a.occurred_at, a.id) < (sqlc.narg('cursor_occurred_at')::timestamptz, sqlc.narg('cursor_id')::uuid)
ORDER BY a.occurred_at DESC, a.id DESC
LIMIT sqlc.arg('row_limit')::int;
