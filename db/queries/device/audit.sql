-- name: InsertAuditEvent :exec
INSERT INTO audit_events (
    id,
    actor_id,
    action,
    resource_id,
    reason
) VALUES (
    sqlc.arg('id'),
    sqlc.narg('actor_id'),
    sqlc.arg('action'),
    sqlc.arg('resource_id'),
    sqlc.arg('reason')
);

-- name: ListAuditEventsFirst :many
SELECT
    id,
    occurred_at,
    actor_id,
    action,
    resource_id,
    reason
FROM audit_events
ORDER BY occurred_at DESC, id DESC
LIMIT sqlc.arg('row_limit')::int;

-- name: ListAuditEventsAfter :many
SELECT
    id,
    occurred_at,
    actor_id,
    action,
    resource_id,
    reason
FROM audit_events
WHERE (occurred_at, id) < (sqlc.arg('cursor_occurred_at')::timestamptz, sqlc.arg('cursor_id')::uuid)
ORDER BY occurred_at DESC, id DESC
LIMIT sqlc.arg('row_limit')::int;
