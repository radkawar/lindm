-- name: InsertApproval :one
INSERT INTO approval_requests (id, requester_id, requester_version, action, permission, device_id, mutation_id, payload, payload_sha256, created_at, expires_at)
VALUES (sqlc.arg(id), sqlc.arg(requester_id), sqlc.arg(requester_version), sqlc.arg(action), sqlc.arg(permission), sqlc.narg(device_id), sqlc.arg(mutation_id), sqlc.arg(payload), sqlc.arg(payload_sha256), statement_timestamp(), statement_timestamp() + make_interval(secs => sqlc.arg(lifetime_seconds)::int))
RETURNING *;

-- name: GetApproval :one
SELECT * FROM approval_requests WHERE id = sqlc.arg(id);

-- name: GetApprovalForMutation :one
SELECT * FROM approval_requests
WHERE requester_id = sqlc.arg(requester_id) AND action = sqlc.arg(action) AND mutation_id = sqlc.arg(mutation_id);

-- name: LockApproval :one
SELECT * FROM approval_requests WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: DecideApproval :one
UPDATE approval_requests SET state = sqlc.arg(state), approver_id = sqlc.arg(approver_id), approver_version = sqlc.arg(approver_version), decision_reason = sqlc.arg(decision_reason)
WHERE id = sqlc.arg(id) AND state = 'pending' AND expires_at > clock_timestamp()
RETURNING *;

-- name: ConsumeApproval :execrows
UPDATE approval_requests SET state = 'consumed', consumed_at = clock_timestamp()
WHERE id = sqlc.arg(id) AND state = 'approved' AND expires_at > clock_timestamp();

-- name: ListVisibleApprovals :many
SELECT * FROM approval_requests a
WHERE a.id > sqlc.arg(after_id)::uuid
  AND (
    a.permission = ANY(sqlc.arg(unrestricted_permissions)::text[])
    OR (a.device_id IS NOT NULL AND device_scope_matches(a.device_id, false, coalesce(sqlc.arg(scopes)::jsonb -> a.permission, '[]'::jsonb)))
  )
  AND (
    a.requester_id = sqlc.arg(actor_id)
    OR sqlc.arg(manage_unrestricted)::boolean
    OR (a.device_id IS NOT NULL AND device_scope_matches(a.device_id, false, sqlc.arg(manage_scopes)::jsonb))
  )
ORDER BY a.id LIMIT sqlc.arg(row_limit);
