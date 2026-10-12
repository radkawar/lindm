-- name: InsertApproval :one
INSERT INTO approval_requests (id, requester_id, requester_version, action, permission, device_id, mutation_id, payload, payload_sha256, created_at, expires_at)
VALUES (sqlc.arg(id), sqlc.arg(requester_id), sqlc.arg(requester_version), sqlc.arg(action), sqlc.arg(permission), sqlc.narg(device_id), sqlc.arg(mutation_id), sqlc.arg(payload), sqlc.arg(payload_sha256), statement_timestamp(), statement_timestamp() + make_interval(secs => sqlc.arg(lifetime_seconds)::int))
RETURNING *;

-- name: GetApproval :one
SELECT * FROM approval_requests WHERE id = sqlc.arg(id);

-- name: GetApprovalProjection :one
SELECT sqlc.embed(a),
  coalesce(nullif(requester.display_name, ''), requester_account.username, '')::text AS requester_display_name,
  coalesce(nullif(approver.display_name, ''), approver_account.username, '')::text AS approver_display_name,
  coalesce(d.hostname, '')::text AS device_hostname
FROM approval_requests a
LEFT JOIN principals requester ON requester.id = a.requester_id
LEFT JOIN local_accounts requester_account ON requester_account.id = requester.id
LEFT JOIN principals approver ON approver.id = a.approver_id
LEFT JOIN local_accounts approver_account ON approver_account.id = approver.id
LEFT JOIN devices d ON d.id = a.device_id
WHERE a.id = sqlc.arg(id);

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
-- Open requests (pending or approved, unexpired at as_of) come first, nearest
-- expiry first; closed ones follow, newest first. The keyset (open, time, id)
-- matches this order exactly; id breaks ties so every row has one position.
SELECT sqlc.embed(a),
  coalesce(nullif(requester.display_name, ''), requester_account.username, '')::text AS requester_display_name,
  coalesce(nullif(approver.display_name, ''), approver_account.username, '')::text AS approver_display_name,
  coalesce(d.hostname, '')::text AS device_hostname
FROM approval_requests a
LEFT JOIN principals requester ON requester.id = a.requester_id
LEFT JOIN local_accounts requester_account ON requester_account.id = requester.id
LEFT JOIN principals approver ON approver.id = a.approver_id
LEFT JOIN local_accounts approver_account ON approver_account.id = approver.id
LEFT JOIN devices d ON d.id = a.device_id
WHERE (
    sqlc.arg(first_page)::boolean
    OR (NOT sqlc.arg(after_closed)::boolean AND (
      NOT (a.state IN ('pending', 'approved') AND a.expires_at > sqlc.arg(as_of)::timestamptz)
      OR (a.expires_at, a.id) > (sqlc.arg(after_at)::timestamptz, sqlc.arg(after_id)::uuid)
    ))
    OR (sqlc.arg(after_closed)::boolean
      AND NOT (a.state IN ('pending', 'approved') AND a.expires_at > sqlc.arg(as_of)::timestamptz)
      AND (a.created_at < sqlc.arg(after_at)::timestamptz
        OR (a.created_at = sqlc.arg(after_at)::timestamptz AND a.id > sqlc.arg(after_id)::uuid)))
  )
  AND (
    a.permission = ANY(sqlc.arg(unrestricted_permissions)::text[])
    OR (a.device_id IS NOT NULL AND device_scope_matches(a.device_id, false, coalesce(sqlc.arg(scopes)::jsonb -> a.permission, '[]'::jsonb)))
  )
  AND NOT EXISTS (
    SELECT 1
    FROM jsonb_array_elements(coalesce(sqlc.arg(required_scopes)::jsonb -> a.permission, '[]'::jsonb)) required
    WHERE a.device_id IS NULL
       OR NOT device_scope_matches(a.device_id, (required ->> 'unrestricted')::boolean, required -> 'scopes')
  )
  AND (
    a.requester_id = sqlc.arg(actor_id)
    OR sqlc.arg(manage_unrestricted)::boolean
    OR (a.device_id IS NOT NULL AND device_scope_matches(a.device_id, false, sqlc.arg(manage_scopes)::jsonb))
  )
ORDER BY NOT (a.state IN ('pending', 'approved') AND a.expires_at > sqlc.arg(as_of)::timestamptz),
  CASE WHEN a.state IN ('pending', 'approved') AND a.expires_at > sqlc.arg(as_of)::timestamptz THEN a.expires_at END,
  CASE WHEN NOT (a.state IN ('pending', 'approved') AND a.expires_at > sqlc.arg(as_of)::timestamptz) THEN a.created_at END DESC,
  a.id
LIMIT sqlc.arg(row_limit);
