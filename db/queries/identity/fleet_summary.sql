-- name: CountVisibleOpenApprovals :one
-- Exact ListVisibleApprovals visibility over unexpired open records: pending
-- ones, and the actor's own approved requests that only they can run.
SELECT count(*) FILTER (WHERE a.state = 'pending')::bigint AS pending,
  count(*) FILTER (WHERE a.state = 'approved' AND a.requester_id = sqlc.arg(actor_id))::bigint AS ready_to_run
FROM approval_requests a
WHERE a.state IN ('pending', 'approved') AND a.expires_at > CURRENT_TIMESTAMP
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
  );
