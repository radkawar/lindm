-- name: CountVisiblePendingApprovals :one
-- Exact ListVisibleApprovals visibility, with pending/unexpired record filters.
SELECT count(*)::bigint FROM approval_requests a
WHERE a.state = 'pending' AND a.expires_at > CURRENT_TIMESTAMP
  AND (
    a.permission = ANY(sqlc.arg(unrestricted_permissions)::text[])
    OR (a.device_id IS NOT NULL AND device_scope_matches(a.device_id, false, coalesce(sqlc.arg(scopes)::jsonb -> a.permission, '[]'::jsonb)))
  )
  AND (
    a.requester_id = sqlc.arg(actor_id)
    OR sqlc.arg(manage_unrestricted)::boolean
    OR (a.device_id IS NOT NULL AND device_scope_matches(a.device_id, false, sqlc.arg(manage_scopes)::jsonb))
  );
