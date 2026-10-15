-- SPDX-License-Identifier: Apache-2.0

-- name: InsertAuditEvent :exec
INSERT INTO audit_events (id, actor_id, action, resource_id, reason, target_device_id, details)
VALUES (sqlc.arg('id'), sqlc.narg('actor_id'), sqlc.arg('action'), sqlc.arg('resource_id'), sqlc.arg('reason'), sqlc.narg('target_device_id'), COALESCE(sqlc.narg('details')::jsonb, '{}'::jsonb));

-- name: ListAuditEvents :many
-- device_action_capability names the device action a device_action.* event
-- records; device action capabilities never change after creation.
-- The public details map is textual display context; stored JSON and signed
-- report payloads retain their original types and bytes.
SELECT a.id, a.occurred_at, a.actor_id, a.action, a.resource_id, a.reason,
       COALESCE((SELECT jsonb_object_agg(detail.key, detail.value)
                 FROM jsonb_each_text(a.details) AS detail), '{}'::jsonb)::jsonb AS details,
       f.target_device_id, COALESCE(d.hostname, '')::text AS device_hostname,
       COALESCE(p.display_name, '')::text AS actor_display_name,
       COALESCE(da.capability, '')::text AS device_action_capability
FROM audit_event_search f
JOIN audit_events a ON a.id = f.event_id
LEFT JOIN devices d ON d.id = f.target_device_id
LEFT JOIN principals p ON p.id = f.actor_id
LEFT JOIN device_actions da ON a.action LIKE 'device\_action.%' AND da.id::text = a.resource_id
WHERE f.sequence <= sqlc.arg('snapshot_sequence')::bigint
  AND (sqlc.narg('actor_id')::uuid IS NULL OR f.actor_id = sqlc.narg('actor_id'))
  AND (sqlc.narg('target_device_id')::uuid IS NULL OR f.target_device_id = sqlc.narg('target_device_id'))
  AND (sqlc.arg('action_category')::smallint IN (0, 4) OR f.action_category = sqlc.arg('action_category'))
-- Human actions: a person acted, and the kind is not session or read bookkeeping.
  AND (sqlc.arg('action_category')::smallint <> 4
       OR (f.actor_id IS NOT NULL AND a.action <> ALL(sqlc.arg('human_excluded_actions')::text[])))
  AND (sqlc.narg('occurred_from')::timestamptz IS NULL OR f.occurred_at >= sqlc.narg('occurred_from'))
  AND (sqlc.narg('occurred_until')::timestamptz IS NULL OR f.occurred_at < sqlc.narg('occurred_until'))
  AND (sqlc.narg('cursor_id')::uuid IS NULL
       OR (f.occurred_at, f.event_id) < (sqlc.narg('cursor_occurred_at')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY f.occurred_at DESC, f.event_id DESC
LIMIT sqlc.arg('row_limit')::int;

-- name: GetAuditSnapshot :one
SELECT sequence FROM report_audit_head WHERE singleton;

-- name: ListAuditActors :many
SELECT p.id, p.display_name FROM principals p
WHERE p.id > sqlc.arg('after_id')::uuid
  AND (sqlc.narg('id')::uuid IS NULL OR p.id = sqlc.narg('id'))
  AND starts_with(lower(p.display_name), lower(sqlc.arg('name_prefix')::text))
  AND EXISTS (SELECT 1 FROM audit_event_search f WHERE f.actor_id = p.id)
ORDER BY p.id LIMIT sqlc.arg('row_limit')::int;

-- name: ListAuditDevices :many
SELECT d.id, d.hostname FROM devices d
WHERE d.id > sqlc.arg('after_id')::uuid
  AND (sqlc.narg('id')::uuid IS NULL OR d.id = sqlc.narg('id'))
  AND starts_with(lower(d.hostname), lower(sqlc.arg('name_prefix')::text))
  AND EXISTS (SELECT 1 FROM audit_event_search f WHERE f.target_device_id = d.id)
ORDER BY d.id LIMIT sqlc.arg('row_limit')::int;
