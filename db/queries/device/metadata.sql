-- name: LockInventoryMetadata :exec
SELECT singleton FROM inventory_metadata_lock WHERE singleton FOR UPDATE;

-- name: GetDeviceMetadata :one
SELECT metadata FROM devices WHERE id = sqlc.arg('id');

-- name: SetDeviceMetadata :exec
UPDATE devices SET metadata = sqlc.arg('metadata'), owner_principal_id = sqlc.narg('owner_principal_id')
WHERE id = sqlc.arg('id');

-- name: DeleteDeviceLabels :exec
DELETE FROM device_labels WHERE device_id = sqlc.arg('device_id');

-- name: InsertDeviceLabels :exec
INSERT INTO device_labels (device_id, label)
SELECT sqlc.arg('device_id')::uuid, unnest(sqlc.arg('labels')::text[]);

-- name: ListDeviceLabels :many
SELECT label FROM device_labels WHERE device_id = sqlc.arg('device_id') ORDER BY label;

-- name: GetAttributeDefinition :one
SELECT definition FROM inventory_attribute_definitions WHERE key = sqlc.arg('key');

-- name: SetAttributeDefinition :exec
INSERT INTO inventory_attribute_definitions (key, definition) VALUES (sqlc.arg('key'), sqlc.arg('definition'))
ON CONFLICT (key) DO UPDATE SET definition = EXCLUDED.definition;

-- name: ListAttributeDefinitions :many
SELECT key, definition FROM inventory_attribute_definitions
WHERE key > sqlc.arg('after_key')::text ORDER BY key LIMIT sqlc.arg('row_limit')::int;

-- name: AttributeDefinitionHasIncompatibleValues :one
SELECT EXISTS (
  SELECT 1 FROM devices
  WHERE metadata -> 'attributes' ? sqlc.arg('key')::text
    AND (NOT (metadata -> 'attributes' -> sqlc.arg('key')::text ? sqlc.arg('value_field')::text)
      OR (sqlc.arg('is_enum')::boolean AND NOT (metadata -> 'attributes' -> sqlc.arg('key')::text ->> 'enumValue' = ANY(sqlc.arg('enum_values')::text[]))))
)::boolean;

-- name: InventoryOwnerExists :one
SELECT EXISTS (SELECT 1 FROM principals WHERE id = sqlc.arg('id'))::boolean;

-- name: InsertDeviceSearchCursor :exec
INSERT INTO device_search_cursors (id, actor_id, filter_digest, upper_enrolled_at, expires_at)
VALUES (sqlc.arg('id'), sqlc.arg('actor_id'), sqlc.arg('filter_digest'), sqlc.arg('upper_enrolled_at'), sqlc.arg('expires_at'));

-- name: GetDeviceSearchCursor :one
SELECT * FROM device_search_cursors WHERE id = sqlc.arg('id');

-- name: DeleteExpiredDeviceSearchCursors :exec
DELETE FROM device_search_cursors WHERE expires_at <= sqlc.arg('now')::timestamptz;

-- name: CountDeviceSearchCursors :one
SELECT count(*) FROM device_search_cursors WHERE actor_id = sqlc.arg('actor_id');

-- name: SearchDevices :many
-- Restrict scope, filters and keyset before projecting bounded page resources.
WITH page AS MATERIALIZED (
    SELECT d.*
    FROM devices d
    WHERE device_scope_matches(d.id, sqlc.arg('scope_unrestricted')::boolean, sqlc.arg('scopes')::jsonb)
      AND d.enrolled_at <= sqlc.arg('upper_enrolled_at')::timestamptz
      AND (NOT sqlc.arg('has_cursor')::boolean OR (d.enrolled_at, d.id) < (sqlc.arg('cursor_enrolled_at')::timestamptz, sqlc.arg('cursor_id')::uuid))
      AND (sqlc.arg('os_id')::text = '' OR d.os_id = sqlc.arg('os_id'))
      AND (sqlc.arg('os_version')::text = '' OR d.os_version = sqlc.arg('os_version'))
      AND starts_with(d.hostname, sqlc.arg('name_prefix')::text)
      AND (sqlc.narg('seen_from')::timestamptz IS NULL OR d.last_seen_at >= sqlc.narg('seen_from')::timestamptz)
      AND (sqlc.narg('seen_until')::timestamptz IS NULL OR d.last_seen_at <= sqlc.narg('seen_until')::timestamptz)
      AND d.metadata @> sqlc.arg('metadata_filter')::jsonb
    ORDER BY d.enrolled_at DESC, d.id DESC
    LIMIT sqlc.arg('row_limit')::int
)
SELECT d.id, d.current_generation_id, d.hostname, d.os_id, d.os_version, d.architecture,
    d.state, d.enrolled_at, d.last_seen_at, d.published_sequence,
    coalesce(g.host_sequence, 0)::bigint AS host_sequence,
    coalesce(g.package_sequence, 0)::bigint AS package_sequence,
    d.host_received_at, d.package_attempt_received_at, d.snapshot_received_at, d.metadata,
    compliance.compliance_rank, compliance.last_verified_at
FROM page d
LEFT JOIN enrollment_generations g ON g.id = d.current_generation_id
CROSS JOIN LATERAL (
    -- Explicit worst rank, independent of protobuf enum numbering:
    -- attention > unknown > stale > drift_remediated > compliant; zero unassigned.
    SELECT coalesce(max(CASE
        WHEN p.blocked_reason <> '' OR p.disposition IN (4, 5, 6, 7) OR p.applying OR p.dependency_attention THEN 5
        WHEN p.last_verified_at IS NULL THEN 4
        WHEN p.last_verified_at + make_interval(secs => LEAST(2 * p.reconcile_interval_seconds, p.verification_max_age_seconds)) <= CURRENT_TIMESTAMP THEN 3
        WHEN p.drift_remediated THEN 2
        ELSE 1
    END), 0)::int AS compliance_rank,
    -- A recent proof must not hide another resource's older or missing proof.
    (CASE WHEN count(*) = count(p.last_verified_at) THEN min(p.last_verified_at) END)::timestamptz AS last_verified_at
    FROM integration_compliance_projection p
    WHERE p.device_id = d.id
) compliance
ORDER BY d.enrolled_at DESC, d.id DESC;
