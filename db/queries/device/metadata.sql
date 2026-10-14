-- SPDX-License-Identifier: Apache-2.0

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

-- name: DeleteOldestDeviceSearchCursors :exec
-- Evicts an actor's soonest-expiring cursors to admit a new search within the cap.
DELETE FROM device_search_cursors
WHERE id IN (
    SELECT c.id FROM device_search_cursors c
    WHERE c.actor_id = sqlc.arg('actor_id')
    ORDER BY c.expires_at, c.id
    LIMIT sqlc.arg('excess')::integer
);

-- name: SearchDevices :many
-- Restrict scope, filters and keyset before projecting bounded page resources.
-- Order: sort_last (rows without the sort value: never seen, no hostname, no OS)
-- always last, then sort_key in the requested direction, then id. sort_field 0
-- keys on enrolled_at (callers pass descending). Keys compare bytewise (C) and
-- hold at most 80 characters so the page token can carry them; longer values
-- sharing that prefix are ordered by id, which is still one total order.
WITH keyed AS (
    SELECT d.*,
        (CASE sqlc.arg('sort_field')::int
            WHEN 1 THEN d.hostname = ''
            WHEN 2 THEN d.last_seen_at IS NULL
            WHEN 3 THEN d.os_id = ''
            ELSE false
        END)::boolean AS sort_last,
        (CASE sqlc.arg('sort_field')::int
            WHEN 1 THEN left(lower(d.hostname), 80)
            WHEN 2 THEN coalesce(lpad((extract(epoch FROM d.last_seen_at) * 1000000)::bigint::text, 20, '0'), '')
            WHEN 3 THEN left(lower(d.os_id), 40) || chr(1) || left(lower(d.os_version), 39)
            ELSE lpad((extract(epoch FROM d.enrolled_at) * 1000000)::bigint::text, 20, '0')
        END)::text COLLATE "C" AS sort_key
    FROM devices d
    WHERE device_scope_matches(d.id, sqlc.arg('scope_unrestricted')::boolean, sqlc.arg('scopes')::jsonb)
      AND d.enrolled_at <= sqlc.arg('upper_enrolled_at')::timestamptz
      AND (sqlc.arg('os_id')::text = '' OR d.os_id = sqlc.arg('os_id'))
      AND (sqlc.arg('os_version')::text = '' OR d.os_version = sqlc.arg('os_version'))
      AND starts_with(d.hostname, sqlc.arg('name_prefix')::text)
      AND (sqlc.arg('hostname_search')::text = '' OR strpos(lower(d.hostname), lower(sqlc.arg('hostname_search')::text)) > 0)
      AND (sqlc.arg('agent_release')::text = '' OR EXISTS (
          SELECT 1 FROM device_release_reports r
          WHERE r.generation_id = d.current_generation_id AND r.agent_release = sqlc.arg('agent_release')::text
      ))
      AND (sqlc.narg('seen_from')::timestamptz IS NULL OR d.last_seen_at >= sqlc.narg('seen_from')::timestamptz)
      AND (sqlc.narg('seen_until')::timestamptz IS NULL OR d.last_seen_at <= sqlc.narg('seen_until')::timestamptz)
      AND d.metadata @> sqlc.arg('metadata_filter')::jsonb
      -- Worst profile-item rank (device_compliance_rank) in the requested set.
      AND (cardinality(sqlc.arg('compliance_ranks')::int[]) = 0
          OR device_compliance_rank(d.id) = ANY(sqlc.arg('compliance_ranks')::int[]))
      -- Patch bucket as the fleet summary counts it: active devices only.
      AND (cardinality(sqlc.arg('patch_buckets')::text[]) = 0
          OR (d.state = 'active' AND device_patch_bucket(d.current_generation_id, sqlc.arg('patch_stale_after_seconds')::integer) = ANY(sqlc.arg('patch_buckets')::text[])))
      -- Same current evaluation and active-exception population as ListAdvisorySummary.
      AND (sqlc.arg('advisory_id')::text = '' OR (d.state = 'active' AND EXISTS (
          SELECT 1 FROM advisory_device_status s
          JOIN advisory_set_findings f ON f.set_id = s.finding_set_id
          WHERE s.device_id = d.id AND NOT s.unknown
            AND f.advisory_id = sqlc.arg('advisory_id')::text
            AND f.severity = sqlc.arg('advisory_severity')::text
            AND NOT EXISTS (
                SELECT 1 FROM advisory_exceptions x
                WHERE x.device_id = d.id AND x.finding_id = f.finding_key
                  AND x.expires_at > CURRENT_TIMESTAMP
            )
      )))
), page AS MATERIALIZED (
    SELECT k.*
    FROM keyed k
    WHERE NOT sqlc.arg('has_cursor')::boolean
       OR k.sort_last > sqlc.arg('cursor_last')::boolean
       OR (k.sort_last = sqlc.arg('cursor_last')::boolean AND (
           (NOT sqlc.arg('descending')::boolean AND (k.sort_key, k.id) > (sqlc.arg('cursor_key')::text COLLATE "C", sqlc.arg('cursor_id')::uuid))
           OR (sqlc.arg('descending')::boolean AND (k.sort_key, k.id) < (sqlc.arg('cursor_key')::text COLLATE "C", sqlc.arg('cursor_id')::uuid))))
    ORDER BY k.sort_last,
        CASE WHEN NOT sqlc.arg('descending')::boolean THEN k.sort_key END COLLATE "C",
        CASE WHEN sqlc.arg('descending')::boolean THEN k.sort_key END COLLATE "C" DESC,
        CASE WHEN NOT sqlc.arg('descending')::boolean THEN k.id END,
        CASE WHEN sqlc.arg('descending')::boolean THEN k.id END DESC
    LIMIT sqlc.arg('row_limit')::int
)
SELECT d.id, d.current_generation_id, d.hostname, d.os_id, d.os_version, d.architecture,
    d.state, d.enrolled_at, d.last_seen_at, d.published_sequence, d.sort_last, d.sort_key::text AS sort_key,
    coalesce(g.host_sequence, 0)::bigint AS host_sequence,
    coalesce(g.package_sequence, 0)::bigint AS package_sequence,
    d.host_received_at, d.package_attempt_received_at, d.snapshot_received_at, d.metadata,
    compliance.compliance_rank, compliance.last_verified_at,
    coalesce(r.agent_release, '')::text AS agent_release,
    coalesce(r.protocol_version, 0)::int AS agent_protocol_version,
    r.reported_at AS agent_version_accepted_at,
    -- Latest OS update status of the current generation; unavailable is unknown.
    (hp.available IS TRUE)::boolean AS updates_reported,
    coalesce(hp.pending_updates, 0)::int AS pending_updates,
    coalesce(hp.pending_security_updates, 0)::int AS pending_security_updates,
    coalesce(hp.reboot_required, false)::boolean AS reboot_required,
    hp.received_at AS updates_received_at,
    -- Same freshness rule as FleetSummaryPatch: never trust the device clock alone.
    coalesce(LEAST(hp.observed_at, hp.received_at) < CURRENT_TIMESTAMP - make_interval(secs => sqlc.arg('patch_stale_after_seconds')::integer), false)::boolean AS updates_stale,
    (findings.critical IS NOT NULL)::boolean AS findings_checked,
    coalesce(findings.partial, false)::boolean AS findings_partial,
    coalesce(findings.critical, 0)::bigint AS findings_critical,
    coalesce(findings.high, 0)::bigint AS findings_high,
    coalesce(findings.medium, 0)::bigint AS findings_medium,
    coalesce(findings.low, 0)::bigint AS findings_low,
    coalesce(findings.other, 0)::bigint AS findings_other
FROM page d
LEFT JOIN enrollment_generations g ON g.id = d.current_generation_id
LEFT JOIN device_release_reports r ON r.generation_id = d.current_generation_id
LEFT JOIN host_patch_status hp ON hp.generation_id = d.current_generation_id
LEFT JOIN LATERAL (
    -- FleetSummaryFindings' open-finding population for one device: the fresh
    -- evaluation's shared finding set minus this device's active exceptions.
    -- No fresh evaluation yields no row: advisory coverage is missing.
    SELECT e.state = 'partial' AS partial,
        fs.critical_count - count(f.finding_key) FILTER (WHERE f.severity = 'critical') AS critical,
        fs.high_count - count(f.finding_key) FILTER (WHERE f.severity = 'high') AS high,
        fs.medium_count - count(f.finding_key) FILTER (WHERE f.severity = 'medium') AS medium,
        fs.low_count - count(f.finding_key) FILTER (WHERE f.severity = 'low') AS low,
        fs.other_count - count(f.finding_key) FILTER (WHERE f.severity NOT IN ('critical', 'high', 'medium', 'low')) AS other
    FROM advisory_device_status s
    JOIN advisory_evaluations e ON e.device_id = s.device_id
    JOIN advisory_finding_sets fs ON fs.id = s.finding_set_id
    LEFT JOIN advisory_exceptions x ON x.device_id = s.device_id AND x.expires_at > CURRENT_TIMESTAMP
    LEFT JOIN advisory_set_findings f ON f.set_id = fs.id AND f.finding_key = x.finding_id
    WHERE s.device_id = d.id AND NOT s.unknown
    GROUP BY e.state, fs.id
) findings ON true
CROSS JOIN LATERAL (
    -- Worst rank: see device_compliance_rank (migration 00041).
    SELECT device_compliance_rank(d.id) AS compliance_rank,
    -- A recent proof must not hide another resource's older or missing proof.
    (CASE WHEN count(*) = count(p.last_verified_at) THEN min(p.last_verified_at) END)::timestamptz AS last_verified_at
    FROM integration_compliance_projection p
    WHERE p.device_id = d.id
) compliance
ORDER BY d.sort_last,
    CASE WHEN NOT sqlc.arg('descending')::boolean THEN d.sort_key END COLLATE "C",
    CASE WHEN sqlc.arg('descending')::boolean THEN d.sort_key END COLLATE "C" DESC,
    CASE WHEN NOT sqlc.arg('descending')::boolean THEN d.id END,
    CASE WHEN sqlc.arg('descending')::boolean THEN d.id END DESC;

-- name: HostObservationDetails :batchone
-- Native details of a generation's latest successful host observation. Batched
-- so a device list page decodes one row at a time, never every page's details.
SELECT details FROM host_observations WHERE generation_id = $1;
