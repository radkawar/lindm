-- SPDX-License-Identifier: Apache-2.0

-- name: SuggestDeviceValues :many
-- One device column selected by field: 'os_id', 'os_version' or 'architecture'.
SELECT v.value::text AS value, count(*)::bigint AS count
FROM devices d
CROSS JOIN LATERAL (
    SELECT (CASE sqlc.arg('field')::text
        WHEN 'os_id' THEN d.os_id
        WHEN 'os_version' THEN d.os_version
        WHEN 'architecture' THEN d.architecture
    END) COLLATE "C" AS value
) v
WHERE device_scope_matches(d.id, sqlc.arg('scope_unrestricted')::boolean, sqlc.arg('scopes')::jsonb)
  AND (NOT sqlc.arg('has_device')::boolean OR d.id = sqlc.arg('device_id')::uuid)
  AND (sqlc.arg('os_id')::text = '' OR d.os_id = sqlc.arg('os_id')::text)
  AND v.value <> ''
  AND starts_with(lower(v.value), sqlc.arg('prefix')::text)
  AND (lower(v.value), v.value) > (lower(sqlc.arg('after')::text COLLATE "C"), sqlc.arg('after')::text COLLATE "C")
GROUP BY v.value
ORDER BY lower(v.value), v.value
LIMIT sqlc.arg('row_limit')::int;

-- name: SuggestDeviceLabels :many
SELECT (l.label COLLATE "C")::text AS value, count(*)::bigint AS count
FROM device_labels l
WHERE device_scope_matches(l.device_id, sqlc.arg('scope_unrestricted')::boolean, sqlc.arg('scopes')::jsonb)
  AND (NOT sqlc.arg('has_device')::boolean OR l.device_id = sqlc.arg('device_id')::uuid)
  AND starts_with(lower(l.label COLLATE "C"), sqlc.arg('prefix')::text)
  AND (lower(l.label COLLATE "C"), l.label COLLATE "C") > (lower(sqlc.arg('after')::text COLLATE "C"), sqlc.arg('after')::text COLLATE "C")
GROUP BY l.label COLLATE "C"
ORDER BY lower(l.label COLLATE "C"), l.label COLLATE "C"
LIMIT sqlc.arg('row_limit')::int;

-- name: SuggestAgentReleases :many
-- Releases reported by each device's current enrollment generation.
SELECT (r.agent_release COLLATE "C")::text AS value, count(*)::bigint AS count
FROM devices d
JOIN device_release_reports r ON r.generation_id = d.current_generation_id
WHERE device_scope_matches(d.id, sqlc.arg('scope_unrestricted')::boolean, sqlc.arg('scopes')::jsonb)
  AND (NOT sqlc.arg('has_device')::boolean OR d.id = sqlc.arg('device_id')::uuid)
  AND r.agent_release <> ''
  AND starts_with(lower(r.agent_release COLLATE "C"), sqlc.arg('prefix')::text)
  AND (lower(r.agent_release COLLATE "C"), r.agent_release COLLATE "C") > (lower(sqlc.arg('after')::text COLLATE "C"), sqlc.arg('after')::text COLLATE "C")
GROUP BY r.agent_release COLLATE "C"
ORDER BY lower(r.agent_release COLLATE "C"), r.agent_release COLLATE "C"
LIMIT sqlc.arg('row_limit')::int;

-- name: SuggestPackageNames :many
-- Fleet-wide names walk snapshot_packages_name_suggest_idx in output order and
-- keep entries whose snapshot is an in-scope device's current one. The caller
-- passes one exclusive start key, the later of (prefix, '') and the previous
-- page's (lower(after), after): a second lower bound would not narrow the btree
-- start, so the scan would begin at the first key. prefix_end stops it.
WITH current_snapshots AS MATERIALIZED (
    SELECT g.current_snapshot_id AS snapshot_id
    FROM devices d
    JOIN enrollment_generations g ON g.id = d.current_generation_id
    WHERE g.current_snapshot_id IS NOT NULL
      AND device_scope_matches(d.id, sqlc.arg('scope_unrestricted')::boolean, sqlc.arg('scopes')::jsonb)
)
SELECT (p.name COLLATE "C")::text AS value, count(DISTINCT p.snapshot_id)::bigint AS count
FROM snapshot_packages p
WHERE p.snapshot_id IN (SELECT c.snapshot_id FROM current_snapshots c)
  AND (lower(p.name COLLATE "C"), p.name COLLATE "C") > (sqlc.arg('start_lower')::text COLLATE "C", sqlc.arg('start_exact')::text COLLATE "C")
  AND (sqlc.arg('unbounded')::boolean OR lower(p.name COLLATE "C") < (sqlc.arg('prefix_end')::text COLLATE "C"))
  AND (sqlc.arg('manager')::text = '' OR p.manager = sqlc.arg('manager')::text)
GROUP BY lower(p.name COLLATE "C"), p.name COLLATE "C"
ORDER BY lower(p.name COLLATE "C"), p.name COLLATE "C"
LIMIT sqlc.arg('row_limit')::int;

-- name: SuggestSnapshotPackageNames :many
-- One device's current snapshot: at most 100000 rows, read through its key.
SELECT (p.name COLLATE "C")::text AS value, count(DISTINCT p.snapshot_id)::bigint AS count
FROM snapshot_packages p
WHERE p.snapshot_id = sqlc.arg('snapshot_id')::uuid
  AND starts_with(lower(p.name COLLATE "C"), sqlc.arg('prefix')::text)
  AND (lower(p.name COLLATE "C"), p.name COLLATE "C") > (lower(sqlc.arg('after')::text COLLATE "C"), sqlc.arg('after')::text COLLATE "C")
  AND (sqlc.arg('manager')::text = '' OR p.manager = sqlc.arg('manager')::text)
GROUP BY lower(p.name COLLATE "C"), p.name COLLATE "C"
ORDER BY lower(p.name COLLATE "C"), p.name COLLATE "C"
LIMIT sqlc.arg('row_limit')::int;

-- name: SuggestSnapshotPackageManagers :many
SELECT (p.manager COLLATE "C")::text AS value, count(DISTINCT p.snapshot_id)::bigint AS count
FROM snapshot_packages p
WHERE p.snapshot_id = sqlc.arg('snapshot_id')::uuid
  AND starts_with(lower(p.manager COLLATE "C"), sqlc.arg('prefix')::text)
  AND (lower(p.manager COLLATE "C"), p.manager COLLATE "C") > (lower(sqlc.arg('after')::text COLLATE "C"), sqlc.arg('after')::text COLLATE "C")
GROUP BY p.manager COLLATE "C"
ORDER BY lower(p.manager COLLATE "C"), p.manager COLLATE "C"
LIMIT sqlc.arg('row_limit')::int;

-- name: SuggestAdvisoryIDs :many
-- Advisories in each in-scope device's latest evaluation finding set,
-- including evaluations that are no longer fresh.
WITH sets AS (
    SELECT e.finding_set_id AS set_id, count(*)::bigint AS devices
    FROM advisory_evaluations e
    WHERE e.finding_set_id IS NOT NULL
      AND device_scope_matches(e.device_id, sqlc.arg('scope_unrestricted')::boolean, sqlc.arg('scopes')::jsonb)
      AND (NOT sqlc.arg('has_device')::boolean OR e.device_id = sqlc.arg('device_id')::uuid)
    GROUP BY e.finding_set_id
)
SELECT a.value::text AS value, sum(s.devices)::bigint AS count
FROM sets s
CROSS JOIN LATERAL (
    SELECT DISTINCT x.advisory_id COLLATE "C" AS value
    FROM advisory_set_advisories x
    WHERE x.set_id = s.set_id
) a
WHERE starts_with(lower(a.value), sqlc.arg('prefix')::text)
  AND (lower(a.value), a.value) > (lower(sqlc.arg('after')::text COLLATE "C"), sqlc.arg('after')::text COLLATE "C")
GROUP BY a.value
ORDER BY lower(a.value), a.value
LIMIT sqlc.arg('row_limit')::int;

-- name: SuggestCVEIDs :many
WITH sets AS (
    SELECT e.finding_set_id AS set_id, count(*)::bigint AS devices
    FROM advisory_evaluations e
    WHERE e.finding_set_id IS NOT NULL
      AND device_scope_matches(e.device_id, sqlc.arg('scope_unrestricted')::boolean, sqlc.arg('scopes')::jsonb)
      AND (NOT sqlc.arg('has_device')::boolean OR e.device_id = sqlc.arg('device_id')::uuid)
    GROUP BY e.finding_set_id
)
SELECT c.value::text AS value, sum(s.devices)::bigint AS count
FROM sets s
CROSS JOIN LATERAL (
    SELECT DISTINCT cve COLLATE "C" AS value
    FROM advisory_set_findings f
    CROSS JOIN LATERAL unnest(f.cves) AS cve
    WHERE f.set_id = s.set_id
) c
WHERE starts_with(lower(c.value), sqlc.arg('prefix')::text)
  AND (lower(c.value), c.value) > (lower(sqlc.arg('after')::text COLLATE "C"), sqlc.arg('after')::text COLLATE "C")
GROUP BY c.value
ORDER BY lower(c.value), c.value
LIMIT sqlc.arg('row_limit')::int;

-- name: SuggestDirectoryGroups :many
-- Group paths recorded from identity-provider claims at account sign-in.
SELECT (g.group_path COLLATE "C")::text AS value, count(*)::bigint AS count
FROM principal_groups g
WHERE starts_with(lower(g.group_path COLLATE "C"), sqlc.arg('prefix')::text)
  AND (lower(g.group_path COLLATE "C"), g.group_path COLLATE "C") > (lower(sqlc.arg('after')::text COLLATE "C"), sqlc.arg('after')::text COLLATE "C")
GROUP BY g.group_path COLLATE "C"
ORDER BY lower(g.group_path COLLATE "C"), g.group_path COLLATE "C"
LIMIT sqlc.arg('row_limit')::int;

-- name: SuggestHostInventoryValues :many
-- One kind of host_inventory_values of each in-scope device's current
-- generation, walked like SuggestPackageNames from one exclusive start key.
SELECT (v.value COLLATE "C")::text AS value, count(DISTINCT d.id)::bigint AS count
FROM host_inventory_values v
JOIN enrollment_generations g ON g.id = v.generation_id
JOIN devices d ON d.id = g.device_id AND d.current_generation_id = g.id
WHERE v.kind = sqlc.arg('kind')::smallint
  AND (lower(v.value COLLATE "C"), v.value COLLATE "C") > (sqlc.arg('start_lower')::text COLLATE "C", sqlc.arg('start_exact')::text COLLATE "C")
  AND (sqlc.arg('unbounded')::boolean OR lower(v.value COLLATE "C") < (sqlc.arg('prefix_end')::text COLLATE "C"))
  AND device_scope_matches(d.id, sqlc.arg('scope_unrestricted')::boolean, sqlc.arg('scopes')::jsonb)
  AND (NOT sqlc.arg('has_device')::boolean OR d.id = sqlc.arg('device_id')::uuid)
GROUP BY lower(v.value COLLATE "C"), v.value COLLATE "C"
ORDER BY lower(v.value COLLATE "C"), v.value COLLATE "C"
LIMIT sqlc.arg('row_limit')::int;
