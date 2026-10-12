-- name: DeleteHostApprovedReferences :exec
-- Clears a generation's reports before its latest accepted observation's.
DELETE FROM host_approved_references
WHERE generation_id = sqlc.arg('generation_id');

-- name: InsertHostApprovedReference :exec
-- At most 64 rows per observation (32 per kind, bounded in protobuf).
INSERT INTO host_approved_references (generation_id, kind, reference_id, name, format, location)
VALUES (sqlc.arg('generation_id'), sqlc.arg('kind'), sqlc.arg('reference_id'), sqlc.arg('name'), sqlc.arg('format'), sqlc.arg('location'))
ON CONFLICT DO NOTHING;
-- name: ListApprovedReferences :many
-- One kind of the references in-scope devices' current generations report,
-- walked in (lowercase name, name, reference ID) order from one exclusive
-- start key. A reference reported under two names is listed once per name.
SELECT (r.reference_id COLLATE "C")::text AS reference_id,
       (r.name COLLATE "C")::text AS name,
       min(r.format)::text AS format,
       min(r.location)::text AS location,
       count(DISTINCT d.id)::bigint AS device_count
FROM host_approved_references r
JOIN enrollment_generations g ON g.id = r.generation_id
JOIN devices d ON d.id = g.device_id AND d.current_generation_id = g.id
WHERE r.kind = sqlc.arg('kind')::smallint
  AND (lower(r.name COLLATE "C"), r.name COLLATE "C", r.reference_id COLLATE "C")
      > (sqlc.arg('start_lower')::text COLLATE "C", sqlc.arg('start_name')::text COLLATE "C", sqlc.arg('start_reference')::text COLLATE "C")
  AND (sqlc.arg('unbounded')::boolean OR lower(r.name COLLATE "C") < (sqlc.arg('prefix_end')::text COLLATE "C"))
  AND device_scope_matches(d.id, sqlc.arg('scope_unrestricted')::boolean, sqlc.arg('scopes')::jsonb)
GROUP BY lower(r.name COLLATE "C"), r.name COLLATE "C", r.reference_id COLLATE "C"
ORDER BY lower(r.name COLLATE "C"), r.name COLLATE "C", r.reference_id COLLATE "C"
LIMIT sqlc.arg('row_limit')::int;
