-- SPDX-License-Identifier: Apache-2.0

-- name: ImpactIsolation :one
SELECT current_setting('transaction_isolation')::text AS isolation;

-- name: LockTargetImpactInputs :exec
-- READ COMMITTED only: acquire before the first candidate/catalog read. These
-- locks also fence absent members and new devices, which row locks cannot do.
LOCK TABLE devices, device_groups, device_group_memberships, device_labels,
 enrollment_generations, host_observations, inventory_attribute_definitions,
 resource_assignment_heads, resource_assignments, resource_assignment_resources,
 profile_revisions IN SHARE MODE;

-- name: ListImpactCandidates :many
SELECT d.id, device_scope_matches(d.id, sqlc.arg(unrestricted)::boolean, sqlc.arg(scopes)::jsonb)::boolean AS visible
FROM devices d
WHERE d.id > sqlc.arg(after_id)::uuid
AND (sqlc.arg(all_devices)::boolean OR d.id = ANY(sqlc.arg(device_ids)::uuid[])
 OR EXISTS (SELECT 1 FROM device_group_memberships m WHERE m.device_id=d.id AND m.group_id=ANY(sqlc.arg(group_ids)::uuid[])))
ORDER BY d.id LIMIT 200;

-- name: ListImpactDevicePage :many
-- Load the same scoped, locked TargetingDevice inputs for one candidate page.
-- Candidate visibility remains separate so hidden members make the report
-- incomplete without disclosing their inputs or aggregate counts.
SELECT d.id, d.current_generation_id, d.state,
 coalesce(h.hostname_value,'')::text AS hostname,
 coalesce(h.os_id_value,'')::text AS os_id,
 coalesce(h.os_version_value,'')::text AS os_version,
 coalesce(h.hostname_status,0)::smallint AS hostname_status,
 coalesce(h.os_id_status,0)::smallint AS os_id_status,
 coalesce(h.os_version_status,0)::smallint AS os_version_status,
 coalesce(g.host_sequence,0)::bigint AS host_sequence,
 coalesce(h.digest,''::bytea)::bytea AS host_digest,
 d.architecture, d.last_seen_at, h.received_at AS host_received_at, d.metadata,
 ARRAY(SELECT label FROM device_labels WHERE device_id=d.id ORDER BY label)::text[] AS labels,
 ARRAY(SELECT group_id::text FROM device_group_memberships WHERE device_id=d.id ORDER BY group_id)::text[] AS groups,
 coalesce((SELECT preview_id::text FROM target_execution_heads WHERE device_id=d.id),'')::text AS previous_preview_id,
 coalesce((SELECT assignment_id::text FROM resource_assignment_heads WHERE generation_id=d.current_generation_id),'')::text AS resource_assignment_id
FROM devices d
LEFT JOIN enrollment_generations g ON g.id=d.current_generation_id
LEFT JOIN host_observations h ON h.generation_id=g.id AND h.sequence=g.host_sequence
WHERE d.id=ANY(sqlc.arg(device_ids)::uuid[])
AND device_scope_matches(d.id, sqlc.arg(unrestricted)::boolean, sqlc.arg(scopes)::jsonb)
ORDER BY d.id LIMIT 200
FOR UPDATE OF d;

-- name: InsertImpactDevice :copyfrom
INSERT INTO target_assignment_impact_devices(report_id,device_id,document) VALUES ($1,$2,$3);

-- name: InsertImpactReport :exec
INSERT INTO target_assignment_impact_reports(id,actor_id,document,input_digest,expires_at) VALUES ($1,$2,$3,$4,$5);

-- name: GetImpactReport :one
SELECT document,input_digest FROM target_assignment_impact_reports WHERE id=$1 AND actor_id=$2;

-- name: ListImpactDevices :many
SELECT device_id,document FROM target_assignment_impact_devices
WHERE report_id=$1 AND device_id>sqlc.arg(after_id)::uuid ORDER BY device_id LIMIT sqlc.arg(row_limit)::int;

-- name: ImpactDevicesVisible :one
-- An unrestricted grant already covers every retained row. Keep the full
-- current-scope check for scoped grants, including rows outside this page.
SELECT CASE WHEN sqlc.arg(unrestricted)::boolean THEN true ELSE
 NOT EXISTS(SELECT 1 FROM target_assignment_impact_devices r WHERE r.report_id=sqlc.arg(report_id)
  AND device_scope_matches(r.device_id,false,sqlc.arg(scopes)::jsonb) IS NOT TRUE)
END::boolean;

-- name: PruneImpactReports :exec
DELETE FROM target_assignment_impact_reports WHERE id IN (
 SELECT id FROM target_assignment_impact_reports WHERE expires_at<=clock_timestamp() ORDER BY expires_at,id LIMIT 100
) OR id IN (
 SELECT r.id FROM target_assignment_impact_reports r WHERE r.actor_id=sqlc.arg(actor_id) ORDER BY r.created_at DESC,r.id DESC OFFSET 4
);
