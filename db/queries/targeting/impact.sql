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

-- name: InsertImpactDevice :exec
INSERT INTO target_assignment_impact_devices(report_id,device_id,document) VALUES ($1,$2,$3);

-- name: InsertImpactReport :exec
INSERT INTO target_assignment_impact_reports(id,actor_id,document,input_digest,expires_at) VALUES ($1,$2,$3,$4,$5);

-- name: GetImpactReport :one
SELECT document,input_digest FROM target_assignment_impact_reports WHERE id=$1 AND actor_id=$2;

-- name: ListImpactDevices :many
SELECT device_id,document FROM target_assignment_impact_devices
WHERE report_id=$1 AND device_id>sqlc.arg(after_id)::uuid ORDER BY device_id LIMIT sqlc.arg(row_limit)::int;

-- name: ImpactDevicesVisible :one
SELECT NOT EXISTS(SELECT 1 FROM target_assignment_impact_devices r WHERE r.report_id=sqlc.arg(report_id)
 AND device_scope_matches(r.device_id,sqlc.arg(unrestricted)::boolean,sqlc.arg(scopes)::jsonb) IS NOT TRUE)::boolean;

-- name: PruneImpactReports :exec
DELETE FROM target_assignment_impact_reports WHERE id IN (
 SELECT id FROM target_assignment_impact_reports WHERE expires_at<=clock_timestamp() ORDER BY expires_at,id LIMIT 100
) OR id IN (
 SELECT r.id FROM target_assignment_impact_reports r WHERE r.actor_id=sqlc.arg(actor_id) ORDER BY r.created_at DESC,r.id DESC OFFSET 4
);
