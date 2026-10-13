-- name: InsertPlannedRollout :execrows
INSERT INTO resource_rollouts(id,definition,creator_id,stage_started_at,paused,pause_reason,name) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id) DO NOTHING;

-- name: InsertRolloutPlan :exec
INSERT INTO resource_rollout_plans(rollout_id,assignment_id,expected_revision,request_id,request,approval_required,status,reason,adopted)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9);

-- name: InsertRolloutDevicePlan :exec
INSERT INTO resource_rollout_device_plans(rollout_id,device_id,generation_id,resolution_sha256,adopts_existing,included,reviewed_head,state,reason)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9);

-- name: GetRolloutPlan :one
SELECT * FROM resource_rollout_plans WHERE rollout_id=$1;

-- name: LockRolloutPlan :one
SELECT * FROM resource_rollout_plans WHERE rollout_id=$1 FOR UPDATE;

-- name: UpdateRolloutPlanStatus :execrows
UPDATE resource_rollout_plans SET status=sqlc.arg(status),status_reason=sqlc.arg(status_reason),
 approval_id=coalesce(sqlc.narg(approval_id)::uuid,approval_id),
 started_at=coalesce(sqlc.narg(started_at)::timestamptz,started_at)
WHERE rollout_id=sqlc.arg(rollout_id) AND status=sqlc.arg(expected_status);

-- name: ActiveRolloutPlansForAssignment :many
SELECT rollout_id,status FROM resource_rollout_plans WHERE assignment_id=$1 AND status IN (1,2) FOR UPDATE;

-- name: ListAwaitingRolloutPlans :many
SELECT p.rollout_id,p.request,p.created_at,r.creator_id,r.revision
FROM resource_rollout_plans p JOIN resource_rollouts r ON r.id=p.rollout_id
WHERE p.status=1 AND p.rollout_id > sqlc.arg(after_id)::uuid ORDER BY p.rollout_id LIMIT 100;

-- name: ListRolloutActivations :many
-- Pending planned devices admitted by a frozen stage of an unpaused, started
-- rollout. Admission is the same cumulative, current-generation rule as matching.
SELECT p.rollout_id,p.device_id,r.creator_id
FROM resource_rollout_device_plans p
JOIN resource_rollout_plans rp ON rp.rollout_id=p.rollout_id AND rp.status=2
JOIN resource_rollouts r ON r.id=p.rollout_id AND NOT r.paused
WHERE p.state=1 AND (NOT p.included OR EXISTS (
 SELECT 1 FROM resource_rollout_members m
 WHERE m.rollout_id=p.rollout_id AND m.device_id=p.device_id AND m.membership=1 AND m.ring_index<=r.ring_index
))
ORDER BY p.updated_at,p.rollout_id,p.device_id LIMIT 50;

-- name: LockRolloutDevicePlan :one
SELECT * FROM resource_rollout_device_plans WHERE rollout_id=$1 AND device_id=$2 FOR UPDATE;

-- name: UpdateRolloutDevicePlan :execrows
UPDATE resource_rollout_device_plans SET state=sqlc.arg(state),reason=sqlc.arg(reason),preview_id=sqlc.narg(preview_id),updated_at=clock_timestamp()
WHERE rollout_id=sqlc.arg(rollout_id) AND device_id=sqlc.arg(device_id) AND state=1;

-- name: TouchRolloutDevicePlan :exec
-- A failed attempt moves the device behind other pending devices.
UPDATE resource_rollout_device_plans SET updated_at=clock_timestamp() WHERE rollout_id=$1 AND device_id=$2 AND state=1;

-- name: RolloutPlanCounts :one
SELECT count(*)::bigint AS planned,
 count(*) FILTER (WHERE p.state=1 AND p.included AND NOT EXISTS (SELECT 1 FROM resource_rollout_members m WHERE m.rollout_id=p.rollout_id AND m.device_id=p.device_id AND m.membership=1 AND m.ring_index<=sqlc.arg(ring_index)::integer))::bigint AS waiting,
 count(*) FILTER (WHERE p.state=1 AND (NOT p.included OR EXISTS (SELECT 1 FROM resource_rollout_members m WHERE m.rollout_id=p.rollout_id AND m.device_id=p.device_id AND m.membership=1 AND m.ring_index<=sqlc.arg(ring_index)::integer)))::bigint AS starting,
 count(*) FILTER (WHERE p.state=2)::bigint AS activated,
 count(*) FILTER (WHERE p.state=3)::bigint AS needs_review,
 count(*) FILTER (WHERE p.adopts_existing)::bigint AS adopting
FROM resource_rollout_device_plans p WHERE p.rollout_id=sqlc.arg(rollout_id)::uuid;

-- name: RolloutCreator :one
SELECT coalesce(nullif(p.display_name,''),a.username,'')::text AS display_name
FROM principals p LEFT JOIN local_accounts a ON a.id=p.id WHERE p.id=$1;

-- name: ListRolloutDevicePlans :many
-- Health is the device's latest admitted member row on its current head; it is
-- a progress projection, not the freshness-gated promotion assessment.
SELECT p.device_id,p.state,p.reason,p.adopts_existing,p.updated_at,d.hostname,
 (NOT p.included OR EXISTS (SELECT 1 FROM resource_rollout_members m WHERE m.rollout_id=p.rollout_id AND m.device_id=p.device_id AND m.membership=1 AND m.ring_index<=sqlc.arg(ring_index)::integer))::boolean AS admitted,
 coalesce((SELECT m.health FROM resource_rollout_members m
  JOIN resource_assignment_heads h ON h.generation_id=d.current_generation_id AND h.assignment_id=m.evidence_assignment_id
  WHERE m.rollout_id=p.rollout_id AND m.device_id=p.device_id AND m.membership=1 AND m.ring_index<=sqlc.arg(ring_index)::integer AND m.generation_id=d.current_generation_id
  ORDER BY m.ring_index DESC LIMIT 1),3)::smallint AS health,
 (d.state='active' AND d.current_generation_id=p.generation_id)::boolean AS current
FROM resource_rollout_device_plans p JOIN devices d ON d.id=p.device_id
WHERE p.rollout_id=sqlc.arg(rollout_id)::uuid AND p.device_id > sqlc.arg(after_id)::uuid
ORDER BY p.device_id LIMIT sqlc.arg(row_limit)::int;

-- name: OtherRolloutPlansResolution :one
-- Another started rollout will activate exactly this resolution on the device.
SELECT EXISTS (
 SELECT 1 FROM resource_rollout_device_plans p JOIN resource_rollout_plans rp ON rp.rollout_id=p.rollout_id AND rp.status=2
 WHERE p.device_id=$1 AND p.rollout_id<>$2 AND p.state=1 AND p.resolution_sha256=$3
)::boolean;

-- name: TargetExecutionHead :one
SELECT tp.document FROM target_execution_heads h JOIN target_previews tp ON tp.id=h.preview_id WHERE h.device_id=$1;

-- name: RevisionLabels :many
SELECT id,name,revision_number FROM profile_revisions WHERE id = ANY(sqlc.arg(ids)::uuid[]);

-- name: StaticGroupName :one
SELECT name FROM device_groups WHERE id=$1;

-- name: TargetDeviceHostname :one
SELECT coalesce(hostname,'')::text FROM devices WHERE id=$1;

-- name: GetDeviceDirectHead :one
-- The device's resource head when it was set directly on the device (it is
-- not the device's targeting execution preview); NULL otherwise.
SELECT h.assignment_id::uuid AS assignment_id
FROM devices d
JOIN resource_assignment_heads h ON h.generation_id = d.current_generation_id
WHERE d.id = $1
  AND h.assignment_id IS DISTINCT FROM (SELECT preview_id FROM target_execution_heads WHERE device_id = d.id);
