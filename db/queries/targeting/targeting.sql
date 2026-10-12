-- name: LockTargeting :exec
-- Updating the fence forces REPEATABLE READ waiters to reject a stale snapshot.
UPDATE targeting_lock SET revision=revision+1 WHERE singleton;

-- name: LockTargetingShared :exec
-- Device dispatch that cannot change targeting or rollout state shares the
-- fence: every LockTargeting writer waits for it, while dispatches to other
-- devices proceed in parallel. It never advances the revision, so it forces no
-- REPEATABLE READ waiter to retry; such dispatch writes only per-device state.
SELECT singleton FROM targeting_lock WHERE singleton FOR SHARE;

-- name: LockTargetingDevice :one
SELECT id FROM devices WHERE id=$1 FOR UPDATE;

-- name: TargetingClock :one
SELECT clock_timestamp()::timestamptz AS now;

-- name: TargetingDevice :one
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
WHERE d.id=sqlc.arg(device_id)
AND device_scope_matches(d.id, sqlc.arg(unrestricted)::boolean, sqlc.arg(scopes)::jsonb)
FOR UPDATE OF d;

-- name: TargetingDeviceSnapshot :one
-- The unlocked, unscoped TargetingDevice row for system membership reads
-- (capability grants) inside the caller's snapshot; it fences nothing.
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
WHERE d.id=sqlc.arg(device_id);

-- name: ListTargetingDevices :many
SELECT id FROM devices WHERE id > sqlc.arg(after_id)::uuid ORDER BY id LIMIT 200;

-- name: ListTargetingDevicePage :many
-- Read-only evaluation input for unsaved group previews: the TargetingDevice
-- columns without row locks, one bounded page at a time.
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
 ''::text AS previous_preview_id,
 ''::text AS resource_assignment_id
FROM devices d
LEFT JOIN enrollment_generations g ON g.id=d.current_generation_id
LEFT JOIN host_observations h ON h.generation_id=g.id AND h.sequence=g.host_sequence
WHERE d.id > sqlc.arg(after_id)::uuid
ORDER BY d.id LIMIT 200;

-- name: GetTargetingRequest :one
SELECT method, digest, response FROM targeting_requests WHERE actor_id=$1 AND request_id=$2;

-- name: InsertTargetingRequest :exec
INSERT INTO targeting_requests(actor_id,request_id,method,digest,response) VALUES ($1,$2,$3,$4,$5);

-- name: TargetingAudit :exec
INSERT INTO audit_events(id,occurred_at,actor_id,action,resource_id,reason,details)
VALUES ($1,clock_timestamp(),$2,$3,$4,$5,jsonb_strip_nulls(jsonb_build_object('context',NULLIF(sqlc.arg('context')::text,''))));

-- name: GetDynamicGroup :one
SELECT id,revision,definition,name FROM dynamic_target_groups WHERE id=$1;

-- name: ListDynamicGroups :many
SELECT id,revision,definition,name FROM dynamic_target_groups
WHERE id > sqlc.arg(after_id)::uuid
  AND (sqlc.arg(name_search)::text = '' OR strpos(lower(name), lower(sqlc.arg(name_search)::text)) > 0)
ORDER BY id LIMIT sqlc.arg(row_limit)::int;

-- name: PutDynamicGroup :execrows
INSERT INTO dynamic_target_groups(id,revision,definition,name) SELECT sqlc.arg(id),1,sqlc.arg(definition),sqlc.arg(name) WHERE sqlc.arg(expected)::bigint=0
ON CONFLICT(id) DO UPDATE SET revision=dynamic_target_groups.revision+1,definition=EXCLUDED.definition,name=EXCLUDED.name WHERE dynamic_target_groups.revision=sqlc.arg(expected)::bigint;

-- name: UpdateDynamicGroup :execrows
UPDATE dynamic_target_groups SET revision=revision+1,definition=$2,name=$3 WHERE id=$1 AND revision=$4;

-- name: InsertDynamicGroupRevision :exec
INSERT INTO dynamic_target_group_revisions(group_id,revision,definition,actor_id) VALUES ($1,$2,$3,$4);

-- name: ListTargetAssignments :many
SELECT id,revision,definition,actor_id FROM target_assignments WHERE id > sqlc.arg(after_id)::uuid ORDER BY id LIMIT sqlc.arg(row_limit)::int;

-- name: PutTargetAssignment :execrows
INSERT INTO target_assignments(id,revision,definition,actor_id) VALUES ($1,1,$2,$3) ON CONFLICT(id) DO NOTHING;

-- name: UpdateTargetAssignment :execrows
UPDATE target_assignments SET revision=revision+1,definition=$2,actor_id=$3 WHERE id=$1 AND revision=$4;

-- name: InsertTargetAssignmentRevision :exec
INSERT INTO target_assignment_revisions(assignment_id,revision,definition,actor_id) VALUES ($1,$2,$3,$4);

-- name: TargetStaticGroupExists :one
SELECT EXISTS(SELECT 1 FROM device_groups WHERE id=$1)::boolean;

-- name: InsertTargetPreview :exec
INSERT INTO target_previews(id,device_id,actor_id,document,digest) VALUES ($1,$2,$3,$4,$5);

-- name: GetTargetPreview :one
SELECT device_id,actor_id,document,digest FROM target_previews WHERE id=$1;

-- name: InsertTargetMembership :exec
INSERT INTO target_membership_snapshots(preview_id,group_id,group_revision,device_id,input_digest,membership,group_kind) VALUES ($1,$2,$3,$4,$5,$6,$7);

-- name: SetTargetExecutionHead :exec
INSERT INTO target_execution_heads(device_id,preview_id) VALUES ($1,$2) ON CONFLICT(device_id) DO UPDATE SET preview_id=EXCLUDED.preview_id;

-- name: InsertRollout :execrows
INSERT INTO resource_rollouts(id,definition,creator_id,stage_started_at,name) VALUES ($1,$2,$3,$4,$5) ON CONFLICT(id) DO NOTHING;

-- name: GetRollout :one
SELECT * FROM resource_rollouts WHERE id=$1;

-- name: ListRollouts :many
SELECT id FROM resource_rollouts
WHERE id > sqlc.arg(after_id)::uuid
  AND (sqlc.arg(name_search)::text = '' OR strpos(lower(name), lower(sqlc.arg(name_search)::text)) > 0)
ORDER BY id LIMIT sqlc.arg(row_limit)::int;

-- name: ListActiveRollouts :many
SELECT id,creator_id,revision FROM resource_rollouts WHERE NOT paused AND id > sqlc.arg(after_id)::uuid ORDER BY id LIMIT 100;

-- name: InsertRolloutStage :exec
INSERT INTO resource_rollout_stages(rollout_id,ring_index,selected_count,pending_count,excluded_count) VALUES ($1,$2,$3,$4,$5);

-- name: GetRolloutStage :one
SELECT selected_count,pending_count,excluded_count FROM resource_rollout_stages WHERE rollout_id=$1 AND ring_index=$2;

-- name: InsertRolloutMember :exec
INSERT INTO resource_rollout_members(rollout_id,ring_index,device_id,generation_id,bucket,membership) VALUES ($1,$2,$3,$4,$5,$6);

-- name: GetRolloutMember :one
-- Admission is cumulative across frozen stages; advancing to another explicit
-- cohort must not silently stop management of an already admitted canary.
SELECT membership FROM resource_rollout_members m WHERE rollout_id=$1 AND ring_index<=$2 AND device_id=$3 AND membership=1
AND generation_id=(SELECT current_generation_id FROM devices WHERE id=m.device_id)
ORDER BY ring_index DESC LIMIT 1;

-- name: RolloutHealthCounts :one
-- Availability is maintained by authenticated sync and accepted dispatch traffic,
-- not native verification. Its heartbeat-tolerant cutoff must not refresh proof.
WITH admitted AS MATERIALIZED (
 SELECT DISTINCT ON (device_id) * FROM resource_rollout_members
 WHERE rollout_id=sqlc.arg(rollout_id)::uuid AND ring_index<=sqlc.arg(ring_index)::integer AND membership=1
 ORDER BY device_id,ring_index DESC
)
SELECT count(*)::bigint AS targeted,
 count(*) FILTER (WHERE m.health=1 AND h.assignment_id=m.evidence_assignment_id AND m.received_at>=sqlc.arg(fresh_after)::timestamptz AND m.health_valid_until>sqlc.arg(assessed_at)::timestamptz AND d.last_seen_at>=sqlc.arg(availability_after)::timestamptz AND d.state='active' AND d.current_generation_id=m.generation_id)::bigint AS healthy,
 count(*) FILTER (WHERE m.ring_index=sqlc.arg(ring_index)::integer AND m.health=1 AND h.assignment_id=m.evidence_assignment_id AND m.received_at>=sqlc.arg(fresh_after)::timestamptz AND m.health_valid_until>sqlc.arg(assessed_at)::timestamptz AND d.last_seen_at>=sqlc.arg(availability_after)::timestamptz AND d.state='active' AND d.current_generation_id=m.generation_id)::bigint AS current_healthy,
 count(*) FILTER (WHERE m.health=2 AND h.assignment_id=m.evidence_assignment_id AND m.received_at>=sqlc.arg(fresh_after)::timestamptz AND d.last_seen_at>=sqlc.arg(availability_after)::timestamptz AND d.state='active' AND d.current_generation_id=m.generation_id)::bigint AS failed,
 count(*) FILTER (WHERE (m.health=4 AND h.assignment_id=m.evidence_assignment_id) OR d.last_seen_at IS NULL OR d.last_seen_at<sqlc.arg(availability_after)::timestamptz OR d.state<>'active' OR d.current_generation_id IS DISTINCT FROM m.generation_id)::bigint AS unavailable
FROM admitted m JOIN devices d ON d.id=m.device_id
LEFT JOIN resource_assignment_heads h ON h.generation_id=d.current_generation_id;

-- name: UpdateRollout :execrows
UPDATE resource_rollouts SET revision=revision+1,ring_index=$2,paused=$3,pause_reason=$4,stage_started_at=$5 WHERE id=$1 AND revision=sqlc.arg(expected_revision)::bigint;

-- name: InsertRolloutEvent :exec
INSERT INTO resource_rollout_events(id,rollout_id,revision,actor_id,reason) VALUES ($1,$2,$3,$4,$5);

-- name: CurrentExecutionHealth :one
SELECT (CASE
 WHEN bool_or(r.disposition IN (4,5) AND r.reason NOT IN ('outcome_unknown','verification_unknown','not_applicable')) THEN 2
 WHEN bool_or(r.disposition=6) THEN 4
 WHEN count(r.resource_id)>0 AND bool_and(r.disposition=3 AND r.last_verified_at IS NOT NULL
  AND r.last_verified_at>=sqlc.arg(fresh_after)::timestamptz
  AND r.last_verified_at+make_interval(secs => LEAST(2*a.reconcile_interval_seconds,r.verification_max_age_seconds))>clock_timestamp()) THEN 1
 ELSE 3 END)::smallint AS health,
 min(r.last_verified_at)::timestamptz AS oldest_verified_at,
 min(r.last_verified_at+make_interval(secs => LEAST(2*a.reconcile_interval_seconds,r.verification_max_age_seconds)))::timestamptz AS native_valid_until
FROM resource_assignments a
JOIN resource_assignment_heads h ON h.assignment_id=a.id AND h.generation_id=a.generation_id
JOIN devices d ON d.id=a.device_id AND d.current_generation_id=a.generation_id AND d.state='active'
-- Rows not applicable to this device's platform are neither health nor evidence.
LEFT JOIN resource_assignment_resources r ON r.assignment_id=a.id AND r.disposition<>8
WHERE a.id=sqlc.arg(assignment_id) AND a.device_id=sqlc.arg(device_id) AND a.generation_id=sqlc.arg(generation_id)
GROUP BY a.id;

-- name: UpdateRolloutExecutionHealth :execrows
UPDATE resource_rollout_members SET health=$4,received_at=$6,health_valid_until=$7,evidence_assignment_id=$8
WHERE rollout_id=$1 AND ring_index<=$2 AND device_id=$3 AND generation_id=$5 AND membership=1;

-- name: TargetProfileRevisionExists :one
SELECT EXISTS(SELECT 1 FROM profile_revisions WHERE id=$1)::boolean;

-- name: TargetDeviceExists :one
SELECT EXISTS(SELECT 1 FROM devices WHERE id=$1)::boolean;

-- name: GetTargetAttributeDefinition :one
-- Row sharing pins referenced definition semantics through preview/activation.
SELECT definition FROM inventory_attribute_definitions WHERE key=$1 FOR SHARE;
