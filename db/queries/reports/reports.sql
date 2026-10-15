-- SPDX-License-Identifier: Apache-2.0

-- name: GetAuditHead :one
SELECT * FROM report_audit_head WHERE singleton;

-- name: GetAuditRow :one
SELECT * FROM report_audit_rows WHERE sequence = $1;

-- name: PageAuditRows :many
SELECT * FROM report_audit_rows
WHERE sequence > sqlc.arg('after_sequence') AND sequence <= sqlc.arg('final_sequence')
ORDER BY sequence LIMIT 128;

-- name: PageAuditSelection :many
SELECT r.*, f.occurred_at
FROM audit_event_search f
JOIN report_audit_rows r ON r.sequence = f.sequence
WHERE f.sequence <= sqlc.arg('snapshot_sequence')::bigint
  AND (sqlc.narg('actor_id')::uuid IS NULL OR f.actor_id = sqlc.narg('actor_id'))
  AND (sqlc.narg('target_device_id')::uuid IS NULL OR f.target_device_id = sqlc.narg('target_device_id'))
  AND (sqlc.arg('action_category')::smallint IN (0, 4) OR f.action_category = sqlc.arg('action_category'))
  AND (sqlc.arg('action_category')::smallint <> 4
       OR (f.actor_id IS NOT NULL
           AND NOT EXISTS (SELECT 1 FROM audit_events a WHERE a.id = f.event_id AND a.action = ANY(sqlc.arg('human_excluded_actions')::text[]))))
  AND (sqlc.narg('occurred_from')::timestamptz IS NULL OR f.occurred_at >= sqlc.narg('occurred_from'))
  AND (sqlc.narg('occurred_until')::timestamptz IS NULL OR f.occurred_at < sqlc.narg('occurred_until'))
  AND (sqlc.narg('cursor_id')::uuid IS NULL
       OR (f.occurred_at, f.event_id) < (sqlc.narg('cursor_occurred_at')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY f.occurred_at DESC, f.event_id DESC
LIMIT 128;

-- name: GetReportMutation :one
SELECT * FROM report_mutations WHERE actor_id = $1 AND request_id = $2;

-- name: InsertReportMutation :exec
INSERT INTO report_mutations(actor_id,request_id,request_hash,response) VALUES ($1,$2,$3,$4);

-- name: InsertReportAudit :exec
INSERT INTO audit_events(actor_id,action,resource_id,reason) VALUES ($1,$2,$3,$4);

-- name: CreateReportSchedule :one
INSERT INTO report_schedules(id,actor_id,name,kind,format,interval_seconds,retention_days,enabled,revision)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,1) RETURNING *;

-- name: UpdateReportSchedule :one
UPDATE report_schedules SET actor_id = sqlc.arg('actor_id'), name = sqlc.arg('name'),
kind = sqlc.arg('kind'), format = sqlc.arg('format'), interval_seconds = sqlc.arg('interval_seconds'),
retention_days = sqlc.arg('retention_days'), enabled = sqlc.arg('enabled'), revision = revision+1,
next_run_at = now(), lease_token = NULL, lease_until = NULL
WHERE id = sqlc.arg('id') AND revision = sqlc.arg('expected_revision') RETURNING *;

-- name: ListReportSchedules :many
SELECT * FROM report_schedules WHERE id > sqlc.arg('after_id')::uuid ORDER BY id LIMIT sqlc.arg('row_limit')::int;

-- name: QueueDueReport :one
WITH candidate AS (
 SELECT id FROM report_schedules WHERE enabled AND next_run_at <= now()
 AND (lease_until IS NULL OR lease_until < now())
 ORDER BY next_run_at,id FOR UPDATE SKIP LOCKED LIMIT 1
), claimed AS (
 UPDATE report_schedules s SET lease_token = sqlc.arg('lease_token')::uuid, lease_until = now()+interval '60 seconds',
 next_run_at = now()+s.interval_seconds*interval '1 second'
 FROM candidate c WHERE s.id = c.id RETURNING s.*
), queued AS (
 INSERT INTO report_artifacts(id,schedule_id,actor_id,kind,format,expires_at)
 SELECT sqlc.arg('artifact_id')::uuid,id,actor_id,kind,format,now()+retention_days*interval '1 day' FROM claimed
 RETURNING *
)
SELECT * FROM queued;

-- name: CreateAuditArtifact :one
INSERT INTO report_artifacts(id,actor_id,kind,format,expires_at,after_sequence,after_hash,final_sequence,final_hash,captured_head_sequence,captured_head_hash,chain_id)
VALUES (sqlc.arg('id'),sqlc.arg('actor_id'),4,3,now()+sqlc.arg('retention_days')::int*interval '1 day',
sqlc.arg('after_sequence'),sqlc.arg('after_hash'),sqlc.arg('final_sequence'),sqlc.arg('final_hash'),sqlc.arg('captured_head_sequence'),sqlc.arg('captured_head_hash'),sqlc.arg('chain_id')) RETURNING *;

-- name: CreateAuditSelectionArtifact :one
INSERT INTO report_artifacts(id,actor_id,kind,format,expires_at,captured_head_sequence,captured_head_hash,chain_id,audit_filter,audit_max_events)
VALUES (sqlc.arg('id'),sqlc.arg('actor_id'),5,3,now()+sqlc.arg('retention_days')::int*interval '1 day',
sqlc.arg('captured_head_sequence'),sqlc.arg('captured_head_hash'),sqlc.arg('chain_id'),sqlc.arg('audit_filter'),sqlc.arg('audit_max_events')) RETURNING *;

-- name: ClaimReportArtifact :one
WITH candidate AS (
 SELECT id FROM report_artifacts WHERE expires_at > now() AND
 (state = 'queued' OR (state = 'building' AND lease_until < now()))
 ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1
)
UPDATE report_artifacts a SET state = 'building', lease_token = sqlc.arg('lease_token')::uuid,
lease_until = now()+interval '60 seconds' FROM candidate c WHERE a.id = c.id RETURNING a.*;

-- name: LockReportArtifact :one
SELECT * FROM report_artifacts WHERE id = sqlc.arg('id') AND state = 'building'
AND lease_token = sqlc.arg('lease_token')::uuid AND lease_until > clock_timestamp() AND expires_at > clock_timestamp()
FOR UPDATE;

-- name: InsertReportChunk :exec
INSERT INTO report_artifact_chunks(artifact_id,chunk_index,data) VALUES ($1,$2,$3);

-- name: PublishReportArtifact :execrows
UPDATE report_artifacts SET state = 'published', byte_count = sqlc.arg('byte_count'),row_count = sqlc.arg('row_count'),
chunk_count = sqlc.arg('chunk_count'),signed_manifest = sqlc.arg('signed_manifest'),lease_until = NULL
WHERE id = sqlc.arg('id') AND state = 'building' AND lease_token = sqlc.arg('lease_token')::uuid
AND lease_until > clock_timestamp() AND expires_at > clock_timestamp();

-- name: FailReportArtifact :execrows
UPDATE report_artifacts SET state = 'failed', failure_reason = sqlc.arg('failure_reason'),lease_until = NULL
WHERE id = sqlc.arg('id') AND state = 'building' AND lease_token = sqlc.arg('lease_token')::uuid AND lease_until > clock_timestamp();

-- name: ListReportArtifacts :many
SELECT * FROM report_artifacts WHERE id > sqlc.arg('after_id')::uuid AND expires_at > now()
ORDER BY id LIMIT sqlc.arg('row_limit')::int;

-- name: GetReportArtifact :one
SELECT * FROM report_artifacts WHERE id = $1 AND expires_at > now();

-- name: DownloadReportChunk :one
SELECT c.data FROM report_artifact_chunks c JOIN report_artifacts a ON a.id = c.artifact_id
WHERE c.artifact_id = sqlc.arg('artifact_id') AND c.chunk_index = sqlc.arg('chunk_index')
AND a.state = 'published' AND a.expires_at > now();

-- name: PruneReportArtifacts :execrows
DELETE FROM report_artifacts WHERE id IN (
 SELECT id FROM report_artifacts WHERE expires_at <= now()
 ORDER BY expires_at FOR UPDATE SKIP LOCKED LIMIT 20
);

-- name: InventoryReportRows :many
SELECT d.id::text AS cursor, jsonb_build_object(
'device_id',d.id,'hostname',d.hostname,'state',d.state,'os_id',d.os_id,'os_version',d.os_version,
'architecture',d.architecture,'enrolled_at',d.enrolled_at,'last_seen_at',d.last_seen_at,
'host_received_at',d.host_received_at,'snapshot_received_at',d.snapshot_received_at,
'published_sequence',d.published_sequence)::text AS record
FROM devices d WHERE d.id > sqlc.arg('after_id')::uuid ORDER BY d.id LIMIT 128;

-- name: ComplianceReportRows :many
SELECT (r.device_id::text || '/' || r.resource_id::text)::text AS cursor,
jsonb_build_object('device_id',r.device_id,'assignment_id',r.assignment_id,'resource_id',r.resource_id,
'resource_kind',r.resource_kind,'canonical_key',r.canonical_key,'reason',CASE WHEN r.blocked_reason <> '' THEN r.blocked_reason ELSE r.reason END,
'last_verified_at',r.last_verified_at,'observed_at',r.observed_at,
'state', CASE WHEN r.blocked_reason <> '' OR r.disposition IN (4,5,6,7) OR r.applying OR r.dependency_attention
THEN 'ATTENTION' WHEN r.last_verified_at IS NULL THEN 'UNKNOWN'
WHEN r.last_verified_at + LEAST(r.reconcile_interval_seconds*2,r.verification_max_age_seconds)*interval '1 second' <= now() THEN 'STALE'
WHEN r.drift_remediated THEN 'DRIFT_REMEDIATED' ELSE 'COMPLIANT' END)::text AS record
FROM integration_compliance_projection r
WHERE r.device_id::text || '/' || r.resource_id::text > sqlc.arg('after_cursor')::text
ORDER BY r.device_id::text || '/' || r.resource_id::text LIMIT 128;

-- name: FindingsReportRows :many
-- Finding keys are unique per device, not globally: page by (device, finding).
SELECT (f.device_id::text || '/' || f.id::text)::text AS cursor, jsonb_build_object('finding_id',f.id,'device_id',f.device_id,
'advisory_id',f.advisory_id,'package_name',f.package_name,'installed_version',f.installed_version,
'fixed_version',f.fixed_version,'architecture',f.architecture,'severity',f.severity,
'state',CASE WHEN advisory_rpm_authority_current(d.os_id,d.os_version,sqlc.arg('rpm_authority_valid')::boolean) THEN f.state ELSE 'unknown' END,
'evaluated_at',f.evaluated_at,'inventory_at',f.inventory_at)::text AS record
FROM advisory_finding_status f
JOIN devices d ON d.id=f.device_id
WHERE (f.device_id, f.id) > (sqlc.arg('after_device')::uuid, sqlc.arg('after_id')::uuid)
ORDER BY f.device_id, f.id LIMIT 128;
