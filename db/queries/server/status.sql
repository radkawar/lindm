-- SPDX-License-Identifier: Apache-2.0

-- name: ServerFeedHealth :one
SELECT count(*)::bigint AS enabled,
 count(*) FILTER (WHERE error <> '')::bigint AS failed,
 count(*) FILTER (WHERE checked_at IS NULL OR expires_at IS NULL)::bigint AS unknown,
 count(*) FILTER (WHERE expires_at <= CURRENT_TIMESTAMP)::bigint AS stale,
 min(checked_at)::timestamptz AS evidence_at,
 min(expires_at)::timestamptz AS expires_at
FROM advisory_feeds WHERE enabled;

-- name: ServerQueueHealth :one
SELECT
 (SELECT count(*) FROM integration_deliveries WHERE status = 4)::bigint AS failed,
 (SELECT count(*) FROM integration_deliveries WHERE status IN (1,2))::bigint AS pending,
 (SELECT min(next_attempt_at) FROM integration_deliveries WHERE status IN (1,2))::timestamptz AS oldest_due_at,
 (SELECT min(next_run_at) FROM report_schedules WHERE enabled)::timestamptz AS report_due_at;

-- name: RecordServerStatusTransition :one
WITH changed AS (
 INSERT INTO server_status_alerts(instance, component, state, has_degradation, evidence_key, notified_at)
 SELECT sqlc.arg('instance'), sqlc.arg('component'), sqlc.arg('state'), sqlc.arg('state')::integer IN (1,3,4), sqlc.arg('evidence_key'), CURRENT_TIMESTAMP
 WHERE EXISTS (SELECT 1 FROM integration_destinations WHERE enabled AND deleted_at IS NULL)
 ON CONFLICT (instance, component) DO UPDATE
 SET state = EXCLUDED.state, notified_at = EXCLUDED.notified_at, evidence_key = EXCLUDED.evidence_key,
   has_degradation = server_status_alerts.has_degradation OR EXCLUDED.has_degradation
 WHERE server_status_alerts.state <> EXCLUDED.state
    OR (EXCLUDED.state IN (1,3,4) AND server_status_alerts.evidence_key <> EXCLUDED.evidence_key)
    OR (EXCLUDED.state IN (1,3,4) AND server_status_alerts.notified_at <= CURRENT_TIMESTAMP - interval '6 hours')
 RETURNING state, has_degradation
), emitted AS (
 INSERT INTO audit_events(action, resource_id, details)
 SELECT CASE WHEN state = 2 THEN 'server.status.recovered'
             WHEN state = 4 THEN 'server.status.failed'
             WHEN state = 3 THEN 'server.status.attention'
             WHEN state = 1 THEN 'server.status.unknown'
             ELSE 'server.status.inactive' END,
   'server/' || sqlc.arg('instance')::text || '/' || sqlc.arg('component')::text,
   jsonb_build_object('state', state)
 FROM changed WHERE has_degradation
 RETURNING id
)
SELECT count(*)::bigint FROM emitted;
