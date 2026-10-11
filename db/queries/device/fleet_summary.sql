-- name: FleetSummaryCounts :one
SELECT CURRENT_TIMESTAMP::timestamptz AS observed_at,
 count(*)::bigint AS total_devices,
 count(*) FILTER (WHERE d.state = 'pending')::bigint AS pending_devices,
 count(*) FILTER (WHERE d.state = 'active')::bigint AS active_devices,
 count(*) FILTER (WHERE d.state = 'revoked')::bigint AS revoked_devices,
 count(*) FILTER (WHERE d.state = 'recovery_hold')::bigint AS recovery_hold_devices,
 count(*) FILTER (WHERE d.last_seen_at >= CURRENT_TIMESTAMP - interval '24 hours')::bigint AS recent_devices,
 count(*) FILTER (WHERE d.last_seen_at < CURRENT_TIMESTAMP - interval '24 hours')::bigint AS stale_devices,
 count(*) FILTER (WHERE d.last_seen_at IS NULL)::bigint AS unknown_devices,
 count(*) FILTER (WHERE NOT EXISTS (
   SELECT 1 FROM resource_assignment_heads h
   JOIN resource_assignment_resources r ON r.assignment_id = h.assignment_id
   WHERE h.generation_id = d.current_generation_id
 ))::bigint AS unassigned_devices
FROM devices d
WHERE device_scope_matches(d.id, sqlc.arg('scope_unrestricted')::boolean, sqlc.arg('scopes')::jsonb);

-- name: FleetSummaryOS :many
-- Bounded output, exact full-population group counts; the caller subtracts these
-- from total_devices to expose the exact remaining population as other_devices.
SELECT d.os_id, d.os_version, count(*)::bigint AS devices
FROM devices d
WHERE device_scope_matches(d.id, sqlc.arg('scope_unrestricted')::boolean, sqlc.arg('scopes')::jsonb)
GROUP BY d.os_id, d.os_version
ORDER BY devices DESC, d.os_id, d.os_version
LIMIT 20;

-- name: FleetSummaryCompliance :one
WITH resources AS (
 SELECT CASE
   WHEN p.blocked_reason <> '' OR p.disposition IN (4, 5, 6, 7) OR p.applying OR p.dependency_attention THEN 'attention'
   WHEN p.last_verified_at IS NULL THEN 'unknown'
   WHEN p.last_verified_at + make_interval(secs => LEAST(2 * p.reconcile_interval_seconds, p.verification_max_age_seconds)) <= CURRENT_TIMESTAMP THEN 'stale'
   WHEN p.drift_remediated THEN 'drift_remediated'
   ELSE 'compliant'
 END AS compliance
 FROM integration_compliance_projection p
 WHERE device_scope_matches(p.device_id, sqlc.arg('scope_unrestricted')::boolean, sqlc.arg('scopes')::jsonb)
)
SELECT count(*)::bigint AS total_resources,
 count(*) FILTER (WHERE compliance = 'compliant')::bigint AS compliant_resources,
 count(*) FILTER (WHERE compliance = 'drift_remediated')::bigint AS drift_remediated_resources,
 count(*) FILTER (WHERE compliance = 'attention')::bigint AS attention_resources,
 count(*) FILTER (WHERE compliance = 'stale')::bigint AS stale_resources,
 count(*) FILTER (WHERE compliance = 'unknown')::bigint AS unknown_resources
FROM resources;

-- name: FleetSummaryFindings :one
-- Same affected population as advisory_finding_status, computed from shared
-- finding sets weighted by fresh bound devices, minus each device's active
-- exceptions. Never infer open findings from retained evidence rows.
WITH dev AS (
 SELECT s.device_id, s.finding_set_id FROM advisory_device_status s
 WHERE NOT s.unknown AND s.finding_set_id IS NOT NULL
  AND device_scope_matches(s.device_id, sqlc.arg('scope_unrestricted')::boolean, sqlc.arg('scopes')::jsonb)
), bound AS (
 SELECT finding_set_id, count(*)::bigint AS devices FROM dev GROUP BY finding_set_id
), totals AS (
 SELECT coalesce(sum(b.devices * fs.critical_count), 0)::bigint AS critical,
  coalesce(sum(b.devices * fs.high_count), 0)::bigint AS high,
  coalesce(sum(b.devices * fs.medium_count), 0)::bigint AS medium,
  coalesce(sum(b.devices * fs.low_count), 0)::bigint AS low,
  coalesce(sum(b.devices * fs.other_count), 0)::bigint AS other
 FROM bound b JOIN advisory_finding_sets fs ON fs.id = b.finding_set_id
), accepted AS (
 SELECT count(*) FILTER (WHERE f.severity = 'critical')::bigint AS critical,
  count(*) FILTER (WHERE f.severity = 'high')::bigint AS high,
  count(*) FILTER (WHERE f.severity = 'medium')::bigint AS medium,
  count(*) FILTER (WHERE f.severity = 'low')::bigint AS low,
  count(*) FILTER (WHERE f.severity NOT IN ('critical', 'high', 'medium', 'low'))::bigint AS other
 FROM dev
 JOIN advisory_exceptions x ON x.device_id = dev.device_id AND x.expires_at > CURRENT_TIMESTAMP
 JOIN advisory_set_findings f ON f.set_id = dev.finding_set_id AND f.finding_key = x.finding_id
)
SELECT (t.critical - a.critical)::bigint AS critical_findings,
 (t.high - a.high)::bigint AS high_findings,
 (t.medium - a.medium)::bigint AS medium_findings,
 (t.low - a.low)::bigint AS low_findings,
 (t.other - a.other)::bigint AS other_findings
FROM totals t CROSS JOIN accepted a;

-- name: FleetSummaryAdvisoryDevices :one
-- Same evaluated/unknown population as advisory.CountAdvisoryDevices.
SELECT count(*) FILTER (WHERE e.state = 'evaluated' AND e.expires_at > CURRENT_TIMESTAMP
 AND e.snapshot_id = g.current_snapshot_id AND e.feed_revision = af.revision
 AND e.host_received_at = d.host_received_at AND pa.status = 1
 AND af.enabled AND af.expires_at > CURRENT_TIMESTAMP)::bigint AS evaluated,
 count(*)::bigint AS total
FROM devices d
LEFT JOIN enrollment_generations g ON g.id = d.current_generation_id
LEFT JOIN package_attempts pa ON pa.generation_id = g.id
LEFT JOIN advisory_evaluations e ON e.device_id = d.id
LEFT JOIN advisory_feeds af ON af.id = e.feed_id
WHERE d.state = 'active'
 AND device_scope_matches(d.id, sqlc.arg('scope_unrestricted')::boolean, sqlc.arg('scopes')::jsonb);

-- name: FleetSummaryRecentActions :many
-- Scope filtering precedes both branch limits and the final mixed-action limit.
-- Project only bounded metadata, never action documents, attestations or secrets.
WITH recent_device AS (
 SELECT a.id, a.device_id, a.capability, a.issued_at, a.expires_at,
  a.start_authorized_at, a.closed_at, a.closed_reason, a.outcome_unknown,
  'device'::text AS kind, ''::text AS resource_id, ''::text AS unit
 FROM device_actions a
 WHERE device_scope_matches(a.device_id, sqlc.arg('scope_unrestricted')::boolean, sqlc.arg('scopes')::jsonb)
 ORDER BY a.issued_at DESC, a.id DESC LIMIT sqlc.arg('row_limit')
), recent_service AS (
 SELECT a.id, a.device_id, ''::text AS capability, a.issued_at, a.expires_at,
  a.start_authorized_at, a.closed_at, a.closed_reason,
  (a.start_authorized_at IS NOT NULL AND a.closed_at IS NULL)::boolean AS outcome_unknown,
  'resource'::text AS kind, a.resource_id::text AS resource_id, r.canonical_key AS unit
 FROM resource_actions a
 JOIN resource_assignment_resources r ON r.assignment_id = a.assignment_id AND r.resource_id = a.resource_id
 WHERE device_scope_matches(a.device_id, sqlc.arg('scope_unrestricted')::boolean, sqlc.arg('scopes')::jsonb)
 ORDER BY a.issued_at DESC, a.id DESC LIMIT sqlc.arg('row_limit')
), recent AS (
 SELECT * FROM recent_device
 UNION ALL
 SELECT * FROM recent_service
)
SELECT * FROM recent ORDER BY issued_at DESC, id DESC, kind DESC LIMIT sqlc.arg('row_limit');

-- name: FleetSummaryPatch :one
-- Active devices only, keyed by their current generation's latest published
-- patch status. Buckets are disjoint; freshness never trusts a device clock
-- beyond the server receipt of the observation that carried the status.
-- last_run_result 2 is lindm.agent.v1.PatchRunResult FAILED.
WITH patch AS (
 SELECT CASE
   WHEN p.generation_id IS NULL OR NOT p.available THEN 'unknown'
   WHEN LEAST(p.observed_at, p.received_at) < CURRENT_TIMESTAMP - make_interval(secs => sqlc.arg('stale_after_seconds')::integer) THEN 'stale'
   WHEN p.pending_security_updates > 0 THEN 'security_pending'
   WHEN p.reboot_required THEN 'reboot_required'
   ELSE 'patched'
 END AS bucket,
 COALESCE(p.pending_security_updates, 0)::bigint AS pending_security_updates,
 COALESCE(p.last_run_result, 0)::smallint AS last_run_result
 FROM devices d
 LEFT JOIN host_patch_status p ON p.generation_id = d.current_generation_id
 WHERE d.state = 'active'
  AND device_scope_matches(d.id, sqlc.arg('scope_unrestricted')::boolean, sqlc.arg('scopes')::jsonb)
)
SELECT count(*) FILTER (WHERE bucket = 'patched')::bigint AS patched_devices,
 count(*) FILTER (WHERE bucket = 'security_pending')::bigint AS security_pending_devices,
 count(*) FILTER (WHERE bucket = 'reboot_required')::bigint AS reboot_required_devices,
 count(*) FILTER (WHERE bucket = 'stale')::bigint AS stale_devices,
 count(*) FILTER (WHERE bucket = 'unknown')::bigint AS unknown_devices,
 COALESCE(sum(pending_security_updates) FILTER (WHERE bucket IN ('patched', 'security_pending', 'reboot_required')), 0)::bigint AS pending_security_updates,
 count(*) FILTER (WHERE bucket IN ('patched', 'security_pending', 'reboot_required') AND last_run_result = 2)::bigint AS failed_run_devices
FROM patch;
