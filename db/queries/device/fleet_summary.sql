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
-- Canonical view applies current inventory/feed validity and exception expiry;
-- never infer open findings from retained evidence rows or sum advisory devices.
SELECT count(*) FILTER (WHERE f.severity = 'critical')::bigint AS critical_findings,
 count(*) FILTER (WHERE f.severity = 'high')::bigint AS high_findings,
 count(*) FILTER (WHERE f.severity = 'medium')::bigint AS medium_findings,
 count(*) FILTER (WHERE f.severity = 'low')::bigint AS low_findings,
 count(*) FILTER (WHERE f.severity NOT IN ('critical', 'high', 'medium', 'low'))::bigint AS other_findings
FROM advisory_finding_status f
WHERE f.state = 'affected'
 AND device_scope_matches(f.device_id, sqlc.arg('scope_unrestricted')::boolean, sqlc.arg('scopes')::jsonb);

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
