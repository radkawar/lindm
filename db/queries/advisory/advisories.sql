-- name: DisableAdvisoryFeeds :exec
UPDATE advisory_feeds SET enabled = false WHERE NOT (id = ANY(sqlc.arg('enabled_ids')::text[]));

-- name: ConfigureAdvisoryFeed :exec
INSERT INTO advisory_feeds (id,distro,release,source_url,config_bytes,revision,platform_stream)
VALUES ($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT(id) DO UPDATE SET distro=EXCLUDED.distro,release=EXCLUDED.release,
 source_url=EXCLUDED.source_url,config_bytes=EXCLUDED.config_bytes,platform_stream=EXCLUDED.platform_stream,enabled=true,
 revision=CASE WHEN advisory_feeds.config_bytes=EXCLUDED.config_bytes THEN advisory_feeds.revision ELSE EXCLUDED.revision END,
 source_sha256=CASE WHEN advisory_feeds.config_bytes=EXCLUDED.config_bytes THEN advisory_feeds.source_sha256 ELSE ''::bytea END,
 source_manifest=CASE WHEN advisory_feeds.config_bytes=EXCLUDED.config_bytes THEN advisory_feeds.source_manifest ELSE ''::bytea END,
 snapshot_at=CASE WHEN advisory_feeds.config_bytes=EXCLUDED.config_bytes THEN advisory_feeds.snapshot_at END,
 complete_snapshot=advisory_feeds.config_bytes=EXCLUDED.config_bytes AND advisory_feeds.complete_snapshot,
 checked_at=CASE WHEN advisory_feeds.config_bytes=EXCLUDED.config_bytes THEN advisory_feeds.checked_at END,
 expires_at=CASE WHEN advisory_feeds.config_bytes=EXCLUDED.config_bytes THEN advisory_feeds.expires_at END;

-- name: GetAdvisoryFeed :one
SELECT * FROM advisory_feeds WHERE id=$1;

-- name: LockAdvisoryFeed :one
SELECT * FROM advisory_feeds WHERE id=$1 FOR UPDATE;

-- name: ListAdvisoryFeeds :many
SELECT * FROM advisory_feeds WHERE enabled ORDER BY id LIMIT 32;

-- name: PublishAdvisoryFeed :exec
UPDATE advisory_feeds SET revision=$2,source_sha256=$3,checked_at=$4,expires_at=$5,
 attempted_at=$4,error='',advisory_count=$6,complete_snapshot=$7,source_manifest=$8,snapshot_at=$9 WHERE id=$1;

-- name: FailAdvisoryFeed :exec
UPDATE advisory_feeds SET attempted_at=$2,error=$3 WHERE id=$1;

-- name: DeleteAdvisoryRecords :exec
DELETE FROM advisory_records WHERE feed_id=$1;

-- name: InsertAdvisoryRecords :copyfrom
INSERT INTO advisory_records(id,feed_id,advisory_id,package_name,source_package,architecture,record_bytes)
VALUES($1,$2,$3,$4,$5,$6,$7);

-- name: GetAdvisoryDevice :one
SELECT d.id,d.state,d.os_id,d.os_version,d.architecture,d.current_generation_id,
 g.current_snapshot_id,ps.finished_at AS inventory_at,ps.package_count,
 h.received_at AS host_received_at,h.finished_at AS host_finished_at,h.os_id_status,h.os_version_status,h.architecture_status,
 pa.status AS package_status,COALESCE(h.details,''::bytea) AS host_details
FROM devices d
LEFT JOIN enrollment_generations g ON g.id=d.current_generation_id
LEFT JOIN package_snapshots ps ON ps.id=g.current_snapshot_id
LEFT JOIN host_observations h ON h.generation_id=g.id
LEFT JOIN package_attempts pa ON pa.generation_id=g.id
WHERE d.id=$1;

-- name: AdvisoryCandidates :many
SELECT p.position,p.name,p.version,p.architecture,p.manager,p.source_name,p.source_version,
 p.module_status,p.module_name,p.module_stream,p.module_version,p.module_context,r.record_bytes
FROM snapshot_packages p
JOIN advisory_records r ON r.feed_id=sqlc.arg('feed_id')
 AND ((NOT r.source_package AND r.package_name=p.name)
      OR (r.source_package AND r.package_name=p.source_name))
 AND (r.architecture='' OR r.architecture=p.architecture OR r.architecture IN ('all','noarch'))
WHERE p.snapshot_id=sqlc.arg('snapshot_id') AND p.position>=sqlc.arg('first_position')
 AND p.position<sqlc.arg('end_position')
ORDER BY p.position,r.id
LIMIT 10001;

-- name: AdvisorySourceMappingMissing :one
SELECT EXISTS (SELECT 1 FROM snapshot_packages WHERE snapshot_id=$1 AND manager='dpkg'
 AND (source_name='' OR source_version=''))::boolean;

-- name: GetAdvisoryEvaluation :one
SELECT * FROM advisory_evaluations WHERE device_id=$1;

-- name: LockAdvisoryDevice :exec
SELECT id FROM devices WHERE id=$1 FOR UPDATE;

-- name: StoreAdvisoryEvaluation :exec
INSERT INTO advisory_evaluations(device_id,id,snapshot_id,feed_id,feed_revision,evaluated_at,inventory_at,expires_at,state,reason,finding_digest,host_received_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
ON CONFLICT(device_id) DO UPDATE SET id=EXCLUDED.id,snapshot_id=EXCLUDED.snapshot_id,
 feed_id=EXCLUDED.feed_id,feed_revision=EXCLUDED.feed_revision,evaluated_at=EXCLUDED.evaluated_at,
 inventory_at=EXCLUDED.inventory_at,host_received_at=EXCLUDED.host_received_at,expires_at=EXCLUDED.expires_at,state=EXCLUDED.state,
 reason=EXCLUDED.reason,finding_digest=EXCLUDED.finding_digest;

-- name: DeleteAdvisoryFindings :exec
DELETE FROM advisory_findings WHERE device_id=$1;

-- name: InsertAdvisoryFinding :exec
INSERT INTO advisory_findings(id,device_id,advisory_id,package_name,installed_version,fixed_version,architecture,severity,published_at,cves,feed_id,source_url)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
ON CONFLICT(id) DO NOTHING;

-- name: ListDeviceAdvisoryFindings :many
SELECT * FROM advisory_finding_status WHERE device_id=$1 AND id>$2 ORDER BY id LIMIT $3;

-- name: GetAdvisoryFinding :one
SELECT * FROM advisory_findings WHERE device_id=$1 AND id=$2;

-- name: ListAdvisorySummary :many
SELECT f.advisory_id,f.severity,
 count(DISTINCT f.device_id) FILTER(WHERE f.state='affected')::bigint AS affected_devices,
 count(DISTINCT f.device_id) FILTER(WHERE f.state='accepted')::bigint AS accepted_devices,
 count(DISTINCT f.device_id) FILTER(WHERE f.state='unknown')::bigint AS unknown_devices
FROM advisory_finding_status f
WHERE device_scope_matches(f.device_id,sqlc.arg('scope_unrestricted')::boolean,sqlc.arg('scopes')::jsonb)
 AND (f.advisory_id,f.severity)>(sqlc.arg('after_advisory')::text,sqlc.arg('after_severity')::text)
GROUP BY f.advisory_id,f.severity ORDER BY f.advisory_id,f.severity LIMIT sqlc.arg('row_limit');

-- name: CountAdvisoryDevices :one
SELECT count(*) FILTER(WHERE e.state='evaluated' AND e.expires_at>CURRENT_TIMESTAMP
 AND e.snapshot_id=g.current_snapshot_id AND e.feed_revision=af.revision
 AND e.host_received_at=d.host_received_at AND pa.status=1
 AND af.enabled AND af.expires_at>CURRENT_TIMESTAMP)::bigint AS evaluated,
 count(*)::bigint AS total
FROM devices d
LEFT JOIN enrollment_generations g ON g.id=d.current_generation_id
LEFT JOIN package_attempts pa ON pa.generation_id=g.id
LEFT JOIN advisory_evaluations e ON e.device_id=d.id
LEFT JOIN advisory_feeds af ON af.id=e.feed_id
WHERE d.state='active' AND device_scope_matches(d.id,sqlc.arg('scope_unrestricted')::boolean,sqlc.arg('scopes')::jsonb);

-- name: ListAdvisoryDeviceIDs :many
SELECT id FROM devices WHERE id>$1 AND state='active' ORDER BY id LIMIT 100;

-- name: AcceptAdvisoryException :exec
INSERT INTO advisory_exceptions(finding_id,device_id,actor_id,reason,accepted_at,expires_at)
VALUES($1,$2,$3,$4,$5,$6)
ON CONFLICT(finding_id) DO UPDATE SET actor_id=EXCLUDED.actor_id,reason=EXCLUDED.reason,
 accepted_at=EXCLUDED.accepted_at,expires_at=EXCLUDED.expires_at;

-- name: GetAdvisoryExceptionRequest :one
SELECT request_digest,response_bytes FROM advisory_exception_requests WHERE actor_id=$1 AND request_id=$2;

-- name: InsertAdvisoryExceptionRequest :exec
INSERT INTO advisory_exception_requests(actor_id,request_id,request_digest,response_bytes) VALUES($1,$2,$3,$4);

-- name: InsertAdvisoryAudit :exec
INSERT INTO audit_events(id,actor_id,action,resource_id,reason)
VALUES(sqlc.arg('id'),sqlc.narg('actor_id'),sqlc.arg('action'),sqlc.arg('resource_id'),sqlc.arg('reason'));

-- name: AdvisoryDatabaseTime :one
SELECT clock_timestamp()::timestamptz AS now;

-- name: AdvisoryDeviceVisible :one
SELECT EXISTS(SELECT 1 FROM devices d WHERE d.id=sqlc.arg('device_id')::uuid
 AND device_scope_matches(d.id,sqlc.arg('scope_unrestricted')::boolean,sqlc.arg('scopes')::jsonb))::boolean;

-- name: AdvisoryArchitectures :many
SELECT DISTINCT architecture FROM snapshot_packages WHERE snapshot_id=$1 LIMIT 65;

-- name: PruneAdvisoryExceptionRequests :exec
DELETE FROM advisory_exception_requests WHERE (actor_id,request_id) IN
 (SELECT actor_id,request_id FROM advisory_exception_requests
 WHERE created_at < now()-interval '90 days' ORDER BY created_at LIMIT 1000);

-- name: PruneAdvisoryExceptions :exec
DELETE FROM advisory_exceptions WHERE finding_id IN
 (SELECT finding_id FROM advisory_exceptions WHERE expires_at < now()-interval '90 days'
 ORDER BY expires_at LIMIT 1000);
