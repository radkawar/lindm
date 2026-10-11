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
 advisory_count=CASE WHEN advisory_feeds.config_bytes=EXCLUDED.config_bytes THEN advisory_feeds.advisory_count ELSE 0 END,
 checked_at=CASE WHEN advisory_feeds.config_bytes=EXCLUDED.config_bytes THEN advisory_feeds.checked_at END,
 expires_at=CASE WHEN advisory_feeds.config_bytes=EXCLUDED.config_bytes THEN advisory_feeds.expires_at END,
 configured_at=CASE WHEN advisory_feeds.config_bytes=EXCLUDED.config_bytes AND advisory_feeds.enabled
  THEN advisory_feeds.configured_at ELSE clock_timestamp() END;

-- name: GetAdvisoryFeed :one
SELECT * FROM advisory_feeds WHERE id=$1;

-- name: LockAdvisoryFeed :one
SELECT * FROM advisory_feeds WHERE id=$1 FOR UPDATE;

-- name: ListAdvisoryFeeds :many
SELECT * FROM advisory_feeds WHERE enabled ORDER BY id LIMIT 32;

-- name: PublishAdvisoryFeed :execrows
UPDATE advisory_feeds SET revision=$2,source_sha256=$3,checked_at=$4,expires_at=$5,
 attempted_at=$4,error='',advisory_count=$6,complete_snapshot=$7,source_manifest=$8,snapshot_at=$9
WHERE id=$1 AND enabled AND config_bytes=$10 AND (checked_at IS NULL OR checked_at<=$4);

-- name: FailAdvisoryFeed :exec
UPDATE advisory_feeds SET attempted_at=$2,error=$3
WHERE id=$1 AND enabled AND config_bytes=$4
 AND (checked_at IS NULL OR checked_at<=$2)
 AND (attempted_at IS NULL OR attempted_at<=$2);

-- name: InsertAdvisoryPublicationBatch :copyfrom
INSERT INTO advisory_publication_batch(publication_id,position,id,feed_id,advisory_id,package_name,source_package,architecture,record_bytes)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9);

-- name: MergeAdvisoryPublicationBatch :execrows
INSERT INTO advisory_record_generations(generation,id,feed_id,advisory_id,package_name,source_package,architecture,record_bytes)
SELECT publication_id,id,feed_id,advisory_id,package_name,source_package,architecture,record_bytes
FROM advisory_publication_batch WHERE publication_id=$1
ON CONFLICT(feed_id,generation,id) DO NOTHING;

-- name: DeleteAdvisoryPublicationBatch :exec
DELETE FROM advisory_publication_batch WHERE publication_id=$1;

-- name: DeleteInactiveAdvisoryGenerationBatch :execrows
WITH doomed AS (
 SELECT r.id FROM advisory_record_generations r
 WHERE r.feed_id=sqlc.arg('feed_id') AND r.generation=sqlc.arg('generation')
  AND NOT EXISTS (SELECT 1 FROM advisory_feeds f WHERE f.id=sqlc.arg('feed_id') AND f.revision=sqlc.arg('generation'))
 ORDER BY r.id LIMIT 5000
)
DELETE FROM advisory_record_generations r USING doomed
WHERE r.feed_id=sqlc.arg('feed_id') AND r.generation=sqlc.arg('generation') AND r.id=doomed.id;

-- name: StartAdvisoryGeneration :exec
INSERT INTO advisory_generation_cleanup(feed_id,generation,cleanup_after)
VALUES($1,$2,clock_timestamp()+interval '10 minutes');

-- name: RenewAdvisoryGeneration :execrows
UPDATE advisory_generation_cleanup SET cleanup_after=clock_timestamp()+interval '10 minutes'
WHERE generation=$1 AND cleanup_after>clock_timestamp();

-- name: QueueAdvisoryGenerationCleanup :exec
INSERT INTO advisory_generation_cleanup(feed_id,generation,cleanup_after)
VALUES($1,$2,clock_timestamp())
ON CONFLICT(feed_id,generation) DO UPDATE SET cleanup_after=EXCLUDED.cleanup_after;

-- name: FinishAdvisoryGeneration :exec
DELETE FROM advisory_generation_cleanup WHERE feed_id=$1 AND generation=$2;

-- name: LockAdvisoryGenerationCleanup :one
SELECT feed_id,generation FROM advisory_generation_cleanup
WHERE cleanup_after<=clock_timestamp()
ORDER BY cleanup_after,feed_id,generation LIMIT 1 FOR UPDATE SKIP LOCKED;

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
-- Binary and source identities are disjoint UNION ALL branches so each probes
-- advisory_record_generations_identity_idx by exact key; an OR join scans the
-- whole generation. The caller passes the feed revision read in the same
-- repeatable-read transaction, which is exactly the advisory_records view's
-- generation filter. Pages are keyset-bounded by (position, record id): one
-- installed kernel binary alone has ~10,000 Ubuntu records, so a fixed package
-- window cannot bound rows. The identity index ends in id, so each package's
-- records arrive in page order without sorting the remainder of the snapshot.
-- RPM imported signing keys (gpg-pubkey without an architecture) are keyring
-- entries, not installable packages, and never match.
(SELECT p.position,p.name,p.version,p.architecture,p.manager,p.source_name,p.source_version,
 p.module_status,p.module_name,p.module_stream,p.module_version,p.module_context,r.id AS record_id,r.record_bytes
FROM snapshot_packages p
JOIN advisory_record_generations r ON r.feed_id=sqlc.arg('feed_id') AND r.generation=sqlc.arg('generation')
 AND NOT r.source_package AND r.package_name=p.name
 AND (r.architecture='' OR r.architecture=p.architecture OR r.architecture IN ('all','noarch'))
WHERE p.snapshot_id=sqlc.arg('snapshot_id') AND p.position>=sqlc.arg('after_position')
 AND (p.position>sqlc.arg('after_position') OR r.id>sqlc.arg('after_record'))
 AND NOT (p.manager='rpm' AND p.name='gpg-pubkey' AND p.architecture='')
ORDER BY p.position,r.id
LIMIT sqlc.arg('row_limit'))
UNION ALL
(SELECT p.position,p.name,p.version,p.architecture,p.manager,p.source_name,p.source_version,
 p.module_status,p.module_name,p.module_stream,p.module_version,p.module_context,r.id AS record_id,r.record_bytes
FROM snapshot_packages p
JOIN advisory_record_generations r ON r.feed_id=sqlc.arg('feed_id') AND r.generation=sqlc.arg('generation')
 AND r.source_package AND r.package_name=p.source_name
 AND (r.architecture='' OR r.architecture=p.architecture OR r.architecture IN ('all','noarch'))
WHERE p.snapshot_id=sqlc.arg('snapshot_id') AND p.position>=sqlc.arg('after_position')
 AND (p.position>sqlc.arg('after_position') OR r.id>sqlc.arg('after_record')) AND p.source_name<>''
 AND NOT (p.manager='rpm' AND p.name='gpg-pubkey' AND p.architecture='')
ORDER BY p.position,r.id
LIMIT sqlc.arg('row_limit'))
ORDER BY position,record_id
LIMIT sqlc.arg('row_limit');

-- name: AdvisorySourceMappingMissing :one
SELECT EXISTS (SELECT 1 FROM snapshot_packages WHERE snapshot_id=$1 AND manager='dpkg'
 AND (source_name='' OR source_version=''))::boolean;

-- name: ListAdvisoryUncoveredPackages :many
-- Packages of one snapshot that a base release's feed does not cover on a
-- derivative device, in bounded keyset pages by position. The arguments are
-- the platform registry's archive and vendor facts; see advisory_origin_reason.
SELECT p.position,p.name,p.version,p.architecture,r.reason::text AS reason
FROM snapshot_packages p
CROSS JOIN LATERAL (SELECT advisory_origin_reason(p.snapshot_id,p.position,p.origin_status,
 sqlc.arg('origin')::text,sqlc.arg('codename')::text,sqlc.arg('suites')::text[],
 sqlc.arg('signers')::text[],sqlc.arg('vendor_origins')::text[]) AS reason) r
WHERE p.snapshot_id=sqlc.arg('snapshot_id') AND p.position>sqlc.arg('after_position') AND r.reason<>''
ORDER BY p.position LIMIT sqlc.arg('row_limit');

-- name: AdvisoryOriginDigest :one
-- Normalized origin evidence of one snapshot (status and every listing, in
-- position and ordinal order), folded into a derivative's finding-set key.
SELECT sha256(convert_to(coalesce(string_agg(
 concat_ws(',', p.position, p.origin_status, coalesce(l.ordinal, -1), length(l.origin), l.origin,
  length(l.label), l.label, length(l.suite), l.suite, length(l.codename), l.codename, l.signature, l.signer),
 ';' ORDER BY p.position, l.ordinal), ''), 'UTF8'))::bytea AS digest
FROM snapshot_packages p
LEFT JOIN snapshot_package_listings l ON l.snapshot_id=p.snapshot_id AND l.position=p.position
WHERE p.snapshot_id=$1;

-- name: GetAdvisoryEvaluation :one
SELECT * FROM advisory_evaluations WHERE device_id=$1;

-- name: LockAdvisoryDevice :exec
SELECT id FROM devices WHERE id=$1 FOR UPDATE;

-- name: TryLockAdvisoryDevice :many
-- The background evaluator skips a device whose row is being updated (session,
-- heartbeat, inventory) instead of waiting: in its repeatable-read snapshot a
-- wait ends in a serialization failure. A skipped device stays pending.
SELECT id FROM devices WHERE id=$1 FOR UPDATE SKIP LOCKED;

-- name: StoreAdvisoryEvaluation :exec
INSERT INTO advisory_evaluations(device_id,id,snapshot_id,feed_id,feed_revision,evaluated_at,inventory_at,expires_at,state,reason,finding_digest,host_received_at,finding_set_id,uncovered_packages)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
ON CONFLICT(device_id) DO UPDATE SET id=EXCLUDED.id,snapshot_id=EXCLUDED.snapshot_id,
 feed_id=EXCLUDED.feed_id,feed_revision=EXCLUDED.feed_revision,evaluated_at=EXCLUDED.evaluated_at,
 inventory_at=EXCLUDED.inventory_at,host_received_at=EXCLUDED.host_received_at,expires_at=EXCLUDED.expires_at,state=EXCLUDED.state,
 reason=EXCLUDED.reason,finding_digest=EXCLUDED.finding_digest,finding_set_id=EXCLUDED.finding_set_id,
 uncovered_packages=EXCLUDED.uncovered_packages;

-- name: TouchAdvisoryEvaluation :exec
-- Records that unchanged feed-less evidence was rechecked against the current
-- feed configuration, without replacing the evaluation identity bound by cursors.
UPDATE advisory_evaluations SET evaluated_at=$2 WHERE device_id=$1 AND id=$3;

-- name: AdvisoryPackageDigest :one
-- Normalized identity of every matching input in one published snapshot:
-- length-prefixed fields in position order, so equal digests mean equal rows.
SELECT sha256(convert_to(coalesce(string_agg(
 concat_ws(',', position, length(name), name, length(version), version, length(architecture), architecture,
  length(manager), manager, length(source_name), source_name, length(source_version), source_version,
  module_status, length(module_name), module_name, length(module_stream), module_stream,
  length(module_version), module_version, length(module_context), module_context),
 ';' ORDER BY position), ''), 'UTF8'))::bytea AS digest
FROM snapshot_packages WHERE snapshot_id=$1;

-- name: GetAdvisoryFindingSet :one
SELECT * FROM advisory_finding_sets WHERE feed_id=$1 AND feed_revision=$2 AND package_digest=$3;

-- name: InsertAdvisoryFindingSet :exec
-- A concurrent creator of the same content is a serialization conflict in the
-- caller's repeatable-read transaction; the evaluation job retries next pass.
INSERT INTO advisory_finding_sets(id,feed_id,feed_revision,package_digest,state,reason,finding_digest,
 finding_count,critical_count,high_count,medium_count,low_count,other_count,uncovered_packages)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14);

-- name: InsertAdvisorySetFindings :copyfrom
INSERT INTO advisory_set_findings(set_id,finding_key,advisory_id,package_name,installed_version,fixed_version,architecture,severity,published_at,cves,source_url)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11);

-- name: InsertAdvisorySetAdvisories :copyfrom
INSERT INTO advisory_set_advisories(set_id,advisory_id,severity,findings) VALUES($1,$2,$3,$4);

-- name: PruneAdvisoryFindingSets :execrows
-- Unbound sets are removed after a grace period; a binding racing the delete
-- fails its foreign-key check and is retried by the evaluation job.
DELETE FROM advisory_finding_sets WHERE id IN (
 SELECT s.id FROM advisory_finding_sets s
 WHERE s.created_at < clock_timestamp()-interval '15 minutes'
  AND NOT EXISTS (SELECT 1 FROM advisory_evaluations e WHERE e.finding_set_id=s.id)
 ORDER BY s.created_at LIMIT sqlc.arg('set_limit'));

-- name: ListDeviceAdvisoryFindings :many
SELECT f.*, EXISTS (
 SELECT 1 FROM unnest(sqlc.arg('rejected_ids')::text[]) WITH ORDINALITY AS r(advisory_id,ordinal)
 WHERE r.advisory_id=f.advisory_id AND (
  (sqlc.arg('rejected_packages')::text[])[r.ordinal]=f.package_name OR EXISTS (
   SELECT 1 FROM snapshot_packages p
   WHERE p.snapshot_id=sqlc.narg('snapshot_id')::uuid
    AND p.name=f.package_name AND p.version=f.installed_version
    AND p.architecture=f.architecture AND p.source_name=(sqlc.arg('rejected_packages')::text[])[r.ordinal]
  )
 )
) AS source_record_rejected
FROM advisory_finding_status f
WHERE f.device_id=sqlc.arg('device_id') AND f.id>sqlc.arg('id')
ORDER BY f.id LIMIT sqlc.arg('row_limit');

-- name: GetAdvisoryFinding :one
SELECT * FROM advisory_findings WHERE device_id=$1 AND id=$2;

-- name: ListAdvisorySummary :many
-- Same device states as advisory_finding_status, weighted from shared sets:
-- a fresh device is affected unless every finding of the advisory is under an
-- active exception, accepted if any is, and stale devices are unknown.
WITH dev AS (
 SELECT s.device_id, s.finding_set_id, s.unknown FROM advisory_device_status s
 WHERE s.finding_set_id IS NOT NULL
  AND device_scope_matches(s.device_id,sqlc.arg('scope_unrestricted')::boolean,sqlc.arg('scopes')::jsonb)
), bound AS (
 SELECT finding_set_id, count(*) FILTER (WHERE NOT unknown)::bigint AS fresh,
  count(*) FILTER (WHERE unknown)::bigint AS stale
 FROM dev GROUP BY finding_set_id
), totals AS (
 SELECT a.advisory_id, a.severity, sum(b.fresh)::bigint AS fresh, sum(b.stale)::bigint AS stale
 FROM bound b JOIN advisory_set_advisories a ON a.set_id=b.finding_set_id
 WHERE (a.advisory_id,a.severity)>(sqlc.arg('after_advisory')::text,sqlc.arg('after_severity')::text)
 GROUP BY a.advisory_id, a.severity
), accepted AS (
 SELECT f.advisory_id, f.severity, dev.device_id, count(*)::integer AS accepted, max(sa.findings) AS findings
 FROM dev
 JOIN advisory_exceptions x ON x.device_id=dev.device_id AND x.expires_at>CURRENT_TIMESTAMP
 JOIN advisory_set_findings f ON f.set_id=dev.finding_set_id AND f.finding_key=x.finding_id
 JOIN advisory_set_advisories sa ON sa.set_id=dev.finding_set_id AND sa.advisory_id=f.advisory_id AND sa.severity=f.severity
 WHERE NOT dev.unknown
 GROUP BY f.advisory_id, f.severity, dev.device_id
)
SELECT t.advisory_id, t.severity,
 (t.fresh - coalesce((SELECT count(*) FROM accepted a WHERE a.advisory_id=t.advisory_id AND a.severity=t.severity AND a.accepted>=a.findings),0))::bigint AS affected_devices,
 coalesce((SELECT count(*) FROM accepted a WHERE a.advisory_id=t.advisory_id AND a.severity=t.severity),0)::bigint AS accepted_devices,
 t.stale::bigint AS unknown_devices
FROM totals t ORDER BY t.advisory_id, t.severity LIMIT sqlc.arg('row_limit');

-- name: CountAdvisoryDevices :one
-- A current evaluation is complete ('evaluated') or covers only verified
-- base-archive packages ('partial'); every other active device is unknown.
SELECT count(*) FILTER(WHERE e.state='evaluated' AND e.expires_at>CURRENT_TIMESTAMP
 AND e.snapshot_id=g.current_snapshot_id AND e.feed_revision=af.revision
 AND e.host_received_at=d.host_received_at AND pa.status=1
 AND af.enabled AND af.expires_at>CURRENT_TIMESTAMP)::bigint AS evaluated,
 count(*) FILTER(WHERE e.state='partial' AND e.expires_at>CURRENT_TIMESTAMP
 AND e.snapshot_id=g.current_snapshot_id AND e.feed_revision=af.revision
 AND e.host_received_at=d.host_received_at AND pa.status=1
 AND af.enabled AND af.expires_at>CURRENT_TIMESTAMP)::bigint AS partial,
 count(*)::bigint AS total
FROM devices d
LEFT JOIN enrollment_generations g ON g.id=d.current_generation_id
LEFT JOIN package_attempts pa ON pa.generation_id=g.id
LEFT JOIN advisory_evaluations e ON e.device_id=d.id
LEFT JOIN advisory_feeds af ON af.id=e.feed_id
WHERE d.state='active' AND device_scope_matches(d.id,sqlc.arg('scope_unrestricted')::boolean,sqlc.arg('scopes')::jsonb);

-- name: ListAdvisoryEvaluationsPending :many
-- Evaluations are recomputed only when their bound evidence changes: a new
-- published snapshot or host observation, a new feed generation, or a disabled
-- bound feed. Feed selection depends only on enabled feed configuration, so a
-- device evaluated without any applicable feed is rechecked once any process
-- configures or re-enables a feed after that evaluation. Time-based expiry needs
-- no worker: the read path and advisory_finding_status recheck it.
SELECT d.id FROM devices d
LEFT JOIN enrollment_generations g ON g.id=d.current_generation_id
LEFT JOIN host_observations h ON h.generation_id=g.id
LEFT JOIN advisory_evaluations e ON e.device_id=d.id
LEFT JOIN advisory_feeds af ON af.id=e.feed_id
WHERE d.state='active' AND (e.device_id IS NULL
 OR e.snapshot_id IS DISTINCT FROM g.current_snapshot_id
 OR e.host_received_at IS DISTINCT FROM h.received_at
 OR (e.feed_id<>'' AND (af.id IS NULL OR NOT af.enabled OR af.revision IS DISTINCT FROM e.feed_revision))
 OR (e.feed_id='' AND EXISTS (SELECT 1 FROM advisory_feeds f WHERE f.enabled AND f.configured_at>e.evaluated_at)))
ORDER BY e.evaluated_at NULLS FIRST,d.id
LIMIT sqlc.arg('row_limit');

-- name: AcceptAdvisoryException :one
INSERT INTO advisory_exceptions(finding_id,device_id,actor_id,reason,accepted_at,expires_at)
VALUES($1,$2,$3,$4,$5,$6)
ON CONFLICT(device_id,finding_id) DO UPDATE SET actor_id=EXCLUDED.actor_id,reason=EXCLUDED.reason,
 accepted_at=EXCLUDED.accepted_at,expires_at=EXCLUDED.expires_at
RETURNING actor_id, reason, accepted_at, expires_at;

-- name: GetAdvisoryExceptionRequest :one
SELECT request_digest,response_bytes FROM advisory_exception_requests WHERE actor_id=$1 AND request_id=$2;

-- name: InsertAdvisoryExceptionRequest :exec
INSERT INTO advisory_exception_requests(actor_id,request_id,request_digest,response_bytes) VALUES($1,$2,$3,$4);

-- name: InsertAdvisoryAudit :exec
INSERT INTO audit_events(id,actor_id,action,resource_id,reason,details)
VALUES(sqlc.arg('id'),sqlc.narg('actor_id'),sqlc.arg('action'),sqlc.arg('resource_id'),sqlc.arg('reason'),
  jsonb_strip_nulls(jsonb_build_object('context', NULLIF(sqlc.arg('context')::text, ''))));

-- name: AdvisoryDatabaseTime :one
SELECT clock_timestamp()::timestamptz AS now;

-- name: AdvisoryDeviceVisible :one
SELECT EXISTS(SELECT 1 FROM devices d WHERE d.id=sqlc.arg('device_id')::uuid
 AND device_scope_matches(d.id,sqlc.arg('scope_unrestricted')::boolean,sqlc.arg('scopes')::jsonb))::boolean;

-- name: AdvisoryArchitectures :many
-- RPM imported signing keys (gpg-pubkey with no ARCH tag) are not packages and
-- do not make a device's architecture coverage unknown.
SELECT DISTINCT architecture FROM snapshot_packages WHERE snapshot_id=$1
 AND NOT (manager='rpm' AND name='gpg-pubkey' AND architecture='') LIMIT 65;

-- name: PruneAdvisoryExceptionRequests :exec
DELETE FROM advisory_exception_requests WHERE (actor_id,request_id) IN
 (SELECT actor_id,request_id FROM advisory_exception_requests
 WHERE created_at < now()-interval '90 days' ORDER BY created_at LIMIT 1000);

-- name: PruneAdvisoryExceptions :exec
DELETE FROM advisory_exceptions WHERE (device_id,finding_id) IN
 (SELECT device_id,finding_id FROM advisory_exceptions WHERE expires_at < now()-interval '90 days'
 ORDER BY expires_at LIMIT 1000);

-- name: AdvisoryNativeInstances :many
-- Native OVAL predicates bind all installed instances, including installonly
-- versions and secondary architectures. The extra row detects the hard bound.
SELECT manager,version,architecture FROM snapshot_packages
WHERE snapshot_id=$1 AND name=$2 ORDER BY position LIMIT 1025;
