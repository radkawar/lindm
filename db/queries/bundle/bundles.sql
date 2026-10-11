-- name: LockBundleLedger :exec
SELECT pg_advisory_xact_lock(7340843010195847517);

-- name: GetBundleImport :one
SELECT sequence, bundle_id, manifest_sha256, state
FROM offline_bundle_imports
WHERE sequence = sqlc.arg('sequence');

-- name: MaxBundleSequence :one
SELECT COALESCE(max(sequence), 0)::bigint AS sequence
FROM offline_bundle_imports;

-- name: StartBundleImport :exec
INSERT INTO offline_bundle_imports(sequence, bundle_id, manifest_sha256, signing_key_id, release_version, created_at, expires_at, state)
VALUES(sqlc.arg('sequence'), sqlc.arg('bundle_id'), sqlc.arg('manifest_sha256'), sqlc.arg('signing_key_id'), sqlc.arg('release_version'), sqlc.arg('created_at'), sqlc.arg('expires_at'), 'importing');

-- name: FinishBundleImport :execrows
UPDATE offline_bundle_imports
SET state = 'imported', imported_at = clock_timestamp()
WHERE sequence = sqlc.arg('sequence') AND manifest_sha256 = sqlc.arg('manifest_sha256') AND state = 'importing';

-- name: InsertBundleAudit :exec
INSERT INTO audit_events(id, actor_id, action, resource_id, reason)
VALUES(sqlc.arg('id'), NULL, sqlc.arg('action'), sqlc.arg('resource_id'), sqlc.arg('reason'));
