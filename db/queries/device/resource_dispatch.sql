-- SPDX-License-Identifier: Apache-2.0

-- An empty poll may finish at this snapshot. Any head or open action requires
-- the normal locked dispatch path, including its fresh actor authorization.
-- name: HasResourceWork :one
SELECT EXISTS (
    SELECT 1 FROM resource_assignment_heads h WHERE h.generation_id = sqlc.arg('generation_id')
    UNION ALL
    SELECT 1 FROM resource_actions a WHERE a.device_id = sqlc.arg('device_id') AND a.closed_at IS NULL
);

-- name: GetResourceAssignment :one
SELECT a.* FROM resource_assignments a JOIN resource_assignment_heads h ON h.assignment_id = a.id WHERE h.generation_id = $1;

-- name: LockResourceAssignment :one
SELECT a.* FROM resource_assignments a JOIN resource_assignment_heads h ON h.assignment_id = a.id WHERE h.generation_id = $1 FOR UPDATE OF h, a;

-- name: GetResourceAssignmentRequest :one
SELECT * FROM resource_assignments WHERE request_id = $1;

-- name: InsertResourceAssignment :exec
INSERT INTO resource_assignments(id, device_id, generation_id, request_id, request_digest, actor_id, authorization_version, revision_id, document, assigned_at, reconcile_interval_seconds)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11);

-- name: SetResourceAssignmentHead :exec
INSERT INTO resource_assignment_heads(generation_id, assignment_id) VALUES ($1,$2)
ON CONFLICT (generation_id) DO UPDATE SET assignment_id = EXCLUDED.assignment_id;

-- name: BlockResourceAssignment :exec
UPDATE resource_assignments SET blocked_reason = $2 WHERE id = $1;

-- name: InsertAssignmentResource :exec
INSERT INTO resource_assignment_resources(assignment_id, resource_id, resource_kind, canonical_key, position, document, depends_on, verification_max_age_seconds) VALUES ($1,$2,$3,$4,$5,$6,$7,$8);

-- name: ListAssignmentResources :many
SELECT * FROM resource_assignment_resources WHERE assignment_id = $1 ORDER BY position;

-- name: SetAssignmentResourceDisposition :exec
UPDATE resource_assignment_resources SET disposition = $3, reason = $4 WHERE assignment_id = $1 AND resource_id = $2;

-- name: SetAssignmentResourceVerification :exec
UPDATE resource_assignment_resources SET last_verified_at = $3, observed_at = $4, drift_remediated = $5 WHERE assignment_id = $1 AND resource_id = $2;

-- A device-observed transient native hold: BLOCKED with its reason, retried
-- once the reconcile interval has passed since observed_at.
-- name: HoldResource :exec
UPDATE resource_assignment_resources SET disposition = 5, reason = $3, observed_at = $4 WHERE assignment_id = $1 AND resource_id = $2;

-- name: MarkResourceReadOnlySuccess :exec
UPDATE resource_actions SET read_only_success = true WHERE id = $1 AND closed_reason = 'result' AND octet_length(start_grant_envelope) = 0;

-- name: PruneResourceReadOnlySuccesses :exec
DELETE FROM resource_actions WHERE id IN (
    SELECT a.id FROM resource_actions a WHERE a.generation_id = $1 AND a.read_only_success
    ORDER BY a.issued_at DESC, a.id DESC OFFSET 256
);

-- name: NextResourceSequence :one
INSERT INTO resource_sequences(generation_id, resource_kind, canonical_key, sequence) VALUES ($1,$2,$3,1)
ON CONFLICT (generation_id, resource_kind, canonical_key) DO UPDATE SET sequence = resource_sequences.sequence + 1 RETURNING sequence;

-- name: GetOpenResourceAction :one
SELECT * FROM resource_actions WHERE device_id = $1 AND closed_at IS NULL FOR UPDATE;

-- name: GetResourceAction :one
SELECT * FROM resource_actions WHERE id = $1;

-- name: LockResourceAction :one
SELECT * FROM resource_actions WHERE id = $1 FOR UPDATE;

-- name: LatestResourceAction :one
SELECT * FROM resource_actions WHERE assignment_id = $1 AND resource_id = $2 ORDER BY resource_sequence DESC LIMIT 1;

-- name: InsertResourceAction :exec
INSERT INTO resource_actions(id, device_id, generation_id, assignment_id, resource_id, resource_sequence, intent_envelope, intent_document, issued_at, expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10);

-- name: CloseResourceAction :exec
UPDATE resource_actions SET closed_at = $2, closed_reason = $3 WHERE id = $1 AND closed_at IS NULL;

-- Cancellation retains the one-open-action fence until the executor reports
-- terminal owned staging cleanup. The first cancellation reason is immutable.
-- name: RequestResourcePreparationCancellation :exec
UPDATE resource_actions SET closed_reason = $2
WHERE id = $1 AND closed_at IS NULL AND closed_reason = '' AND octet_length(start_grant_envelope) = 0;

-- name: SetResourceNonce :exec
UPDATE resource_actions SET result_nonce = $2, nonce_expires_at = $3 WHERE id = $1;

-- name: SetResourceGrant :exec
UPDATE resource_actions SET challenge_proof = $2, start_grant_envelope = $3, start_authorized_at = $4 WHERE id = $1;

-- name: SetResourceResult :exec
UPDATE resource_actions SET action_revision = $2, attestation_envelope = $3, attestation_certificate = $4, status_document = $5, attested_at = $6, received_at = $7, result_nonce = '', nonce_expires_at = NULL WHERE id = $1;

-- name: ResourceDispatchClock :one
SELECT clock_timestamp()::timestamptz;

-- name: ResourceDispatchCapacity :one
SELECT (SELECT count(*) FROM resource_assignments a WHERE a.generation_id = $1)::bigint AS assignments,
       (SELECT count(*) FROM resource_actions w WHERE w.generation_id = $1 AND NOT w.read_only_success)::bigint AS actions;

-- name: RecentResourceActions :many
SELECT * FROM resource_actions WHERE generation_id = $1 ORDER BY issued_at DESC, id DESC LIMIT 50;

-- name: RecordResourceReleases :exec
INSERT INTO resource_releases(id, generation_id, source_assignment_id, resource_id, resource_kind, canonical_key, superseding_assignment_id, requested_at)
SELECT gen_random_uuid(), a.generation_id, old.assignment_id, old.resource_id, old.resource_kind, old.canonical_key, sqlc.arg(new_assignment_id), sqlc.arg(requested_at)
FROM resource_assignment_resources old JOIN resource_assignments a ON a.id = old.assignment_id
WHERE old.assignment_id = sqlc.arg(old_assignment_id)
AND NOT EXISTS (SELECT 1 FROM resource_assignment_resources current WHERE current.assignment_id = sqlc.arg(new_assignment_id) AND current.resource_kind = old.resource_kind AND current.canonical_key = old.canonical_key)
ON CONFLICT (source_assignment_id, resource_id, superseding_assignment_id) DO NOTHING;

-- name: ListResourceReleases :many
SELECT * FROM resource_releases WHERE generation_id = $1 ORDER BY requested_at DESC, id LIMIT 256;

-- name: SetResourceAssignmentAdoptionApproval :exec
UPDATE resource_assignments SET adoption_approval_id = $2 WHERE id = $1;

-- name: GetResourceAssignmentByID :one
SELECT * FROM resource_assignments WHERE id = $1;

-- name: PendingResourceReleases :many
SELECT r.* FROM resource_releases r
JOIN resource_assignment_resources original ON original.assignment_id = r.source_assignment_id AND original.resource_id = r.resource_id
WHERE r.generation_id = $1 AND r.state = 'pending'
ORDER BY original.position DESC, r.requested_at, r.id
LIMIT 256;

-- name: GetResourceRelease :one
SELECT * FROM resource_releases WHERE id = $1 FOR UPDATE;

-- name: BindResourceReleaseAction :exec
UPDATE resource_actions SET release_id = $2 WHERE id = $1 AND release_id IS NULL;

-- name: SetResourceReleaseState :exec
UPDATE resource_releases SET state = $2, reason = $3, completed_at = $4 WHERE id = $1;

-- name: LatestResourceReleaseAction :one
SELECT * FROM resource_actions WHERE release_id = $1 ORDER BY resource_sequence DESC LIMIT 1;

-- The latest host observation's platform facts decide resource applicability.
-- name: GetResourcePlatformFacts :one
SELECT os_id_status, os_id_value, os_version_status, os_version_value, architecture_status, architecture_value
FROM host_observations WHERE generation_id = $1;
