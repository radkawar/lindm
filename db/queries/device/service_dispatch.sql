-- name: GetServiceAssignment :one
SELECT a.* FROM service_assignments a JOIN service_assignment_heads h ON h.assignment_id = a.id WHERE h.generation_id = $1;

-- name: LockServiceAssignment :one
SELECT a.* FROM service_assignments a JOIN service_assignment_heads h ON h.assignment_id = a.id WHERE h.generation_id = $1 FOR UPDATE OF h, a;

-- name: GetServiceAssignmentRequest :one
SELECT * FROM service_assignments WHERE request_id = $1;

-- name: InsertServiceAssignment :exec
INSERT INTO service_assignments(id, device_id, generation_id, request_id, request_digest, actor_id, authorization_version, revision_id, document, assigned_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10);

-- name: SetServiceAssignmentHead :exec
INSERT INTO service_assignment_heads(generation_id, assignment_id) VALUES ($1,$2)
ON CONFLICT (generation_id) DO UPDATE SET assignment_id = EXCLUDED.assignment_id;

-- name: BlockServiceAssignment :exec
UPDATE service_assignments SET blocked_reason = $2 WHERE id = $1;

-- name: InsertServiceResource :exec
INSERT INTO service_assignment_resources(assignment_id, resource_id, unit_name, position, document) VALUES ($1,$2,$3,$4,$5);

-- name: ListServiceResources :many
SELECT * FROM service_assignment_resources WHERE assignment_id = $1 ORDER BY position;

-- name: SetServiceResourceDisposition :exec
UPDATE service_assignment_resources SET disposition = $3, reason = $4 WHERE assignment_id = $1 AND resource_id = $2;

-- name: NextServiceSequence :one
INSERT INTO service_resource_sequences(generation_id, unit_name, sequence) VALUES ($1,$2,1)
ON CONFLICT (generation_id, unit_name) DO UPDATE SET sequence = service_resource_sequences.sequence + 1 RETURNING sequence;

-- name: GetOpenServiceAction :one
SELECT * FROM service_actions WHERE device_id = $1 AND closed_at IS NULL FOR UPDATE;

-- name: GetServiceAction :one
SELECT * FROM service_actions WHERE id = $1;

-- name: LockServiceAction :one
SELECT * FROM service_actions WHERE id = $1 FOR UPDATE;

-- name: LatestServiceAction :one
SELECT * FROM service_actions WHERE assignment_id = $1 AND resource_id = $2 ORDER BY resource_sequence DESC LIMIT 1;

-- name: InsertServiceAction :exec
INSERT INTO service_actions(id, device_id, generation_id, assignment_id, resource_id, resource_sequence, intent_envelope, intent_document, issued_at, expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10);

-- name: CloseServiceAction :exec
UPDATE service_actions SET closed_at = $2, closed_reason = $3 WHERE id = $1 AND closed_at IS NULL;

-- name: SetServiceNonce :exec
UPDATE service_actions SET result_nonce = $2, nonce_expires_at = $3 WHERE id = $1;

-- name: SetServiceGrant :exec
UPDATE service_actions SET challenge_proof = $2, start_grant_envelope = $3, start_authorized_at = $4 WHERE id = $1;

-- name: SetServiceResult :exec
UPDATE service_actions SET action_revision = $2, attestation_envelope = $3, attestation_certificate = $4, status_document = $5, attested_at = $6, received_at = $7, result_nonce = '', nonce_expires_at = NULL WHERE id = $1;

-- name: ServiceDispatchClock :one
SELECT clock_timestamp()::timestamptz;

-- name: ServiceDispatchCapacity :one
SELECT (SELECT count(*) FROM service_assignments a WHERE a.generation_id = $1)::bigint AS assignments,
       (SELECT count(*) FROM service_actions w WHERE w.generation_id = $1)::bigint AS actions;

-- name: RecentServiceActions :many
SELECT * FROM service_actions WHERE generation_id = $1 ORDER BY issued_at DESC, id DESC LIMIT 50;
