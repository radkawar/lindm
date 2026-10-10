-- Authority writes serialize after GetDeviceForUpdate. Read-only polling may
-- read authority in a REPEATABLE READ, READ ONLY transaction instead.
-- name: GetGenerationAuthority :one
SELECT
    id,
    device_id,
    state,
    session_epoch,
    renewal_issuance_count,
    host_sequence,
    package_sequence,
    last_host_admission_at,
    last_package_admission_at,
    current_snapshot_id
FROM enrollment_generations
WHERE id = sqlc.arg('id');

-- name: GetSessionReceipt :one
SELECT request_digest, session_epoch, host_sequence, package_sequence, accepted_at
FROM device_session_receipts
WHERE generation_id = sqlc.arg('generation_id') AND request_id = sqlc.arg('request_id');

-- name: InsertSessionReceipt :exec
INSERT INTO device_session_receipts (
    generation_id, request_id, request_digest, session_epoch, host_sequence, package_sequence, accepted_at
) VALUES (
    sqlc.arg('generation_id'), sqlc.arg('request_id'), sqlc.arg('request_digest'),
    sqlc.arg('session_epoch'), sqlc.arg('host_sequence'), sqlc.arg('package_sequence'), sqlc.arg('accepted_at')
);

-- name: AdvanceSessionEpoch :exec
UPDATE enrollment_generations SET session_epoch = sqlc.arg('session_epoch') WHERE id = sqlc.arg('id');

-- name: HoldDevice :exec
UPDATE devices SET state = 'recovery_hold' WHERE id = sqlc.arg('id');

-- name: HoldGeneration :exec
UPDATE enrollment_generations SET state = 'recovery_hold' WHERE id = sqlc.arg('id');

-- name: GetRenewalReceipt :one
SELECT request_digest, presented_certificate_id, issued_certificate_id
FROM device_renewal_receipts
WHERE generation_id = sqlc.arg('generation_id') AND request_id = sqlc.arg('request_id');

-- name: InsertRenewalReceipt :exec
INSERT INTO device_renewal_receipts (
    generation_id, request_id, request_digest, presented_certificate_id, issued_certificate_id, issued_at
) VALUES (
    sqlc.arg('generation_id'), sqlc.arg('request_id'), sqlc.arg('request_digest'),
    sqlc.arg('presented_certificate_id'), sqlc.arg('issued_certificate_id'), sqlc.arg('issued_at')
);

-- name: CountRenewalIssuance :exec
UPDATE enrollment_generations SET renewal_issuance_count = renewal_issuance_count + 1 WHERE id = sqlc.arg('id');
