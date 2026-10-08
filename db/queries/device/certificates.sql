-- name: InsertDeviceCertificate :exec
INSERT INTO device_certificates (
    id,
    device_id,
    generation_id,
    serial,
    fingerprint,
    public_key_fingerprint,
    pem,
    not_before,
    not_after,
    issued_at,
    status
) VALUES (
    sqlc.arg('id'),
    sqlc.arg('device_id'),
    sqlc.arg('generation_id'),
    sqlc.arg('serial'),
    sqlc.arg('fingerprint'),
    sqlc.arg('public_key_fingerprint'),
    sqlc.arg('pem'),
    sqlc.arg('not_before'),
    sqlc.arg('not_after'),
    sqlc.arg('issued_at'),
    'active'
);

-- name: GetCertificateByFingerprint :one
SELECT
    c.id,
    c.device_id,
    c.generation_id,
    c.status,
    c.not_before,
    c.not_after,
    c.overlap_until,
    c.public_key_fingerprint,
    d.state AS device_state,
    d.current_generation_id
FROM device_certificates c
JOIN devices d ON d.id = c.device_id
WHERE c.fingerprint = sqlc.arg('fingerprint');

-- name: GetActiveCertificate :one
SELECT
    id,
    pem,
    not_after,
    public_key_fingerprint,
    fingerprint
FROM device_certificates
WHERE generation_id = sqlc.arg('generation_id')
  AND status = 'active';

-- name: RetireOverlappingCertificates :exec
UPDATE device_certificates
SET
    status = 'revoked',
    revoked_at = sqlc.arg('revoked_at'),
    revoke_reason = 'superseded',
    overlap_until = NULL
WHERE generation_id = sqlc.arg('generation_id')
  AND status = 'overlapping';

-- name: BeginCertificateOverlap :exec
UPDATE device_certificates
SET
    status = 'overlapping',
    overlap_until = sqlc.arg('overlap_until')
WHERE generation_id = sqlc.arg('generation_id')
  AND status = 'active';

-- name: RevokeDeviceCertificates :exec
UPDATE device_certificates
SET
    status = 'revoked',
    revoked_at = sqlc.arg('revoked_at'),
    revoke_reason = sqlc.arg('revoke_reason'),
    overlap_until = NULL
WHERE device_id = sqlc.arg('device_id')
  AND status <> 'revoked';

-- name: GetCertificateByID :one
SELECT
    id,
    device_id,
    generation_id,
    status,
    pem,
    not_before,
    not_after,
    overlap_until,
    public_key_fingerprint
FROM device_certificates
WHERE id = sqlc.arg('id');
