-- name: InsertEnrollmentGrant :exec
INSERT INTO enrollment_grants (
    id,
    token_hash,
    created_by,
    created_at,
    expires_at,
    reason
) VALUES (
    sqlc.arg('id'),
    sqlc.arg('token_hash'),
    sqlc.arg('created_by'),
    sqlc.arg('created_at'),
    sqlc.arg('expires_at'),
    sqlc.arg('reason')
);

-- name: GetGrantByHashForUpdate :one
SELECT
    id,
    created_by,
    created_at,
    expires_at,
    reason,
    revoked_at,
    revoked_by,
    revoke_reason,
    consumed_at,
    device_id,
    transaction_id,
    public_key_fingerprint,
    certificate_id
FROM enrollment_grants
WHERE token_hash = sqlc.arg('token_hash')
FOR UPDATE;

-- name: GetGrantForUpdate :one
SELECT
    id,
    created_by,
    created_at,
    expires_at,
    reason,
    revoked_at,
    revoked_by,
    revoke_reason,
    consumed_at,
    device_id,
    transaction_id,
    public_key_fingerprint,
    certificate_id
FROM enrollment_grants
WHERE id = sqlc.arg('id')
FOR UPDATE;

-- name: ConsumeEnrollmentGrant :execrows
UPDATE enrollment_grants
SET
    consumed_at = sqlc.arg('consumed_at'),
    device_id = sqlc.arg('device_id'),
    transaction_id = sqlc.arg('transaction_id'),
    public_key_fingerprint = sqlc.arg('public_key_fingerprint'),
    certificate_id = sqlc.arg('certificate_id')
WHERE id = sqlc.arg('id')
  AND consumed_at IS NULL
  AND revoked_at IS NULL;

-- name: RevokeEnrollmentGrant :execrows
UPDATE enrollment_grants
SET
    revoked_at = sqlc.arg('revoked_at'),
    revoked_by = sqlc.arg('revoked_by'),
    revoke_reason = sqlc.arg('revoke_reason')
WHERE id = sqlc.arg('id')
  AND revoked_at IS NULL;
