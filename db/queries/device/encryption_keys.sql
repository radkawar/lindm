-- name: InsertDeviceEncryptionKey :execrows
-- Either uniqueness (one key per identity, one identity per key) leaves the
-- existing registration untouched; the caller distinguishes replay from conflict.
INSERT INTO device_encryption_keys (
    generation_id,
    public_key_sha256,
    device_id,
    identity_key_fingerprint,
    kem_id,
    public_key,
    attestation_envelope
) VALUES (
    sqlc.arg('generation_id'),
    sqlc.arg('public_key_sha256'),
    sqlc.arg('device_id'),
    sqlc.arg('identity_key_fingerprint'),
    sqlc.arg('kem_id'),
    sqlc.arg('public_key'),
    sqlc.arg('attestation_envelope')
)
ON CONFLICT DO NOTHING;

-- name: GetDeviceEncryptionKeyByIdentity :one
SELECT public_key_sha256
FROM device_encryption_keys
WHERE generation_id = sqlc.arg('generation_id')
  AND identity_key_fingerprint = sqlc.arg('identity_key_fingerprint');

-- name: GetCurrentDeviceEncryptionKey :one
-- Only a key attested by a currently valid active or overlapping certificate of
-- the device's live generation receives deliveries; the active one wins.
SELECT k.public_key
FROM device_encryption_keys k
JOIN enrollment_generations g ON g.id = k.generation_id
JOIN devices d ON d.id = g.device_id
JOIN device_certificates c
    ON c.generation_id = k.generation_id
    AND c.public_key_fingerprint = k.identity_key_fingerprint
WHERE k.generation_id = sqlc.arg('generation_id')
  AND g.state IN ('pending', 'active')
  AND d.state IN ('pending', 'active')
  AND d.current_generation_id = g.id
  AND c.not_before <= clock_timestamp()
  AND c.not_after > clock_timestamp()
  AND (c.status = 'active' OR (c.status = 'overlapping' AND c.overlap_until > clock_timestamp()))
ORDER BY c.status = 'active' DESC, k.registered_at DESC
LIMIT 1;
