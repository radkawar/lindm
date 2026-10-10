-- name: InsertRecoveryEnrollmentGrant :exec
INSERT INTO enrollment_recovery_grants(grant_id, device_id, expected_generation_id, expected_revoked_at)
VALUES(sqlc.arg('grant_id'), sqlc.arg('device_id'), sqlc.arg('expected_generation_id'), sqlc.narg('expected_revoked_at'));

-- name: GetRecoveryEnrollmentGrant :one
SELECT device_id, expected_generation_id, expected_revoked_at FROM enrollment_recovery_grants
WHERE grant_id = sqlc.arg('grant_id');

-- name: RecoveryKeyAlreadyUsed :one
SELECT EXISTS(SELECT 1 FROM device_certificates
    WHERE device_id = sqlc.arg('device_id')
      AND public_key_fingerprint = sqlc.arg('public_key_fingerprint'));

-- The device row is locked before generation cutover. Historical records remain,
-- but observations and sessions from the retired generation cannot appear current.
-- name: ResetDeviceForEnrollmentRecovery :exec
UPDATE devices SET state = 'pending', current_generation_id = sqlc.arg('generation_id'),
    hostname = '', os_id = '', os_version = '', architecture = '',
    last_seen_at = NULL, open_snapshot_id = NULL, reserved_inventory_bytes = 0,
    published_sequence = 0, host_received_at = NULL,
    package_attempt_received_at = NULL, snapshot_received_at = NULL,
    revoked_at = NULL, revoked_by = NULL, revoke_reason = ''
WHERE id = sqlc.arg('device_id');

-- name: ReserveEnrollmentInstallation :exec
INSERT INTO enrollment_installations(generation_id, installation_id)
VALUES(sqlc.arg('generation_id'), sqlc.arg('installation_id'));

-- name: GetEnrollmentInstallation :one
SELECT installation_id, boot_id FROM enrollment_installations
WHERE generation_id = sqlc.arg('generation_id');

-- Generation authority is already serialized by the device-row lock.
-- name: PutEnrollmentSessionInstallation :execrows
INSERT INTO enrollment_installations(generation_id, installation_id, boot_id)
VALUES(sqlc.arg('generation_id'), sqlc.arg('installation_id'), sqlc.arg('boot_id'))
ON CONFLICT (generation_id) DO UPDATE SET boot_id = EXCLUDED.boot_id
WHERE enrollment_installations.installation_id = EXCLUDED.installation_id;
