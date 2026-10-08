-- name: InsertDevice :exec
INSERT INTO devices (id, state, enrolled_at)
VALUES (sqlc.arg('id'), 'pending', sqlc.arg('enrolled_at'));

-- name: InsertEnrollmentGeneration :exec
INSERT INTO enrollment_generations (id, device_id, state, created_at)
VALUES (sqlc.arg('id'), sqlc.arg('device_id'), 'pending', sqlc.arg('created_at'));

-- name: SetDeviceGeneration :exec
UPDATE devices
SET current_generation_id = sqlc.arg('current_generation_id')
WHERE id = sqlc.arg('id');

-- name: GetDeviceForUpdate :one
SELECT
    id,
    state,
    current_generation_id,
    hostname,
    os_id,
    os_version,
    architecture,
    enrolled_at,
    last_seen_at,
    inventory_sequence,
    inventory_digest,
    boot_id,
    package_snapshot_sequence,
    package_snapshot_complete,
    revoked_at
FROM devices
WHERE id = sqlc.arg('id')
FOR UPDATE;

-- name: TouchDeviceLastSeen :exec
UPDATE devices
SET last_seen_at = sqlc.arg('last_seen_at')
WHERE id = sqlc.arg('id');

-- name: UpdateDeviceInventory :exec
UPDATE devices
SET
    hostname = sqlc.arg('hostname'),
    os_id = sqlc.arg('os_id'),
    os_version = sqlc.arg('os_version'),
    architecture = sqlc.arg('architecture'),
    last_seen_at = sqlc.arg('last_seen_at'),
    inventory_sequence = sqlc.arg('inventory_sequence'),
    inventory_digest = sqlc.arg('inventory_digest'),
    boot_id = sqlc.arg('boot_id'),
    state = sqlc.arg('state'),
    package_snapshot_sequence = sqlc.arg('package_snapshot_sequence'),
    package_snapshot_complete = sqlc.arg('package_snapshot_complete')
WHERE id = sqlc.arg('id');

-- name: RevokeDeviceRecord :execrows
UPDATE devices
SET
    state = 'revoked',
    revoked_at = sqlc.arg('revoked_at'),
    revoked_by = sqlc.arg('revoked_by'),
    revoke_reason = sqlc.arg('revoke_reason')
WHERE id = sqlc.arg('id')
  AND state <> 'revoked';

-- name: RevokeGenerations :exec
UPDATE enrollment_generations
SET state = 'revoked'
WHERE device_id = sqlc.arg('device_id')
  AND state <> 'revoked';

-- name: ActivateGeneration :exec
UPDATE enrollment_generations
SET state = 'active'
WHERE id = sqlc.arg('id')
  AND state = 'pending';

-- name: ListDevicesFirst :many
SELECT
    id,
    current_generation_id,
    hostname,
    os_id,
    os_version,
    architecture,
    state,
    enrolled_at,
    last_seen_at,
    inventory_sequence
FROM devices
ORDER BY enrolled_at DESC, id DESC
LIMIT sqlc.arg('row_limit')::int;

-- name: ListDevicesAfter :many
SELECT
    id,
    current_generation_id,
    hostname,
    os_id,
    os_version,
    architecture,
    state,
    enrolled_at,
    last_seen_at,
    inventory_sequence
FROM devices
WHERE (enrolled_at, id) < (sqlc.arg('cursor_enrolled_at')::timestamptz, sqlc.arg('cursor_id')::uuid)
ORDER BY enrolled_at DESC, id DESC
LIMIT sqlc.arg('row_limit')::int;
