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

-- Read-only authority callers must use a coherent transaction snapshot.
-- name: GetDeviceAuthority :one
SELECT
    id,
    state,
    current_generation_id
FROM devices
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
    revoked_at,
    open_snapshot_id,
    reserved_inventory_bytes,
    published_sequence,
    host_received_at,
    package_attempt_received_at,
    snapshot_received_at
FROM devices
WHERE id = sqlc.arg('id')
FOR UPDATE;

-- name: TouchDeviceLastSeen :exec
UPDATE devices
SET last_seen_at = sqlc.arg('last_seen_at')
WHERE id = sqlc.arg('id');

-- name: UpdateHostProjection :exec
UPDATE devices
SET
    hostname = CASE WHEN sqlc.arg('set_hostname')::boolean THEN sqlc.arg('hostname')::text ELSE hostname END,
    os_id = CASE WHEN sqlc.arg('set_os_id')::boolean THEN sqlc.arg('os_id')::text ELSE os_id END,
    os_version = CASE WHEN sqlc.arg('set_os_version')::boolean THEN sqlc.arg('os_version')::text ELSE os_version END,
    architecture = CASE WHEN sqlc.arg('set_architecture')::boolean THEN sqlc.arg('architecture')::text ELSE architecture END,
    host_received_at = sqlc.arg('host_received_at'),
    last_seen_at = sqlc.arg('last_seen_at'),
    state = sqlc.arg('state')
WHERE id = sqlc.arg('id');

-- name: SetOpenSnapshot :exec
UPDATE devices
SET
    open_snapshot_id = sqlc.arg('open_snapshot_id'),
    last_seen_at = sqlc.arg('last_seen_at'),
    state = sqlc.arg('state')
WHERE id = sqlc.arg('id');

-- name: ClearOpenSnapshot :exec
UPDATE devices
SET open_snapshot_id = NULL
WHERE id = sqlc.arg('id')
  AND open_snapshot_id IS NOT DISTINCT FROM sqlc.arg('open_snapshot_id');

-- name: PublishDeviceSnapshot :exec
UPDATE devices
SET
    published_sequence = sqlc.arg('published_sequence'),
    snapshot_received_at = sqlc.arg('snapshot_received_at'),
    package_attempt_received_at = sqlc.arg('package_attempt_received_at'),
    open_snapshot_id = NULL,
    last_seen_at = sqlc.arg('last_seen_at'),
    state = sqlc.arg('state')
WHERE id = sqlc.arg('id');

-- name: TouchPackageAttempt :exec
UPDATE devices
SET
    package_attempt_received_at = sqlc.arg('package_attempt_received_at'),
    last_seen_at = sqlc.arg('last_seen_at'),
    state = sqlc.arg('state')
WHERE id = sqlc.arg('id');

-- name: AdmitHostSequence :exec
UPDATE enrollment_generations
SET
    host_sequence = sqlc.arg('host_sequence'),
    last_host_admission_at = sqlc.arg('admitted_at')
WHERE id = sqlc.arg('id');

-- name: AdmitPackageSequence :exec
UPDATE enrollment_generations
SET
    package_sequence = sqlc.arg('package_sequence'),
    last_package_admission_at = sqlc.arg('admitted_at')
WHERE id = sqlc.arg('id');

-- name: SetGenerationSnapshot :exec
UPDATE enrollment_generations
SET current_snapshot_id = sqlc.arg('current_snapshot_id')
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

-- name: GetDeviceDetail :one
SELECT
    d.id,
    d.current_generation_id,
    d.hostname,
    d.os_id,
    d.os_version,
    d.architecture,
    d.state,
    d.enrolled_at,
    d.last_seen_at,
    d.published_sequence,
    d.open_snapshot_id,
    coalesce(g.host_sequence, 0) AS host_sequence,
    coalesce(g.package_sequence, 0) AS package_sequence,
    d.host_received_at,
    d.package_attempt_received_at,
    d.snapshot_received_at,
    g.current_snapshot_id,
    coalesce(r.agent_release, '')::text AS agent_release,
    coalesce(r.protocol_version, 0)::int AS agent_protocol_version,
    r.reported_at AS agent_version_accepted_at
FROM devices d
LEFT JOIN enrollment_generations g ON g.id = d.current_generation_id
LEFT JOIN device_release_reports r ON r.generation_id = d.current_generation_id
WHERE d.id = sqlc.arg('id');
