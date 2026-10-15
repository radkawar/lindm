-- SPDX-License-Identifier: Apache-2.0

-- name: LockInventoryReservation :one
SELECT reserved_bytes
FROM inventory_reservation
WHERE singleton
FOR UPDATE;

-- name: AddInventoryReservation :exec
UPDATE inventory_reservation
SET reserved_bytes = reserved_bytes + sqlc.arg('delta')
WHERE singleton;

-- name: AddDeviceReservation :exec
UPDATE devices
SET reserved_inventory_bytes = reserved_inventory_bytes + sqlc.arg('delta')
WHERE id = sqlc.arg('id');

-- name: InsertPackageSnapshot :exec
INSERT INTO package_snapshots (
    id,
    device_id,
    generation_id,
    sequence,
    state,
    manifest_digest,
    manifest_bytes,
    created_at,
    started_at,
    finished_at,
    accepted_at,
    open_until,
    receipt_expires_at,
    backend,
    package_count,
    batch_count,
    encoded_bytes,
    metadata_bytes,
    reserved_bytes,
    bulk_retained
) VALUES (
    sqlc.arg('id'),
    sqlc.arg('device_id'),
    sqlc.arg('generation_id'),
    sqlc.arg('sequence'),
    'staging',
    sqlc.arg('manifest_digest'),
    sqlc.arg('manifest_bytes'),
    sqlc.arg('created_at'),
    sqlc.arg('started_at'),
    sqlc.arg('finished_at'),
    sqlc.arg('accepted_at')::timestamptz,
    sqlc.arg('accepted_at')::timestamptz + interval '24 hours',
    sqlc.arg('accepted_at')::timestamptz + interval '2160 hours',
    sqlc.arg('backend'),
    sqlc.arg('package_count'),
    sqlc.arg('batch_count'),
    sqlc.arg('encoded_bytes'),
    sqlc.arg('metadata_bytes'),
    sqlc.arg('reserved_bytes'),
    true
);

-- name: GetPackageSnapshot :one
SELECT
    id,
    device_id,
    generation_id,
    sequence,
    state,
    manifest_digest,
    created_at,
    started_at,
    finished_at,
    accepted_at,
    open_until,
    receipt_expires_at,
    committed_at,
    superseded_at,
    backend,
    package_count,
    batch_count,
    encoded_bytes,
    metadata_bytes,
    reserved_bytes,
    bulk_retained
FROM package_snapshots
WHERE id = sqlc.arg('id');

-- name: GetPackageSnapshotBySequence :one
SELECT id, state, manifest_digest
FROM package_snapshots
WHERE generation_id = sqlc.arg('generation_id')
  AND sequence = sqlc.arg('sequence');

-- name: InsertSnapshotBatches :copyfrom
INSERT INTO snapshot_batches (
    snapshot_id,
    batch_index,
    digest,
    record_count,
    encoded_size,
    first_position,
    stored
) VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: GetSnapshotBatch :one
SELECT digest, record_count, encoded_size, first_position, stored
FROM snapshot_batches
WHERE snapshot_id = sqlc.arg('snapshot_id')
  AND batch_index = sqlc.arg('batch_index');

-- name: MarkBatchStored :exec
UPDATE snapshot_batches
SET stored = true
WHERE snapshot_id = sqlc.arg('snapshot_id')
  AND batch_index = sqlc.arg('batch_index');
-- name: CountUnstoredBatches :one
SELECT count(*) AS remaining
FROM snapshot_batches
WHERE snapshot_id = sqlc.arg('snapshot_id')
  AND NOT stored;

-- name: InsertSnapshotPackages :copyfrom
INSERT INTO snapshot_packages (
    snapshot_id,
    position,
    name,
    version,
    architecture,
    manager,
    source_name,
    source_version,
    module_status,
    module_name,
    module_stream,
    module_version,
    module_context,
    origin_status
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14);

-- name: InsertSnapshotPackageListings :copyfrom
INSERT INTO snapshot_package_listings (
    snapshot_id,
    position,
    ordinal,
    origin,
    label,
    suite,
    codename,
    signature,
    signer
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: ListSnapshotPackages :many
SELECT position, name, version, architecture, manager, source_name, source_version,
       module_status, module_name, module_stream, module_version, module_context, origin_status
FROM snapshot_packages
WHERE snapshot_id = sqlc.arg('snapshot_id')
  AND position >= sqlc.arg('next_position')
  AND (sqlc.arg('manager')::text = '' OR manager = sqlc.arg('manager')::text)
  AND (
    sqlc.arg('name_prefix')::text = ''
    OR name LIKE sqlc.arg('name_pattern')::text ESCAPE E'\\'
  )
ORDER BY position
LIMIT sqlc.arg('row_limit')::int;

-- name: ListSnapshotPackageListings :many
-- Origin listings of one bounded page of package positions (at most 16 each).
SELECT position, ordinal, origin, label, suite, codename, signature, signer
FROM snapshot_package_listings
WHERE snapshot_id = sqlc.arg('snapshot_id')
  AND position = ANY(sqlc.arg('positions')::integer[])
ORDER BY position, ordinal;

-- name: DeleteSnapshotPackages :exec
DELETE FROM snapshot_packages
WHERE snapshot_id = sqlc.arg('snapshot_id');

-- name: CommitPackageSnapshot :exec
UPDATE package_snapshots
SET state = 'committed',
    committed_at = sqlc.arg('committed_at')
WHERE id = sqlc.arg('id')
  AND state = 'staging';

-- name: SupersedePackageSnapshot :exec
UPDATE package_snapshots
SET state = 'superseded',
    superseded_at = sqlc.arg('superseded_at')
WHERE id = sqlc.arg('id')
  AND state IN ('staging', 'committed');

-- name: ExpireStagingSnapshot :exec
UPDATE package_snapshots
SET state = 'expired',
    bulk_retained = false,
    reserved_bytes = sqlc.arg('reserved_bytes')
WHERE id = sqlc.arg('id')
  AND state = 'staging';

-- name: ReleaseSnapshotBulk :exec
UPDATE package_snapshots
SET bulk_retained = false,
    reserved_bytes = sqlc.arg('reserved_bytes')
WHERE id = sqlc.arg('id')
  AND bulk_retained;

-- name: DeleteSnapshotBatches :exec
DELETE FROM snapshot_batches
WHERE snapshot_id = sqlc.arg('snapshot_id');

-- name: DeletePackageSnapshot :exec
DELETE FROM package_snapshots
WHERE id = sqlc.arg('id');

-- name: ListExpiredOpenSnapshots :many
SELECT id, encoded_bytes, reserved_bytes, metadata_bytes
FROM package_snapshots
WHERE device_id = sqlc.arg('device_id')
  AND state = 'staging'
  AND open_until <= sqlc.arg('now');

-- name: ListReleasableSnapshotBulk :many
SELECT id, encoded_bytes, reserved_bytes, metadata_bytes
FROM package_snapshots s
WHERE s.device_id = sqlc.arg('device_id')
  AND s.bulk_retained
  AND s.state = 'superseded'
  AND s.superseded_at <= sqlc.arg('cutoff')
  AND NOT EXISTS (
    SELECT 1 FROM package_page_cursors c
    WHERE c.snapshot_id = s.id
      AND c.expires_at > sqlc.arg('now')
  );

-- name: ListExpiredSnapshotReceipts :many
SELECT s.id, s.reserved_bytes
FROM package_snapshots s
WHERE s.device_id = sqlc.arg('device_id')
  AND s.receipt_expires_at <= sqlc.arg('now')
  AND s.state IN ('superseded', 'expired')
  AND NOT s.bulk_retained
  AND NOT EXISTS (
    SELECT 1 FROM package_page_cursors c
    WHERE c.snapshot_id = s.id AND c.expires_at > sqlc.arg('now')
  )
  AND NOT EXISTS (
    SELECT 1 FROM package_attempts a WHERE a.snapshot_id = s.id
  )
  AND NOT EXISTS (
    SELECT 1 FROM enrollment_generations g WHERE g.current_snapshot_id = s.id
  )
  AND NOT EXISTS (
    SELECT 1 FROM devices d WHERE d.open_snapshot_id = s.id
  );

-- name: ListInventoryCleanupDevices :many
SELECT id
FROM devices
WHERE open_snapshot_id IS NOT NULL
   OR reserved_inventory_bytes > 0
ORDER BY id;

-- name: UpsertHostObservation :exec
INSERT INTO host_observations (
    generation_id,
    sequence,
    started_at,
    finished_at,
    received_at,
    digest,
    boot_id_status,
    boot_id_value,
    hostname_status,
    hostname_value,
    os_id_status,
    os_id_value,
    os_version_status,
    os_version_value,
    architecture_status,
    architecture_value,
    kernel_release_status,
    kernel_release_value,
    hardware_vendor_status,
    hardware_vendor_value,
    hardware_model_status,
    hardware_model_value,
    hardware_serial_status,
    hardware_serial_value,
    details
) VALUES (
    sqlc.arg('generation_id'),
    sqlc.arg('sequence'),
    sqlc.arg('started_at'),
    sqlc.arg('finished_at'),
    sqlc.arg('received_at'),
    sqlc.arg('digest'),
    sqlc.arg('boot_id_status'),
    sqlc.arg('boot_id_value'),
    sqlc.arg('hostname_status'),
    sqlc.arg('hostname_value'),
    sqlc.arg('os_id_status'),
    sqlc.arg('os_id_value'),
    sqlc.arg('os_version_status'),
    sqlc.arg('os_version_value'),
    sqlc.arg('architecture_status'),
    sqlc.arg('architecture_value'),
    sqlc.arg('kernel_release_status'),
    sqlc.arg('kernel_release_value'),
    sqlc.arg('hardware_vendor_status'),
    sqlc.arg('hardware_vendor_value'),
    sqlc.arg('hardware_model_status'),
    sqlc.arg('hardware_model_value'),
    sqlc.arg('hardware_serial_status'),
    sqlc.arg('hardware_serial_value'),
    sqlc.arg('details')
)
ON CONFLICT (generation_id) DO UPDATE SET
    sequence = EXCLUDED.sequence,
    started_at = EXCLUDED.started_at,
    finished_at = EXCLUDED.finished_at,
    received_at = EXCLUDED.received_at,
    digest = EXCLUDED.digest,
    boot_id_status = EXCLUDED.boot_id_status,
    boot_id_value = EXCLUDED.boot_id_value,
    hostname_status = EXCLUDED.hostname_status,
    hostname_value = EXCLUDED.hostname_value,
    os_id_status = EXCLUDED.os_id_status,
    os_id_value = EXCLUDED.os_id_value,
    os_version_status = EXCLUDED.os_version_status,
    os_version_value = EXCLUDED.os_version_value,
    architecture_status = EXCLUDED.architecture_status,
    architecture_value = EXCLUDED.architecture_value,
    kernel_release_status = EXCLUDED.kernel_release_status,
    kernel_release_value = EXCLUDED.kernel_release_value,
    hardware_vendor_status = EXCLUDED.hardware_vendor_status,
    hardware_vendor_value = EXCLUDED.hardware_vendor_value,
    hardware_model_status = EXCLUDED.hardware_model_status,
    hardware_model_value = EXCLUDED.hardware_model_value,
    hardware_serial_status = EXCLUDED.hardware_serial_status,
    hardware_serial_value = EXCLUDED.hardware_serial_value,
    advisory_registry_revision = ''::bytea,
    advisory_eligible = false,
    advisory_platform_stream = '',
    details = EXCLUDED.details;

-- name: GetHostObservation :one
SELECT
    sequence,
    started_at,
    finished_at,
    received_at,
    digest,
    boot_id_status,
    boot_id_value,
    hostname_status,
    hostname_value,
    os_id_status,
    os_id_value,
    os_version_status,
    os_version_value,
    architecture_status,
    architecture_value,
    kernel_release_status,
    kernel_release_value,
    hardware_vendor_status,
    hardware_vendor_value,
    hardware_model_status,
    hardware_model_value,
    hardware_serial_status,
    hardware_serial_value,
    details
FROM host_observations
WHERE generation_id = sqlc.arg('generation_id');

-- name: UpsertPackageAttempt :exec
INSERT INTO package_attempts (
    generation_id,
    sequence,
    started_at,
    finished_at,
    received_at,
    status,
    backend,
    snapshot_id,
    digest
) VALUES (
    sqlc.arg('generation_id'),
    sqlc.arg('sequence'),
    sqlc.arg('started_at'),
    sqlc.arg('finished_at'),
    sqlc.arg('received_at'),
    sqlc.arg('status'),
    sqlc.arg('backend'),
    sqlc.arg('snapshot_id'),
    sqlc.arg('digest')
)
ON CONFLICT (generation_id) DO UPDATE SET
    sequence = EXCLUDED.sequence,
    started_at = EXCLUDED.started_at,
    finished_at = EXCLUDED.finished_at,
    received_at = EXCLUDED.received_at,
    status = EXCLUDED.status,
    backend = EXCLUDED.backend,
    snapshot_id = EXCLUDED.snapshot_id,
    digest = EXCLUDED.digest;

-- name: GetPackageAttempt :one
SELECT sequence, started_at, finished_at, received_at, status, backend, snapshot_id, digest
FROM package_attempts
WHERE generation_id = sqlc.arg('generation_id');

-- name: InsertPackageCursor :exec
INSERT INTO package_page_cursors (
    id,
    actor_id,
    device_id,
    generation_id,
    snapshot_id,
    manager,
    name_prefix,
    next_position,
    created_at,
    expires_at
) VALUES (
    sqlc.arg('id'),
    sqlc.arg('actor_id'),
    sqlc.arg('device_id'),
    sqlc.arg('generation_id'),
    sqlc.arg('snapshot_id'),
    sqlc.arg('manager'),
    sqlc.arg('name_prefix'),
    sqlc.arg('next_position'),
    sqlc.arg('created_at')::timestamptz,
    sqlc.arg('created_at')::timestamptz + interval '15 minutes'
);

-- name: GetPackageCursorForUpdate :one
SELECT
    id,
    actor_id,
    device_id,
    generation_id,
    snapshot_id,
    manager,
    name_prefix,
    next_position,
    created_at,
    expires_at
FROM package_page_cursors
WHERE id = sqlc.arg('id')
FOR UPDATE;

-- name: AdvancePackageCursor :exec
UPDATE package_page_cursors
SET next_position = sqlc.arg('next_position')
WHERE id = sqlc.arg('id');

-- name: DeleteExpiredPackageCursors :exec
DELETE FROM package_page_cursors
WHERE expires_at <= sqlc.arg('now');

-- name: DeleteSnapshotCursors :exec
DELETE FROM package_page_cursors
WHERE snapshot_id = sqlc.arg('snapshot_id')
  AND expires_at <= sqlc.arg('now');

-- name: DeleteStaleHostInventoryValues :exec
-- Removes values of one kind that a successful collection no longer reports.
DELETE FROM host_inventory_values
WHERE generation_id = sqlc.arg('generation_id')
  AND kind = sqlc.arg('kind')
  AND NOT (value = ANY(sqlc.arg('values')::text[]));

-- name: InsertHostInventoryValues :exec
INSERT INTO host_inventory_values (generation_id, kind, value)
SELECT sqlc.arg('generation_id'), sqlc.arg('kind'), v
FROM unnest(sqlc.arg('values')::text[]) AS v
ON CONFLICT DO NOTHING;
