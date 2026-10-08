-- name: InsertScope :exec
INSERT INTO scope (
    id, deployment, device, generation, host_allocated, package_allocated,
    host_highwater, package_highwater, synced, loss_recovered
) VALUES (
    1, @deployment, @device, @generation, @host_allocated, @package_allocated,
    @host_highwater, @package_highwater, @synced, @loss_recovered
);

-- name: ReadScope :one
SELECT
    deployment, device, generation, host_allocated, package_allocated,
    host_highwater, package_highwater, synced, loss_recovered
FROM scope
WHERE id = 1;

-- name: UpdateScopeCounters :execrows
UPDATE scope
SET host_allocated = @host_allocated,
    package_allocated = @package_allocated,
    host_highwater = @host_highwater,
    package_highwater = @package_highwater,
    synced = 1
WHERE id = 1
  AND host_allocated <= @host_allocated
  AND package_allocated <= @package_allocated
  AND host_highwater <= @host_highwater
  AND package_highwater <= @package_highwater;

-- name: ReadHostSlot :one
SELECT sequence, observation FROM host_slot WHERE kind = @kind;

-- name: InsertHostSlot :exec
INSERT INTO host_slot (kind, sequence, observation) VALUES (@kind, @sequence, @observation);

-- name: UpdateHostSlot :execrows
UPDATE host_slot SET sequence = @sequence, observation = @observation WHERE kind = @kind;

-- name: DeleteHostSlot :exec
DELETE FROM host_slot WHERE kind = @kind;

-- name: ReadPackageSlot :one
SELECT
    sequence, success, status, backend, started_unix, finished_unix, snapshot_id,
    created_unix, collection_id, begin_accepted, accepted_mask, manifest
FROM package_slot
WHERE kind = @kind;

-- name: InsertPackageSlot :exec
INSERT INTO package_slot (
    kind, sequence, success, status, backend, started_unix, finished_unix, snapshot_id,
    created_unix, collection_id, begin_accepted, accepted_mask, manifest
) VALUES (
    @kind, @sequence, @success, @status, @backend, @started_unix, @finished_unix, @snapshot_id,
    @created_unix, @collection_id, @begin_accepted, @accepted_mask, @manifest
);

-- name: DeletePackageSlot :exec
DELETE FROM package_slot WHERE kind = @kind;

-- name: UpdatePackageBegin :execrows
UPDATE package_slot
SET begin_accepted = 1
WHERE kind = 1 AND success = 1 AND sequence = @sequence;

-- name: UpdatePackageMask :execrows
UPDATE package_slot
SET accepted_mask = @accepted_mask
WHERE kind = 1 AND success = 1 AND sequence = @sequence;

-- name: SetLossRecovered :exec
UPDATE scope SET loss_recovered = 1 WHERE id = 1;

-- name: InsertBatch :exec
INSERT INTO batch_descriptor (collection_id, batch_index, sha256, record_count, encoded_size)
VALUES (@collection_id, @batch_index, @sha256, @record_count, @encoded_size);

-- name: ListBatches :many
SELECT batch_index, sha256, record_count, encoded_size
FROM batch_descriptor
WHERE collection_id = @collection_id
ORDER BY batch_index;

-- name: DeleteBatches :exec
DELETE FROM batch_descriptor WHERE collection_id = @collection_id;

-- name: InsertOwned :exec
INSERT INTO owned_dir (collection_id, referenced, byte_size)
VALUES (@collection_id, @referenced, @byte_size);

-- name: MarkOwned :execrows
UPDATE owned_dir
SET referenced = @referenced, byte_size = @byte_size
WHERE collection_id = @collection_id;

-- name: DeleteOwned :exec
DELETE FROM owned_dir WHERE collection_id = @collection_id;

-- name: ListOwned :many
SELECT collection_id, referenced, byte_size FROM owned_dir ORDER BY collection_id;

-- name: ReadRecovery :one
SELECT reason FROM recovery WHERE id = 1;

-- name: InsertRecovery :exec
INSERT INTO recovery (id, reason) VALUES (1, @reason);

-- name: DeleteRecovery :exec
DELETE FROM recovery WHERE id = 1;
