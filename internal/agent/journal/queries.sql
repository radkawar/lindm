-- name: ReadState :one
SELECT revision, state FROM executor_state WHERE id = 1;

-- name: InitializeState :exec
INSERT INTO executor_state (id, revision, state) VALUES (1, 1, ?);

-- name: ReplaceState :execrows
UPDATE executor_state SET revision = revision + 1, state = ? WHERE id = 1 AND revision = ?;

-- name: ReadExecutionTrust :one
SELECT revision, state FROM execution_trust WHERE id = 1;

-- name: InitializeExecutionTrust :exec
INSERT INTO execution_trust (id, revision, state) VALUES (1, 1, ?);

-- name: ReplaceExecutionTrust :execrows
UPDATE execution_trust SET revision = revision + 1, state = ? WHERE id = 1 AND revision = ?;

-- name: InitializeResourceActionUsage :exec
INSERT INTO resource_action_usage (id, record_count, record_bytes) VALUES (1, 0, 0);

-- name: ReadResourceActionUsage :one
SELECT record_count, record_bytes FROM resource_action_usage WHERE id = 1;

-- name: ReplaceResourceActionUsage :execrows
UPDATE resource_action_usage SET record_count = ?, record_bytes = ? WHERE id = 1;

-- name: ReadResourceAction :one
SELECT * FROM resource_actions WHERE action_id = ?;

-- name: NextResourceAction :one
SELECT * FROM resource_actions WHERE action_id > ? ORDER BY action_id LIMIT 1;

-- name: NextUnfinishedResourceAction :one
SELECT * FROM resource_actions WHERE action_id > ? AND state IN (1, 2, 3, 9) ORDER BY action_id LIMIT 1;

-- name: InsertResourceAction :exec
INSERT INTO resource_actions (action_id, deployment_id, device_id, enrollment_generation, kind, canonical_key, resource_sequence, revision, state, record, read_only_terminal)
VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?);

-- name: ReplaceResourceAction :execrows
UPDATE resource_actions SET revision = revision + 1, state = ?, record = ?, read_only_terminal = ? WHERE action_id = ? AND revision = ?;

-- name: ReadResourceFloor :one
SELECT * FROM resource_floors
WHERE deployment_id = ? AND device_id = ? AND enrollment_generation = ? AND kind = ? AND canonical_key = ?;

-- name: RaiseResourceFloor :exec
INSERT INTO resource_floors (deployment_id, device_id, enrollment_generation, kind, canonical_key, resource_sequence, action_id)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (deployment_id, device_id, enrollment_generation, kind, canonical_key)
DO UPDATE SET resource_sequence = excluded.resource_sequence, action_id = excluded.action_id;

-- name: ResourceActionTotals :one
SELECT count(*) AS record_count,
    CAST(coalesce(sum(CASE WHEN state IN (1, 2, 3, 9) THEN 1048576 ELSE length(record) END), 0) AS INTEGER) AS record_bytes
FROM resource_actions;

-- name: InvalidResourceFloorCount :one
SELECT count(*) FROM resource_floors AS f
LEFT JOIN resource_actions AS a ON a.action_id = f.action_id
WHERE a.action_id IS NULL OR a.deployment_id != f.deployment_id OR a.device_id != f.device_id
    OR a.enrollment_generation != f.enrollment_generation OR a.kind != f.kind OR a.canonical_key != f.canonical_key OR a.resource_sequence != f.resource_sequence;

-- name: ResourceActionCount :one
SELECT count(*) FROM resource_actions
WHERE deployment_id = ? AND device_id = ? AND enrollment_generation = ? AND kind = ? AND canonical_key = ?;

-- name: OldReadOnlyResourceAction :one
SELECT a.* FROM resource_actions a
WHERE a.read_only_terminal = 1 AND NOT EXISTS (SELECT 1 FROM resource_floors f WHERE f.action_id = a.action_id)
ORDER BY a.rowid DESC LIMIT 1 OFFSET 256;

-- name: DeleteReadOnlyResourceAction :execrows
DELETE FROM resource_actions WHERE resource_actions.action_id = ? AND resource_actions.read_only_terminal = 1
AND NOT EXISTS (SELECT 1 FROM resource_floors f WHERE f.action_id = resource_actions.action_id);

-- name: InitializeResourceOwnershipUsage :exec
INSERT INTO resource_ownership_usage (id, record_count) VALUES (1, 0);

-- name: ReadResourceOwnershipUsage :one
SELECT record_count FROM resource_ownership_usage WHERE id = 1;

-- name: IncrementResourceOwnershipUsage :execrows
UPDATE resource_ownership_usage SET record_count = record_count + 1 WHERE id = 1 AND record_count = ?;

-- name: ResourceOwnershipCount :one
SELECT count(*) FROM resource_ownership;

-- name: ReadResourceOwnership :one
SELECT * FROM resource_ownership
WHERE deployment_id = ? AND device_id = ? AND enrollment_generation = ? AND kind = ? AND canonical_key = ?;

-- name: NextResourceOwnership :one
SELECT * FROM resource_ownership WHERE ledger_id > ? ORDER BY ledger_id LIMIT 1;

-- name: InsertResourceOwnership :exec
INSERT INTO resource_ownership (deployment_id, device_id, enrollment_generation, kind, canonical_key, revision, record)
VALUES (?, ?, ?, ?, ?, 1, ?);

-- name: ReplaceResourceOwnership :execrows
UPDATE resource_ownership SET revision = revision + 1, record = ?
WHERE deployment_id = ? AND device_id = ? AND enrollment_generation = ? AND kind = ? AND canonical_key = ? AND revision = ?;

-- name: ResourceOwnershipHistoricalEffects :one
SELECT count(*) FROM resource_actions
WHERE deployment_id = ? AND device_id = ? AND enrollment_generation = ? AND kind = ? AND canonical_key = ?
    AND state IN (3, 4, 5, 6) AND read_only_terminal = 0;

-- name: ReadDeviceAction :one
SELECT * FROM device_actions WHERE action_id = ?;

-- name: NextDeviceAction :one
SELECT * FROM device_actions WHERE action_id > ? ORDER BY action_id LIMIT 1;

-- name: NextUnfinishedDeviceAction :one
SELECT * FROM device_actions WHERE action_id > ? AND state IN (1, 2, 3, 6, 8, 9) ORDER BY action_id LIMIT 1;

-- name: NextUpdateInterlockDeviceAction :one
SELECT * FROM device_actions WHERE action_id > ? AND state IN (2, 3, 6, 8, 9) ORDER BY action_id LIMIT 1;

-- name: InsertDeviceAction :exec
INSERT INTO device_actions (action_id, deployment_id, device_id, enrollment_generation, action_sequence, revision, state, record)
VALUES (?, ?, ?, ?, ?, 1, ?, ?);

-- name: ReplaceDeviceAction :execrows
UPDATE device_actions SET revision = revision + 1, state = ?, record = ? WHERE action_id = ? AND revision = ?;

-- name: DeviceActionCount :one
SELECT count(*) FROM device_actions;

-- name: DeviceActionSequenceFloor :one
SELECT CAST(coalesce(max(action_sequence), 0) AS INTEGER) FROM device_actions
WHERE deployment_id = ? AND device_id = ? AND enrollment_generation = ?;

-- name: InitializeDeviceActionUsage :exec
INSERT INTO device_action_usage (id, record_count) VALUES (1, 0);

-- name: ReadDeviceActionUsage :one
SELECT record_count FROM device_action_usage WHERE id = 1;

-- name: IncrementDeviceActionUsage :execrows
UPDATE device_action_usage SET record_count = record_count + 1 WHERE id = 1 AND record_count = ?;

-- name: AccountLockCount :one
SELECT count(*) FROM account_locks;

-- name: ReadAccountLock :one
SELECT * FROM account_locks WHERE lock_action_id = ?;

-- name: NextAccountLock :one
SELECT * FROM account_locks WHERE lock_action_id > ? ORDER BY lock_action_id LIMIT 1;

-- name: InsertAccountLock :exec
INSERT INTO account_locks (lock_action_id, revision, record) VALUES (?, 1, ?);

-- name: ReplaceAccountLock :execrows
UPDATE account_locks SET revision = revision + 1, record = ? WHERE lock_action_id = ? AND revision = ?;

-- name: ReadAccountLockOwner :many
SELECT * FROM account_lock_owners WHERE username = ? OR uid = ?;

-- name: InsertAccountLockOwner :exec
INSERT INTO account_lock_owners (username, uid, lock_action_id) VALUES (?, ?, ?);

-- name: DeleteAccountLockOwner :execrows
DELETE FROM account_lock_owners WHERE username = ? AND lock_action_id = ?;

-- name: AccountLockOwnerCount :one
SELECT count(*) FROM account_lock_owners;

-- name: InitializeAccountLockUsage :exec
INSERT INTO account_lock_usage (id, record_count) VALUES (1, 0);

-- name: ReadAccountLockUsage :one
SELECT record_count FROM account_lock_usage WHERE id = 1;

-- name: IncrementAccountLockUsage :execrows
UPDATE account_lock_usage SET record_count = record_count + 1 WHERE id = 1 AND record_count = ?;

-- name: ReadResourcePreparationCancellation :one
SELECT * FROM resource_preparation_cancellations WHERE action_id = ?;

-- name: CountResourcePreparationCancellations :one
SELECT count(*) FROM resource_preparation_cancellations;

-- name: InsertResourcePreparationCancellation :exec
INSERT INTO resource_preparation_cancellations (action_id, enrollment_generation, intent_sha256) VALUES (?, ?, ?);

-- name: InvalidResourcePreparationCancellationCount :one
SELECT count(*) FROM resource_preparation_cancellations c
WHERE length(c.action_id) != 36 OR length(c.enrollment_generation) != 36
    OR EXISTS (SELECT 1 FROM resource_actions a WHERE a.action_id = c.action_id);

-- name: CountResourceOwnershipReservations :one
SELECT count(*) FROM resource_ownership_reservations;

-- name: ReadResourceOwnershipReservation :one
SELECT * FROM resource_ownership_reservations WHERE action_id = ?;

-- name: InsertResourceOwnershipReservation :exec
INSERT INTO resource_ownership_reservations (action_id, deployment_id, device_id, enrollment_generation, kind, canonical_key)
VALUES (?, ?, ?, ?, ?, ?);

-- name: DeleteResourceOwnershipReservation :execrows
DELETE FROM resource_ownership_reservations WHERE action_id = ?;

-- name: InvalidResourceOwnershipReservations :one
SELECT count(*) FROM resource_ownership_reservations r
LEFT JOIN resource_actions a ON a.action_id = r.action_id
WHERE a.action_id IS NULL OR a.deployment_id != r.deployment_id OR a.device_id != r.device_id
    OR a.enrollment_generation != r.enrollment_generation OR a.kind != r.kind OR a.canonical_key != r.canonical_key
    OR a.state NOT IN (1, 2, 3, 9)
    OR EXISTS (SELECT 1 FROM resource_ownership o WHERE o.deployment_id = r.deployment_id AND o.device_id = r.device_id
        AND o.enrollment_generation = r.enrollment_generation AND o.kind = r.kind AND o.canonical_key = r.canonical_key);
