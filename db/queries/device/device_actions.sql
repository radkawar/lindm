-- name: InsertDeviceAction :exec
INSERT INTO device_actions (id, device_id, generation_id, capability, luks_uuids, request_id, request_digest, request_document, actor_id, authorization_version, approval_id, intent_envelope, intent_document, issued_at, expires_at)
VALUES (sqlc.arg('id'), sqlc.arg('device_id'), sqlc.arg('generation_id'), sqlc.arg('capability'), sqlc.arg('luks_uuids'), sqlc.arg('request_id'), sqlc.arg('request_digest'), sqlc.arg('request_document'), sqlc.arg('actor_id'), sqlc.arg('authorization_version'), sqlc.narg('approval_id'), sqlc.arg('intent_envelope'), sqlc.arg('intent_document'), sqlc.arg('issued_at'), sqlc.arg('expires_at'));

-- name: GetDeviceActionRequest :one
SELECT * FROM device_actions WHERE request_id = $1;

-- name: GetDeviceAction :one
SELECT * FROM device_actions WHERE id = $1;

-- name: LockDeviceAction :one
SELECT * FROM device_actions WHERE id = $1 FOR UPDATE;

-- name: GetOpenDeviceAction :one
SELECT * FROM device_actions WHERE device_id = $1 AND closed_at IS NULL FOR UPDATE;

-- name: ListDeviceActions :many
SELECT * FROM device_actions
WHERE device_id = sqlc.arg('device_id')
AND (NOT sqlc.arg('has_cursor')::boolean OR (issued_at, id) < (sqlc.arg('cursor_time')::timestamptz, sqlc.arg('cursor_id')::uuid))
AND (cardinality(sqlc.arg('capabilities')::text[]) = 0 OR capability = ANY(sqlc.arg('capabilities')::text[]))
ORDER BY issued_at DESC, id DESC LIMIT sqlc.arg('page_limit');

-- name: ListDeviceActionActorNames :many
SELECT p.id, coalesce(nullif(p.display_name, ''), account.username, '')::text AS display_name
FROM principals p
LEFT JOIN local_accounts account ON account.id = p.id
WHERE p.id = ANY(sqlc.arg('ids')::uuid[]);

-- name: SetDeviceActionNonce :exec
UPDATE device_actions SET result_nonce = sqlc.arg('result_nonce'), nonce_expires_at = sqlc.arg('nonce_expires_at') WHERE id = sqlc.arg('id');

-- name: SetDeviceActionGrant :exec
UPDATE device_actions SET challenge_proof = sqlc.arg('challenge_proof'), challenge_document = sqlc.arg('challenge_document'), start_grant_envelope = sqlc.arg('start_grant_envelope'), start_authorized_at = sqlc.arg('start_authorized_at'), outcome_unknown = true WHERE id = sqlc.arg('id');

-- name: CloseDeviceAction :exec
UPDATE device_actions SET closed_at = sqlc.arg('closed_at'), closed_reason = sqlc.arg('closed_reason') WHERE id = sqlc.arg('id');

-- name: SetDeviceActionResult :exec
UPDATE device_actions SET action_revision = sqlc.arg('action_revision'), attestation_envelope = sqlc.arg('attestation_envelope'), attestation_certificate = sqlc.arg('attestation_certificate'), status_document = sqlc.arg('status_document'), received_at = sqlc.arg('received_at'), outcome_unknown = sqlc.arg('outcome_unknown'), result_nonce = '', nonce_expires_at = NULL WHERE id = sqlc.arg('id');

-- name: InsertDeviceActionEscrow :one
INSERT INTO device_action_escrow (action_id, binding_document, key_id, wrapped_key, ciphertext, secret_sha256)
VALUES (sqlc.arg('action_id'), sqlc.arg('binding_document'), sqlc.arg('key_id'), sqlc.arg('wrapped_key'), sqlc.arg('ciphertext'), sqlc.arg('secret_sha256')) RETURNING *;

-- name: GetDeviceActionEscrow :one
SELECT * FROM device_action_escrow WHERE action_id = $1;

-- name: SetDeviceActionEscrowReceipt :exec
UPDATE device_actions SET escrow_receipt_envelope = sqlc.arg('escrow_receipt_envelope') WHERE id = sqlc.arg('id');

-- name: SetDeviceActionInventoryReceipt :exec
UPDATE device_actions SET inventory_receipt_envelope = sqlc.arg('inventory_receipt_envelope'), inventory_receipt_document = sqlc.arg('inventory_receipt_document') WHERE id = sqlc.arg('id');

-- Admission slots bind the first fresh collection, even when the routine limiter
-- would admit it. The caller holds the device/action locks in the ingestion tx.
-- name: ClaimDeviceActionHostAdmission :execrows
UPDATE device_actions SET inventory_host_sequence = sqlc.arg('sequence'), inventory_host_received_at = sqlc.arg('received_at')
WHERE id = sqlc.arg('id') AND inventory_host_sequence = 0 AND closed_at IS NULL
AND capability = 'device.refresh-inventory.v1' AND start_authorized_at IS NOT NULL;

-- name: ClaimDeviceActionPackageAdmission :execrows
UPDATE device_actions SET inventory_package_sequence = sqlc.arg('sequence')
WHERE id = sqlc.arg('id') AND inventory_package_sequence = 0 AND closed_at IS NULL
AND capability = 'device.refresh-inventory.v1' AND start_authorized_at IS NOT NULL;

-- name: SetDeviceActionRestriction :exec
INSERT INTO device_action_restrictions (device_id, sessions_locked, lock_action_id, quarantined, action_id, updated_at, quarantine_until)
VALUES (sqlc.arg('device_id'), sqlc.arg('sessions_locked'), CASE WHEN sqlc.arg('set_sessions')::boolean THEN sqlc.arg('action_id')::uuid ELSE NULL END, sqlc.arg('quarantined'), sqlc.arg('action_id'), sqlc.arg('updated_at'), CASE WHEN sqlc.arg('quarantined')::boolean THEN sqlc.arg('updated_at')::timestamptz + interval '330 seconds' ELSE NULL END)
ON CONFLICT (device_id) DO UPDATE SET
sessions_locked = CASE WHEN sqlc.arg('set_sessions')::boolean THEN EXCLUDED.sessions_locked ELSE device_action_restrictions.sessions_locked END,
lock_action_id = CASE WHEN sqlc.arg('set_sessions')::boolean THEN EXCLUDED.lock_action_id ELSE device_action_restrictions.lock_action_id END,
quarantined = CASE WHEN sqlc.arg('set_quarantine')::boolean THEN EXCLUDED.quarantined ELSE device_action_restrictions.quarantined END,
quarantine_until = CASE WHEN sqlc.arg('set_quarantine')::boolean THEN EXCLUDED.quarantine_until ELSE device_action_restrictions.quarantine_until END,
action_id = EXCLUDED.action_id, updated_at = EXCLUDED.updated_at;

-- name: GetDeviceActionRestriction :one
SELECT * FROM device_action_restrictions WHERE device_id = $1;

-- Release only the original fence, never a newer lock or the quarantine fence.
-- name: ReleaseDeviceActionLock :exec
UPDATE device_action_restrictions
SET sessions_locked = false, lock_action_id = NULL, updated_at = sqlc.arg('updated_at')
WHERE device_id = sqlc.arg('device_id') AND lock_action_id = sqlc.arg('lock_action_id');

-- name: LatestDeviceActionEscrow :one
SELECT a.* FROM device_actions a JOIN device_action_escrow e ON e.action_id = a.id
JOIN devices d ON d.id = a.device_id AND d.current_generation_id = a.generation_id
WHERE a.device_id = sqlc.arg('device_id') AND a.capability = 'device.escrow-rotate.v1' AND (sqlc.narg('luks_uuid')::uuid IS NULL OR a.luks_uuids @> ARRAY[sqlc.narg('luks_uuid')::uuid])
ORDER BY e.committed_at DESC, a.id DESC LIMIT 1;

-- name: LatestDeviceActionObservation :one
SELECT a.* FROM device_actions a JOIN devices d ON d.id = a.device_id AND d.current_generation_id = a.generation_id
WHERE a.device_id = sqlc.arg('device_id') AND octet_length(a.status_document) > 0
AND (sqlc.narg('luks_uuid')::uuid IS NULL OR a.luks_uuids @> ARRAY[sqlc.narg('luks_uuid')::uuid])
AND a.capability IN ('device.escrow-rotate.v1', 'device.tpm2-bind.v1', 'device.crypto-erase.v1', 'device.sanitize.v1')
ORDER BY a.received_at DESC, a.id DESC LIMIT 1;

-- name: ExpireDeviceActionQuarantine :exec
UPDATE device_action_restrictions SET quarantined = false
WHERE device_id = $1 AND quarantined AND quarantine_until <= clock_timestamp();

-- name: DeviceActionCount :one
SELECT count(*)::bigint FROM device_actions WHERE generation_id = $1;

-- Historical custody remains relevant across reenrollment. A live-root erase
-- cannot silently omit a device volume merely because its key is older.
-- name: ListDeviceEscrowedVolumes :many
SELECT DISTINCT unnest(a.luks_uuids)::uuid AS luks_uuid FROM device_actions a
JOIN device_action_escrow e ON e.action_id = a.id
WHERE a.device_id = $1
ORDER BY luks_uuid LIMIT 65;

-- Admission claims prove postchallenge collection. The host receipt is retained
-- on the action because the latest host observation can be overwritten later.
-- name: GetDeviceActionInventoryPublication :one
SELECT s.id AS snapshot_id, s.sequence AS package_sequence,
       a.inventory_host_sequence AS host_sequence,
       greatest(s.committed_at, a.inventory_host_received_at)::timestamptz AS published_at
FROM device_actions a
JOIN package_snapshots s ON s.generation_id = a.generation_id
    AND s.device_id = a.device_id AND s.sequence = a.inventory_package_sequence
WHERE a.id = sqlc.arg('action_id')
  AND a.inventory_host_sequence > 0
  AND a.inventory_host_received_at >= a.start_authorized_at
  AND s.state IN ('committed', 'superseded')
  AND s.committed_at >= a.start_authorized_at;
