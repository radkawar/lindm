-- SPDX-License-Identifier: Apache-2.0

-- name: InsertDeviceActionRecovery :exec
INSERT INTO device_action_recovery (action_id, credential_id, certificate_id, session_epoch, public_key, handoff_proof, handoff_document, credential_envelope, credential_sha256, credential_document, boot_grant_envelope, root_json, delegation_envelope, expires_at)
VALUES (sqlc.arg('action_id'), sqlc.arg('credential_id'), sqlc.arg('certificate_id'), sqlc.arg('session_epoch'), sqlc.arg('public_key'), sqlc.arg('handoff_proof'), sqlc.arg('handoff_document'), sqlc.arg('credential_envelope'), sqlc.arg('credential_sha256'), sqlc.arg('credential_document'), sqlc.arg('boot_grant_envelope'), sqlc.arg('root_json'), sqlc.arg('delegation_envelope'), sqlc.arg('expires_at'));

-- name: GetDeviceActionRecovery :one
SELECT * FROM device_action_recovery WHERE action_id = $1;

-- name: GetRecoveryCredential :one
SELECT * FROM device_action_recovery WHERE credential_sha256 = $1;

-- name: LockDeviceActionRecovery :one
SELECT * FROM device_action_recovery WHERE action_id = $1 FOR UPDATE;

-- name: SetRecoveryStartGrant :exec
UPDATE device_action_recovery SET challenge_document = sqlc.arg('challenge_document'), start_grant_envelope = sqlc.arg('start_grant_envelope'), start_authorized_at = sqlc.arg('start_authorized_at') WHERE action_id = sqlc.arg('action_id');

-- name: SetRecoveryCheckpoint :exec
UPDATE device_action_recovery SET checkpoint_document = sqlc.arg('checkpoint_document'), checkpoint_sha256 = sqlc.arg('checkpoint_sha256'), checkpoint_sequence = sqlc.arg('checkpoint_sequence'), checkpoint_receipt_envelope = sqlc.arg('checkpoint_receipt_envelope'), journal_document = sqlc.arg('journal_document'), effect_committed_at = CASE WHEN sqlc.arg('effect_committed')::boolean THEN sqlc.arg('stored_at')::timestamptz ELSE effect_committed_at END WHERE action_id = sqlc.arg('action_id');

-- name: SetRecoveryNonce :exec
UPDATE device_action_recovery SET result_nonce = sqlc.arg('result_nonce'), nonce_expires_at = sqlc.arg('nonce_expires_at') WHERE action_id = sqlc.arg('action_id');

-- name: SetRecoveryResult :exec
UPDATE device_action_recovery SET result_request_id = sqlc.arg('result_request_id'), result_proof = sqlc.arg('result_proof'), result_document = sqlc.arg('result_document'), result_nonce = '', nonce_expires_at = NULL WHERE action_id = sqlc.arg('action_id');

-- name: GetRecoveryRequest :one
SELECT * FROM device_action_recovery_requests WHERE credential_id = sqlc.arg('credential_id') AND request_id = sqlc.arg('request_id');

-- name: InsertRecoveryRequest :exec
INSERT INTO device_action_recovery_requests (credential_id, request_id, nonce, request_sha256, response_document)
VALUES (sqlc.arg('credential_id'), sqlc.arg('request_id'), sqlc.arg('nonce'), sqlc.arg('request_sha256'), sqlc.arg('response_document'));

-- name: RecoveryRequestCount :one
SELECT count(*)::bigint FROM device_action_recovery_requests WHERE credential_id = $1;

-- name: MarkDeviceActionOutcomeUnknown :exec
UPDATE device_actions SET outcome_unknown = true WHERE id = $1;
