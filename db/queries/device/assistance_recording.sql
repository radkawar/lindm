-- SPDX-License-Identifier: Apache-2.0

-- name: SetAssistanceReconnect :exec
UPDATE assistance_sessions
SET reconnect_workflow_id = sqlc.arg('reconnect_workflow_id'), reconnect_of = sqlc.narg('reconnect_of')
WHERE id = sqlc.arg('id');

-- name: GetAssistanceSessionByReconnectOf :one
SELECT * FROM assistance_sessions WHERE reconnect_of = sqlc.arg('reconnect_of');

-- name: InsertAssistanceReconnectWorkflow :exec
INSERT INTO assistance_reconnect_workflows(id, device_id, operator_id, origin_session_id, latest_session_id, mode, window_seconds, max_reconnects, target_username, created_at)
VALUES (sqlc.arg('id'), sqlc.arg('device_id'), sqlc.arg('operator_id'), sqlc.arg('origin_session_id'), sqlc.arg('origin_session_id'), sqlc.arg('mode'), sqlc.arg('window_seconds'), sqlc.arg('max_reconnects'), sqlc.arg('target_username'), sqlc.arg('created_at'));

-- name: GetAssistanceReconnectWorkflow :one
SELECT * FROM assistance_reconnect_workflows WHERE id = sqlc.arg('id');

-- name: LockAssistanceReconnectWorkflow :one
SELECT * FROM assistance_reconnect_workflows WHERE id = sqlc.arg('id') FOR UPDATE;

-- name: LockOpenAssistanceReconnectWorkflow :one
SELECT * FROM assistance_reconnect_workflows WHERE device_id = sqlc.arg('device_id') AND state < 3 FOR UPDATE;

-- name: GetAutomaticAssistanceReconnect :one
-- Observation only; the reconnect itself relocks and rechecks everything.
SELECT * FROM assistance_reconnect_workflows
WHERE device_id = sqlc.arg('device_id') AND state = 2 AND mode = 3
  AND expires_at > sqlc.arg('now')::timestamptz
  AND (next_attempt_at IS NULL OR next_attempt_at <= sqlc.arg('now')::timestamptz);

-- name: UpdateAssistanceReconnectWorkflow :exec
UPDATE assistance_reconnect_workflows
SET latest_session_id = sqlc.arg('latest_session_id'),
    reconnects = sqlc.arg('reconnects'),
    target_username = sqlc.arg('target_username'),
    approved = sqlc.arg('approved'),
    state = sqlc.arg('state'),
    expires_at = sqlc.narg('expires_at'),
    next_attempt_at = sqlc.narg('next_attempt_at'),
    ended_at = sqlc.narg('ended_at'),
    end_reason = sqlc.arg('end_reason')
WHERE id = sqlc.arg('id') AND state < 3;

-- name: ListExpiredAssistanceReconnects :many
SELECT id FROM assistance_reconnect_workflows
WHERE state = 2 AND expires_at <= sqlc.arg('now')::timestamptz
ORDER BY expires_at
LIMIT 64;

-- name: InsertAssistanceRecording :exec
INSERT INTO assistance_recordings(id, session_id, device_id, operator_id, required, key_id, max_bytes, retention_days, created_at)
VALUES (sqlc.arg('id'), sqlc.arg('session_id'), sqlc.arg('device_id'), sqlc.arg('operator_id'), sqlc.arg('required'), sqlc.arg('key_id'), sqlc.arg('max_bytes'), sqlc.arg('retention_days'), sqlc.arg('created_at'));

-- name: GetAssistanceRecording :one
SELECT * FROM assistance_recordings WHERE id = sqlc.arg('id');

-- name: LockAssistanceRecording :one
SELECT * FROM assistance_recordings WHERE id = sqlc.arg('id') FOR UPDATE;

-- name: GetAssistanceRecordingBySession :one
SELECT * FROM assistance_recordings WHERE session_id = sqlc.arg('session_id');

-- name: LockAssistanceRecordingBySession :one
SELECT * FROM assistance_recordings WHERE session_id = sqlc.arg('session_id') FOR UPDATE;

-- name: UpdateAssistanceRecording :exec
UPDATE assistance_recordings
SET state = sqlc.arg('state'),
    encapsulated_key = sqlc.arg('encapsulated_key'),
    segments = sqlc.arg('segments'),
    stored_bytes = sqlc.arg('stored_bytes'),
    hash_state = sqlc.arg('hash_state'),
    ciphertext_sha256 = sqlc.arg('ciphertext_sha256'),
    started_at = sqlc.narg('started_at'),
    last_segment_at = sqlc.narg('last_segment_at'),
    finalized_at = sqlc.narg('finalized_at'),
    retain_until = sqlc.narg('retain_until'),
    deleted_at = sqlc.narg('deleted_at'),
    reason = sqlc.arg('reason')
WHERE id = sqlc.arg('id');

-- name: ListAssistanceRecordings :many
SELECT * FROM assistance_recordings
WHERE device_id = sqlc.arg('device_id')
  AND (NOT sqlc.arg('has_cursor')::boolean OR (created_at, id) < (sqlc.arg('cursor_time')::timestamptz, sqlc.arg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('page_limit')::int;

-- name: LockAssistanceRecordingQuota :exec
SELECT pg_advisory_xact_lock(583310948);

-- name: AssistanceRecordingStoredBytes :one
SELECT COALESCE(sum(stored_bytes), 0)::bigint FROM assistance_recordings WHERE state <> 7;

-- name: InsertAssistanceRecordingSegment :exec
INSERT INTO assistance_recording_segments(recording_id, sequence, final, ciphertext, digest, stored_at)
VALUES (sqlc.arg('recording_id'), sqlc.arg('sequence'), sqlc.arg('final'), sqlc.arg('ciphertext'), sqlc.arg('digest'), sqlc.arg('stored_at'));

-- name: GetAssistanceRecordingSegment :one
SELECT * FROM assistance_recording_segments WHERE recording_id = sqlc.arg('recording_id') AND sequence = sqlc.arg('sequence');

-- name: GetAssistanceRecordingSegmentDigest :one
SELECT final, digest FROM assistance_recording_segments WHERE recording_id = sqlc.arg('recording_id') AND sequence = sqlc.arg('sequence');

-- name: DeleteAssistanceRecordingSegments :exec
DELETE FROM assistance_recording_segments WHERE recording_id = sqlc.arg('recording_id');

-- name: ListAssistanceRecordingsDue :many
-- Retention-expired archives, then recordings whose session ended beyond the
-- finalization grace without a final segment.
SELECT r.id FROM assistance_recordings r
WHERE (r.state IN (3, 4) AND r.retain_until <= sqlc.arg('now')::timestamptz)
   OR (r.state IN (1, 2) AND EXISTS (
        SELECT 1 FROM assistance_sessions s
        WHERE s.id = r.session_id AND s.state = 6 AND s.ended_at <= sqlc.arg('settle_before')::timestamptz))
ORDER BY r.created_at
LIMIT 32;

-- name: InsertAssistanceRecordingRetrieval :exec
INSERT INTO assistance_recording_retrievals(id, recording_id, operator_id, created_at, expires_at)
VALUES (sqlc.arg('id'), sqlc.arg('recording_id'), sqlc.arg('operator_id'), sqlc.arg('created_at'), sqlc.arg('expires_at'));

-- name: GetAssistanceRecordingRetrieval :one
SELECT * FROM assistance_recording_retrievals WHERE id = sqlc.arg('id');

-- name: DeleteExpiredAssistanceRecordingRetrievals :exec
DELETE FROM assistance_recording_retrievals WHERE expires_at <= sqlc.arg('now')::timestamptz;

-- name: DeleteAssistanceRecordingRetrievals :exec
DELETE FROM assistance_recording_retrievals WHERE recording_id = sqlc.arg('recording_id');

-- name: GetAssistanceRecordingDeletion :one
SELECT * FROM assistance_recording_deletions WHERE request_id = sqlc.arg('request_id');

-- name: InsertAssistanceRecordingDeletion :exec
INSERT INTO assistance_recording_deletions(request_id, recording_id, operator_id, request_digest)
VALUES (sqlc.arg('request_id'), sqlc.arg('recording_id'), sqlc.arg('operator_id'), sqlc.arg('request_digest'));
