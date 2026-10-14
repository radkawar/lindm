-- SPDX-License-Identifier: Apache-2.0

-- name: InsertAssistanceSession :exec
INSERT INTO assistance_sessions (
    id,
    device_id,
    generation_id,
    request_id,
    request_digest,
    operator_id,
    operator_display,
    mode,
    reason,
    target_username,
    state,
    created_at,
    consent_deadline,
    ends_at
) VALUES (
    sqlc.arg('id'),
    sqlc.arg('device_id'),
    sqlc.arg('generation_id'),
    sqlc.arg('request_id'),
    sqlc.arg('request_digest'),
    sqlc.arg('operator_id'),
    sqlc.arg('operator_display'),
    sqlc.arg('mode'),
    sqlc.arg('reason'),
    sqlc.arg('target_username'),
    1,
    sqlc.arg('created_at'),
    sqlc.arg('consent_deadline'),
    sqlc.arg('ends_at')
);

-- name: GetAssistanceSessionByRequest :one
SELECT * FROM assistance_sessions
WHERE request_id = sqlc.arg('request_id');

-- name: GetAssistanceSession :one
SELECT * FROM assistance_sessions
WHERE id = sqlc.arg('id');

-- name: LockAssistanceSession :one
SELECT * FROM assistance_sessions
WHERE id = sqlc.arg('id')
FOR UPDATE;

-- name: LockOpenAssistanceSession :one
SELECT * FROM assistance_sessions
WHERE device_id = sqlc.arg('device_id') AND state <> 6
FOR UPDATE;

-- name: LockAssistanceSessionForDevice :one
SELECT * FROM assistance_sessions
WHERE id = sqlc.arg('id') AND device_id = sqlc.arg('device_id')
FOR UPDATE;

-- name: LockAssistanceAdmission :exec
SELECT pg_advisory_xact_lock(583310947);

-- name: CountLiveAssistanceSessions :one
-- Deadline-due sessions are ended lazily; they never consume admission.
SELECT count(*)::bigint FROM assistance_sessions
WHERE state <> 6
  AND ends_at > sqlc.arg('now')::timestamptz
  AND NOT (state IN (1, 2) AND consent_deadline <= sqlc.arg('now')::timestamptz)
  AND NOT (state IN (2, 3, 4, 5) AND (device_synced_at IS NULL OR device_synced_at <= sqlc.arg('unreachable_before')::timestamptz));

-- name: ListAssistanceSessions :many
SELECT * FROM assistance_sessions
WHERE device_id = sqlc.arg('device_id')
  AND (NOT sqlc.arg('has_cursor')::boolean OR (created_at, id) < (sqlc.arg('cursor_time')::timestamptz, sqlc.arg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('page_limit')::int;

-- name: ListAssistanceDirectiveSessions :many
-- Open sessions first, then recently ended sessions the device has not confirmed.
SELECT * FROM assistance_sessions
WHERE device_id = sqlc.arg('device_id')
  AND (state <> 6 OR (NOT device_ended AND ended_at > sqlc.arg('ended_after')::timestamptz))
ORDER BY (state = 6), created_at DESC, id DESC
LIMIT 8;

-- name: TouchAssistanceDeviceSync :exec
UPDATE assistance_sessions
SET device_synced_at = sqlc.arg('synced_at')
WHERE device_id = sqlc.arg('device_id') AND state <> 6;

-- name: BindAssistanceLocalSession :exec
UPDATE assistance_sessions
SET
    state = 2,
    prompted_at = sqlc.arg('prompted_at'),
    local_username = sqlc.arg('local_username'),
    local_uid = sqlc.arg('local_uid'),
    local_logind_session = sqlc.arg('local_logind_session'),
    local_session_type = sqlc.arg('local_session_type'),
    local_desktop = sqlc.arg('local_desktop')
WHERE id = sqlc.arg('id') AND state = 1;

-- name: OfferAssistanceSession :exec
UPDATE assistance_sessions
SET
    state = 3,
    consented_at = sqlc.arg('consented_at'),
    control_granted = sqlc.arg('control_granted'),
    offer_sdp = sqlc.arg('offer_sdp'),
    offer_fingerprint = sqlc.arg('offer_fingerprint')
WHERE id = sqlc.arg('id') AND state = 2;

-- name: AnswerAssistanceSession :exec
UPDATE assistance_sessions
SET
    state = 4,
    answered_at = sqlc.arg('answered_at'),
    answer_sdp = sqlc.arg('answer_sdp'),
    answer_fingerprint = sqlc.arg('answer_fingerprint')
WHERE id = sqlc.arg('id') AND state = 3;

-- name: StartAssistanceSession :exec
UPDATE assistance_sessions
SET
    state = 5,
    started_at = sqlc.arg('started_at')
WHERE id = sqlc.arg('id') AND state = 4;

-- name: EndAssistanceSession :exec
-- Ended sessions keep fingerprints for audit but drop SDP signaling state.
UPDATE assistance_sessions
SET
    state = 6,
    ended_at = sqlc.arg('ended_at'),
    end_cause = sqlc.arg('end_cause'),
    end_detail = sqlc.arg('end_detail'),
    device_ended = sqlc.arg('device_ended'),
    offer_sdp = '',
    answer_sdp = ''
WHERE id = sqlc.arg('id') AND state <> 6;

-- name: ConfirmAssistanceDeviceEnded :exec
UPDATE assistance_sessions
SET device_ended = true
WHERE id = sqlc.arg('id') AND state = 6;

-- name: SetAssistanceCapabilities :exec
UPDATE assistance_sessions
SET requested_capabilities = sqlc.arg('requested_capabilities'),
    effective_capabilities = sqlc.arg('effective_capabilities')
WHERE id = sqlc.arg('id');

-- name: SetAssistanceProjection :exec
UPDATE assistance_sessions
SET capability_projection = sqlc.arg('capability_projection')
WHERE id = sqlc.arg('id') AND state <> 6;

-- name: GetOpenAssistanceSession :one
SELECT * FROM assistance_sessions WHERE device_id = sqlc.arg('device_id') AND state <> 6;

-- name: GetAssistancePolicy :one
SELECT policy FROM assistance_policies WHERE device_id = sqlc.arg('device_id');

-- name: PutAssistancePolicy :exec
INSERT INTO assistance_policies(device_id, policy)
VALUES (sqlc.arg('device_id'), sqlc.arg('policy'))
ON CONFLICT (device_id) DO UPDATE SET policy = EXCLUDED.policy;

-- name: GetAssistancePolicyRequest :one
SELECT * FROM assistance_policy_requests WHERE request_id = sqlc.arg('request_id');

-- name: InsertAssistancePolicyRequest :exec
INSERT INTO assistance_policy_requests(request_id, device_id, operator_id, request_digest, policy)
VALUES (sqlc.arg('request_id'), sqlc.arg('device_id'), sqlc.arg('operator_id'), sqlc.arg('request_digest'), sqlc.arg('policy'));

-- name: InsertAssistanceCommand :exec
INSERT INTO assistance_commands(request_id, session_id, device_id, operator_id, request_digest, kind, policy, byte_count, special_key, display_id, deadline, status)
VALUES (sqlc.arg('request_id'), sqlc.arg('session_id'), sqlc.arg('device_id'), sqlc.arg('operator_id'), sqlc.arg('request_digest'), sqlc.arg('kind'), sqlc.arg('policy'), sqlc.arg('byte_count'), sqlc.arg('special_key'), sqlc.arg('display_id'), sqlc.arg('deadline'), 1);

-- name: GetAssistanceCommand :one
SELECT * FROM assistance_commands WHERE request_id = sqlc.arg('request_id');

-- name: GetPendingAssistanceCommand :one
SELECT * FROM assistance_commands WHERE session_id = sqlc.arg('session_id') AND status = 1;

-- name: FinishAssistanceCommand :exec
UPDATE assistance_commands
SET status = sqlc.arg('status'), reason = sqlc.arg('reason'), completed_at = sqlc.arg('completed_at'), byte_count = sqlc.arg('byte_count')
WHERE request_id = sqlc.arg('request_id') AND status = 1;

-- name: AuthorizeAssistanceSession :exec
UPDATE assistance_sessions SET authorized_until = sqlc.arg('authorized_until')
WHERE id = sqlc.arg('id') AND state <> 6;

-- name: SetAssistanceEffectiveCapabilities :exec
UPDATE assistance_sessions SET effective_capabilities = sqlc.arg('effective_capabilities')
WHERE id = sqlc.arg('id') AND state <> 6;

-- name: CountAssistanceCommands :one
SELECT count(*)::bigint FROM assistance_commands WHERE session_id = sqlc.arg('session_id');

-- name: SetAssistanceDevicePolicy :exec
-- Writes only when the reported value changes, not on every idle sync.
INSERT INTO assistance_device_policies (device_id, policy, changed_at)
VALUES (sqlc.arg('device_id'), sqlc.arg('policy'), sqlc.arg('changed_at'))
ON CONFLICT (device_id) DO UPDATE
SET policy = excluded.policy, changed_at = excluded.changed_at
WHERE assistance_device_policies.policy <> excluded.policy;

-- name: ClearAssistanceDevicePolicy :exec
DELETE FROM assistance_device_policies
WHERE device_id = sqlc.arg('device_id');

-- name: GetAssistanceReadiness :one
-- At most one non-ended session exists per device (assistance_sessions_one_open).
SELECT
    d.state,
    d.current_generation_id,
    d.last_seen_at,
    p.policy AS reported_policy,
    h.finished_at AS inventory_finished_at,
    h.details AS inventory_details,
    s.id AS open_session_id
FROM devices d
LEFT JOIN assistance_device_policies p ON p.device_id = d.id
LEFT JOIN host_observations h ON h.generation_id = d.current_generation_id
LEFT JOIN assistance_sessions s ON s.device_id = d.id AND s.state <> 6
WHERE d.id = sqlc.arg('device_id');
