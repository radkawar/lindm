-- SPDX-License-Identifier: Apache-2.0

-- name: InsertAssistanceUnattendedGrant :exec
INSERT INTO assistance_unattended_grants(
    id, request_id, request_digest, approval_id, device_id, operator_id, approver_id, mode, policy_mode, reason,
    target_username, not_before, not_after, schedule, requested_capabilities, max_session_seconds, created_at
) VALUES (
    sqlc.arg('id'), sqlc.arg('request_id'), sqlc.arg('request_digest'), sqlc.arg('approval_id'), sqlc.arg('device_id'),
    sqlc.arg('operator_id'), sqlc.arg('approver_id'), sqlc.arg('mode'), sqlc.arg('policy_mode'), sqlc.arg('reason'),
    sqlc.arg('target_username'), sqlc.arg('not_before'), sqlc.arg('not_after'), sqlc.arg('schedule'),
    sqlc.arg('requested_capabilities'), sqlc.arg('max_session_seconds'), sqlc.arg('created_at')
);

-- name: GetAssistanceUnattendedGrantByRequest :one
SELECT * FROM assistance_unattended_grants WHERE request_id = sqlc.arg('request_id');

-- name: LockAssistanceUnattendedGrant :one
SELECT * FROM assistance_unattended_grants WHERE id = sqlc.arg('id') FOR UPDATE;

-- name: GetAssistanceUnattendedGrantView :one
SELECT sqlc.embed(g),
  coalesce(nullif(operator.display_name, ''), operator_account.username, '')::text AS operator_display,
  coalesce(nullif(approver.display_name, ''), approver_account.username, '')::text AS approver_display
FROM assistance_unattended_grants g
LEFT JOIN principals operator ON operator.id = g.operator_id
LEFT JOIN local_accounts operator_account ON operator_account.id = g.operator_id
LEFT JOIN principals approver ON approver.id = g.approver_id
LEFT JOIN local_accounts approver_account ON approver_account.id = g.approver_id
WHERE g.id = sqlc.arg('id');

-- name: ListAssistanceUnattendedGrants :many
SELECT sqlc.embed(g),
  coalesce(nullif(operator.display_name, ''), operator_account.username, '')::text AS operator_display,
  coalesce(nullif(approver.display_name, ''), approver_account.username, '')::text AS approver_display
FROM assistance_unattended_grants g
LEFT JOIN principals operator ON operator.id = g.operator_id
LEFT JOIN local_accounts operator_account ON operator_account.id = g.operator_id
LEFT JOIN principals approver ON approver.id = g.approver_id
LEFT JOIN local_accounts approver_account ON approver_account.id = g.approver_id
WHERE g.device_id = sqlc.arg('device_id')
ORDER BY g.created_at DESC, g.id DESC
LIMIT 50;

-- name: RevokeAssistanceUnattendedGrant :exec
UPDATE assistance_unattended_grants
SET revoked_at = sqlc.arg('revoked_at'), revoked_by = sqlc.narg('revoked_by'), revoke_reason = sqlc.arg('revoke_reason')
WHERE id = sqlc.arg('id') AND revoked_at IS NULL;

-- name: LockLiveAssistanceUnattendedGrants :many
SELECT * FROM assistance_unattended_grants
WHERE device_id = sqlc.arg('device_id') AND revoked_at IS NULL AND not_after > sqlc.arg('now')::timestamptz
ORDER BY id
FOR UPDATE;

-- name: InsertAssistanceUnattendedEnrollment :exec
INSERT INTO assistance_unattended_enrollments(id, device_id, session_id, mode, created_at, expires_at)
VALUES (sqlc.arg('id'), sqlc.arg('device_id'), sqlc.arg('session_id'), sqlc.arg('mode'), sqlc.arg('created_at'), sqlc.arg('expires_at'));

-- name: GetAssistanceUnattendedEnrollmentBySession :one
SELECT * FROM assistance_unattended_enrollments WHERE session_id = sqlc.arg('session_id');

-- name: LockAssistanceUnattendedEnrollment :one
SELECT * FROM assistance_unattended_enrollments WHERE id = sqlc.arg('id') FOR UPDATE;

-- name: LockEnrolledAssistanceUnattended :one
SELECT * FROM assistance_unattended_enrollments
WHERE device_id = sqlc.arg('device_id') AND username = sqlc.arg('username') AND state = 1
FOR UPDATE;

-- name: LockEnrolledAssistanceUnattendedForDevice :many
SELECT * FROM assistance_unattended_enrollments
WHERE device_id = sqlc.arg('device_id') AND state = 1
ORDER BY id
FOR UPDATE;

-- name: ConsentAssistanceUnattendedEnrollment :exec
UPDATE assistance_unattended_enrollments
SET state = 1, username = sqlc.arg('username'), uid = sqlc.arg('uid'), consented_at = sqlc.arg('consented_at')
WHERE id = sqlc.arg('id') AND state = 0;

-- name: DeclineAssistanceUnattendedEnrollment :exec
UPDATE assistance_unattended_enrollments SET state = 3, revoke_reason = sqlc.arg('reason')
WHERE id = sqlc.arg('id') AND state = 0;

-- name: RevokeAssistanceUnattendedEnrollment :exec
UPDATE assistance_unattended_enrollments
SET state = 2, revoked_at = sqlc.arg('revoked_at'), revoke_reason = sqlc.arg('reason')
WHERE id = sqlc.arg('id') AND state = 1;

-- name: ListAssistanceUnattendedEnrollments :many
SELECT * FROM assistance_unattended_enrollments
WHERE device_id = sqlc.arg('device_id') AND state <> 0
ORDER BY created_at DESC, id DESC
LIMIT 20;

-- name: SetAssistanceUnattended :exec
UPDATE assistance_sessions
SET unattended_grant_id = sqlc.arg('unattended_grant_id'), unattended_enrollment_id = sqlc.arg('unattended_enrollment_id')
WHERE id = sqlc.arg('id') AND state = 1;
