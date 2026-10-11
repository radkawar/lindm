-- name: LockLocalAdminPolicy :one
SELECT * FROM local_admin_password_policies WHERE device_id = $1 FOR UPDATE;

-- name: GetLocalAdminPolicy :one
SELECT p.*, coalesce(nullif(actor.display_name, ''), account.username, '')::text AS actor_display_name
FROM local_admin_password_policies p
LEFT JOIN principals actor ON actor.id = p.actor_id
LEFT JOIN local_accounts account ON account.id = actor.id
WHERE p.device_id = $1;

-- name: UpsertLocalAdminPolicy :exec
INSERT INTO local_admin_password_policies (device_id, account_name, rotation_interval_seconds, post_reveal_delay_seconds, actor_id, authorization_version, request_id, rotate_due_at, blocked_reason, created_at, updated_at)
VALUES (sqlc.arg('device_id'), sqlc.arg('account_name'), sqlc.arg('rotation_interval_seconds'), sqlc.arg('post_reveal_delay_seconds'), sqlc.arg('actor_id'), sqlc.arg('authorization_version'), sqlc.arg('request_id'), sqlc.arg('rotate_due_at'), '', sqlc.arg('updated_at'), sqlc.arg('updated_at'))
ON CONFLICT (device_id) DO UPDATE SET
account_name = EXCLUDED.account_name,
rotation_interval_seconds = EXCLUDED.rotation_interval_seconds,
post_reveal_delay_seconds = EXCLUDED.post_reveal_delay_seconds,
actor_id = EXCLUDED.actor_id,
authorization_version = EXCLUDED.authorization_version,
request_id = EXCLUDED.request_id,
rotate_due_at = EXCLUDED.rotate_due_at,
blocked_reason = '',
updated_at = EXCLUDED.updated_at;

-- name: DeleteLocalAdminPolicy :execrows
DELETE FROM local_admin_password_policies WHERE device_id = $1;

-- Only explicit requests clear a visible block; the policy actor is
-- re-authorized again before anything is minted.
-- name: SetLocalAdminPolicyDue :exec
UPDATE local_admin_password_policies SET rotate_due_at = sqlc.arg('rotate_due_at'),
blocked_reason = CASE WHEN sqlc.arg('clear_block')::boolean THEN '' ELSE blocked_reason END, updated_at = sqlc.arg('updated_at')
WHERE device_id = sqlc.arg('device_id');

-- name: AdvanceLocalAdminPolicyDue :exec
UPDATE local_admin_password_policies SET rotate_due_at = LEAST(rotate_due_at, sqlc.arg('rotate_due_at')::timestamptz), updated_at = sqlc.arg('updated_at')
WHERE device_id = sqlc.arg('device_id');

-- The request guard never blocks a policy replaced after the failed check.
-- name: BlockLocalAdminPolicy :exec
UPDATE local_admin_password_policies SET blocked_reason = sqlc.arg('blocked_reason'), updated_at = clock_timestamp()
WHERE device_id = sqlc.arg('device_id') AND request_id = sqlc.arg('request_id') AND blocked_reason = '';

-- name: InsertLocalAdminPassword :exec
INSERT INTO local_admin_passwords (action_id, device_id, generation_id, account_name, account_uid, state)
VALUES (sqlc.arg('action_id'), sqlc.arg('device_id'), sqlc.arg('generation_id'), sqlc.arg('account_name'), sqlc.arg('account_uid'), 'escrowed');

-- name: GetCurrentLocalAdminPassword :one
SELECT * FROM local_admin_passwords WHERE device_id = $1 AND state = 'current';

-- name: GetLocalAdminPassword :one
SELECT * FROM local_admin_passwords WHERE action_id = $1;

-- name: LockLocalAdminPassword :one
SELECT * FROM local_admin_passwords WHERE action_id = $1 FOR UPDATE;

-- Only an escrowed row settles; replayed or later results never rewrite history.
-- name: SettleLocalAdminPassword :execrows
UPDATE local_admin_passwords SET state = sqlc.arg('state'), settled_at = sqlc.arg('settled_at')
WHERE action_id = sqlc.arg('action_id') AND state = 'escrowed';

-- name: SupersedeLocalAdminPasswords :exec
UPDATE local_admin_passwords SET state = 'superseded'
WHERE device_id = sqlc.arg('device_id') AND state = 'current' AND action_id <> sqlc.arg('action_id');

-- name: MarkLocalAdminPasswordRevealed :exec
UPDATE local_admin_passwords SET last_revealed_at = sqlc.arg('revealed_at') WHERE action_id = sqlc.arg('action_id');

-- name: ListLocalAdminPasswords :many
SELECT * FROM local_admin_passwords WHERE device_id = $1
ORDER BY escrowed_at DESC, action_id DESC LIMIT 20;
