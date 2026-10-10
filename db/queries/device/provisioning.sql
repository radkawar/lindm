-- name: InsertProvisioningToken :exec
INSERT INTO provisioning_tokens (id, token_hash, created_by, authorization_version, created_at, expires_at, max_uses, approval_required, assignment, reason)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10);

-- name: GetProvisioningTokenByHash :one
SELECT * FROM provisioning_tokens WHERE token_hash = $1;

-- name: GetProvisioningToken :one
SELECT * FROM provisioning_tokens WHERE id = $1;

-- name: LockProvisioningToken :one
SELECT * FROM provisioning_tokens WHERE id = $1 FOR UPDATE;

-- name: ListProvisioningTokens :many
SELECT t.id, t.created_by, t.created_at, t.expires_at, t.max_uses,
    t.used_count, t.approval_required, t.assignment, t.reason, t.revoked_at,
    coalesce(nullif(creator.display_name, ''), account.username, '')::text AS creator_display_name
FROM provisioning_tokens t
LEFT JOIN principals creator ON creator.id = t.created_by
LEFT JOIN local_accounts account ON account.id = creator.id
WHERE t.id > sqlc.arg(after_id)::uuid ORDER BY t.id LIMIT sqlc.arg(row_limit);

-- name: ConsumeProvisioningToken :execrows
UPDATE provisioning_tokens SET used_count = used_count + 1
WHERE id = $1 AND used_count < max_uses AND revoked_at IS NULL AND expires_at > clock_timestamp();

-- name: RevokeProvisioningToken :exec
UPDATE provisioning_tokens SET revoked_at = $2, revoked_by = $3, revoke_reason = $4
WHERE id = $1 AND revoked_at IS NULL;

-- name: InsertProvisioningEnrollment :exec
INSERT INTO provisioning_enrollments (transaction_id,token_id,installation_id,device_id,generation_id,csr_pem,csr_sha256,state,approval_id,certificate_id,created_at,expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12);

-- name: GetProvisioningEnrollment :one
SELECT * FROM provisioning_enrollments WHERE transaction_id = $1;

-- name: LockProvisioningEnrollment :one
SELECT * FROM provisioning_enrollments WHERE transaction_id = $1 FOR UPDATE;

-- name: CompleteProvisioningEnrollment :execrows
UPDATE provisioning_enrollments SET state = 'ready', certificate_id = $2
WHERE transaction_id = $1 AND state = 'pending_approval';

-- name: ListPendingProvisioningEnrollments :many
SELECT * FROM provisioning_enrollments WHERE transaction_id > sqlc.arg(after_id) AND state = 'pending_approval'
ORDER BY transaction_id LIMIT sqlc.arg(row_limit);

-- name: RevokePendingProvisioningEnrollments :exec
UPDATE provisioning_enrollments SET state = 'revoked'
WHERE token_id = $1 AND state = 'pending_approval';

-- name: ProvisioningProfileIdentity :one
SELECT profile_id FROM profile_revisions WHERE id = $1;

-- name: AddProvisioningGroupMembership :exec
INSERT INTO device_group_memberships (group_id, device_id) VALUES ($1,$2);

-- name: ProvisioningGroupExists :one
SELECT EXISTS(SELECT 1 FROM device_groups WHERE id = $1);

-- name: GetProvisioningEnrollmentForDevice :one
SELECT * FROM provisioning_enrollments WHERE device_id = $1;

-- name: ProvisioningApprovalState :one
SELECT state, expires_at FROM approval_requests WHERE id = $1;
