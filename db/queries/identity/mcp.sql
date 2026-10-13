-- name: ReadMCPEnabled :one
SELECT enabled FROM mcp_settings WHERE id = true;

-- name: LockMCPEnabled :one
SELECT enabled FROM mcp_settings WHERE id = true FOR SHARE;

-- name: SetMCPEnabled :exec
UPDATE mcp_settings SET enabled = sqlc.arg(enabled) WHERE id = true;

-- name: GetMCPTokenByHash :one
SELECT id, principal_id, token_hash, label, proposals_allowed, created_at, expires_at, revoked_at
FROM mcp_tokens WHERE token_hash = sqlc.arg(token_hash);

-- name: LockMCPTokenByHash :one
SELECT id, principal_id, token_hash, label, proposals_allowed, created_at, expires_at, revoked_at
FROM mcp_tokens WHERE token_hash = sqlc.arg(token_hash) FOR SHARE;

-- name: ListOwnMCPTokens :many
SELECT id, label, proposals_allowed, created_at, expires_at
FROM mcp_tokens
WHERE principal_id = sqlc.arg(principal_id) AND revoked_at IS NULL AND expires_at > clock_timestamp()
ORDER BY created_at, id LIMIT 100;

-- name: CountOwnMCPTokens :one
SELECT count(*)::bigint FROM mcp_tokens
WHERE principal_id = sqlc.arg(principal_id) AND revoked_at IS NULL AND expires_at > clock_timestamp();

-- name: InsertMCPToken :one
INSERT INTO mcp_tokens (id, principal_id, token_hash, label, proposals_allowed, created_at, expires_at)
VALUES (sqlc.arg(id), sqlc.arg(principal_id), sqlc.arg(token_hash), sqlc.arg(label),
  sqlc.arg(proposals_allowed), sqlc.arg(created_at), sqlc.arg(expires_at))
RETURNING id, principal_id, token_hash, label, proposals_allowed, created_at, expires_at, revoked_at;

-- name: RevokeOwnMCPToken :one
UPDATE mcp_tokens SET revoked_at = COALESCE(revoked_at, clock_timestamp())
WHERE id = sqlc.arg(id) AND principal_id = sqlc.arg(principal_id)
RETURNING id, principal_id, token_hash, label, proposals_allowed, created_at, expires_at, revoked_at;

-- name: RevokePrincipalMCPTokens :exec
UPDATE mcp_tokens SET revoked_at = clock_timestamp()
WHERE principal_id = sqlc.arg(principal_id) AND revoked_at IS NULL;

-- name: RevokeRuntimeMCPTokens :exec
-- Runtime policy replacement ends prior credential authority. Unlike the
-- console's recovery-owner session exceptions, tokens have no recovery role.
UPDATE mcp_tokens SET revoked_at = clock_timestamp() WHERE revoked_at IS NULL;
