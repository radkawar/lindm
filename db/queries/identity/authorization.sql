-- SPDX-License-Identifier: Apache-2.0

-- name: ReadRuntimeAuthorization :one
SELECT digest, definition, revision, updated_at FROM authorization_policy WHERE id = true;

-- name: LockRuntimeAuthorizationUpdate :one
SELECT digest, definition, revision, updated_at FROM authorization_policy WHERE id = true FOR UPDATE;

-- name: SetRuntimeAuthorization :one
UPDATE authorization_policy
SET digest = sqlc.arg(digest), definition = sqlc.arg(definition),
    revision = revision + 1, updated_at = clock_timestamp()
WHERE id = true AND revision = sqlc.arg(expected_revision)
RETURNING digest, definition, revision, updated_at;

-- name: ReadAuthorizationRequest :one
SELECT request_digest, response FROM authorization_requests
WHERE actor_id = sqlc.arg(actor_id) AND request_id = sqlc.arg(request_id);

-- name: InsertAuthorizationRequest :exec
INSERT INTO authorization_requests (actor_id, request_id, request_digest, response)
VALUES (sqlc.arg(actor_id), sqlc.arg(request_id), sqlc.arg(request_digest), sqlc.arg(response));

-- name: FenceRuntimeAuthorizations :exec
UPDATE principals SET authorization_version = authorization_version + 1,
  lifecycle_not_before = clock_timestamp(), directory_observed_at = NULL;

-- name: InvalidateRuntimeObservations :exec
UPDATE principal_lineage SET upstream_observed_at = NULL;

-- name: RevokeRuntimeSessions :execrows
-- Unrestricted built-in local owners and the pinned deployment owner retain
-- recovery access. Every other session must authenticate under the new policy.
UPDATE sessions SET revoked_at = now()
WHERE revoked_at IS NULL AND principal_id IN (
  SELECT p.id FROM principals p LEFT JOIN local_accounts a ON a.id = p.id
  WHERE p.pinned_role <> 'owner'
    AND NOT COALESCE(a.role = 'owner' AND a.enabled AND COALESCE(a.scope_binding->'scopes', '[]'::jsonb) = '[]'::jsonb, false)
);
