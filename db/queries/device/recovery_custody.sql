-- SPDX-License-Identifier: Apache-2.0

-- name: IsRecoveryCustodyOwner :one
-- The deployment owner is immutable after initialization; authorization already
-- holds the principal/policy fences. No reverse deployment-row lock is introduced.
SELECT EXISTS (
  SELECT 1 FROM deployment_identity d
  JOIN principals p ON p.id = d.owner_principal_id
  WHERE d.id = true AND d.initialized_at IS NOT NULL
    AND p.id = sqlc.arg(actor_id) AND p.pinned_role = 'owner'
    AND p.deactivated_at IS NULL AND NOT p.service_account
);

-- name: GetRecoveryCustodyConfirmation :one
SELECT confirmed_at FROM recovery_key_custody_confirmations
WHERE deployment_id = sqlc.arg(deployment_id) AND confirmation_digest = sqlc.arg(confirmation_digest);

-- name: RecordRecoveryCustodyConfirmation :execrows
INSERT INTO recovery_key_custody_confirmations (deployment_id, confirmation_digest, owner_principal_id)
VALUES (sqlc.arg(deployment_id), sqlc.arg(confirmation_digest), sqlc.arg(owner_principal_id))
ON CONFLICT (deployment_id, confirmation_digest) DO NOTHING;
