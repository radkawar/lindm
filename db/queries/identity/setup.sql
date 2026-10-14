-- SPDX-License-Identifier: Apache-2.0

-- name: IssueSetupCode :exec
INSERT INTO first_run_setup (id, code_hash, expires_at)
VALUES (true, sqlc.arg(code_hash), clock_timestamp() + interval '24 hours')
ON CONFLICT (id) DO UPDATE SET code_hash = EXCLUDED.code_hash,
  expires_at = EXCLUDED.expires_at
WHERE first_run_setup.consumed_at IS NULL;

-- name: SetupAvailable :one
SELECT EXISTS (
  SELECT 1 FROM deployment_identity d JOIN first_run_setup s ON s.id = d.id
  WHERE d.owner_principal_id IS NULL AND d.initialized_at IS NULL
    AND s.consumed_at IS NULL AND s.expires_at > clock_timestamp()
);

-- name: FindSetupCode :one
SELECT account_id FROM first_run_setup
WHERE id = true AND code_hash = sqlc.arg(code_hash)
  AND consumed_at IS NULL AND expires_at > clock_timestamp();

-- name: BindSetupAccount :execrows
UPDATE first_run_setup SET account_id = sqlc.arg(account_id)
WHERE id = true AND account_id IS NULL AND code_hash = sqlc.arg(code_hash)
  AND consumed_at IS NULL AND expires_at > clock_timestamp();

-- name: ConsumeSetupCode :one
UPDATE first_run_setup SET consumed_at = clock_timestamp()
WHERE id = true AND account_id = sqlc.arg(account_id) AND code_hash = sqlc.arg(code_hash)
  AND consumed_at IS NULL AND expires_at > clock_timestamp()
RETURNING account_id;

-- name: AdmitSetupAttempt :one
INSERT INTO first_run_attempts (bucket_hash, window_at, attempts)
VALUES (sqlc.arg(bucket_hash), clock_timestamp(), 1)
ON CONFLICT (bucket_hash) DO UPDATE SET
  window_at = CASE WHEN first_run_attempts.window_at <= clock_timestamp() - interval '1 minute'
    THEN clock_timestamp() ELSE first_run_attempts.window_at END,
  attempts = CASE WHEN first_run_attempts.window_at <= clock_timestamp() - interval '1 minute'
    THEN 1 ELSE first_run_attempts.attempts + 1 END
WHERE first_run_attempts.window_at <= clock_timestamp() - interval '1 minute'
  OR first_run_attempts.attempts < sqlc.arg(max_attempts)::integer
RETURNING attempts;

-- name: PurgeSetupAttempts :exec
DELETE FROM first_run_attempts WHERE window_at <= clock_timestamp() - interval '2 minutes';
