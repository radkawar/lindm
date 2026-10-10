-- name: GetDeploymentID :one
SELECT deployment_id FROM deployment_identity WHERE id = true;

-- name: GetLocalAccount :one
SELECT * FROM local_accounts WHERE id = sqlc.arg(id);

-- name: GetLocalAccountByUsername :one
SELECT * FROM local_accounts WHERE username = sqlc.arg(username);

-- name: ListLocalAccounts :many
SELECT id, username, role, enabled, break_glass, scope_binding,
  EXISTS (SELECT 1 FROM local_credentials c WHERE c.account_id = a.id) AS enrolled
FROM local_accounts a ORDER BY username LIMIT 1000;

-- name: InsertLocalAccount :exec
INSERT INTO local_accounts (id, username, role, break_glass, scope_binding)
VALUES (sqlc.arg(id), sqlc.arg(username), sqlc.arg(role), sqlc.arg(break_glass), sqlc.arg(scope_binding));

-- name: UpdateLocalAccount :exec
UPDATE local_accounts SET role = sqlc.arg(role), enabled = sqlc.arg(enabled),
  break_glass = sqlc.arg(break_glass), scope_binding = sqlc.arg(scope_binding) WHERE id = sqlc.arg(id);

-- name: BumpLocalAuthorization :exec
UPDATE principals SET authorization_version = authorization_version + 1,
  authorization_role = sqlc.arg(authorization_role), authorization_digest = sqlc.arg(authorization_digest)
WHERE id = sqlc.arg(id);

-- name: SetLocalPassword :exec
UPDATE local_accounts SET password_hash = sqlc.arg(password_hash),
  failed_attempts = 0, locked_until = NULL WHERE id = sqlc.arg(id);

-- name: RecordLocalFailure :exec
UPDATE local_accounts SET
  failed_attempts = CASE WHEN locked_until <= clock_timestamp() THEN 1 ELSE LEAST(5, failed_attempts + 1) END,
  locked_until = CASE
    WHEN locked_until <= clock_timestamp() THEN NULL
    WHEN failed_attempts >= 4 THEN clock_timestamp() + interval '15 minutes'
    ELSE locked_until
  END
WHERE id = sqlc.arg(id) AND (locked_until IS NULL OR locked_until <= clock_timestamp());

-- name: ClearLocalFailures :exec
UPDATE local_accounts SET failed_attempts = 0, locked_until = NULL WHERE id = sqlc.arg(id);

-- name: ListLocalCredentials :many
SELECT credential_id, credential_json FROM local_credentials WHERE account_id = sqlc.arg(account_id) ORDER BY credential_id;

-- name: InsertLocalCredential :exec
INSERT INTO local_credentials (credential_id, account_id, credential_json)
VALUES (sqlc.arg(credential_id), sqlc.arg(account_id), sqlc.arg(credential_json));

-- name: UpdateLocalCredential :exec
UPDATE local_credentials SET credential_json = sqlc.arg(credential_json)
WHERE credential_id = sqlc.arg(credential_id) AND account_id = sqlc.arg(account_id);

-- name: DeleteLocalCredentials :exec
DELETE FROM local_credentials WHERE account_id = sqlc.arg(account_id);

-- name: DeleteLocalEnrollments :exec
DELETE FROM local_enrollments WHERE account_id = sqlc.arg(account_id);

-- name: IssueLocalEnrollment :one
INSERT INTO local_enrollments (secret_hash, account_id)
VALUES (sqlc.arg(secret_hash), sqlc.arg(account_id)) RETURNING expires_at;

-- name: FindLocalEnrollment :one
SELECT account_id FROM local_enrollments WHERE secret_hash = sqlc.arg(secret_hash) AND expires_at > clock_timestamp();

-- name: ConsumeLocalEnrollment :one
DELETE FROM local_enrollments WHERE secret_hash = sqlc.arg(secret_hash) AND expires_at > clock_timestamp()
RETURNING account_id;

-- name: DeleteLocalCeremonies :exec
DELETE FROM local_ceremonies WHERE account_id = sqlc.arg(account_id);

-- name: PurgeLocalCeremonies :exec
DELETE FROM local_ceremonies WHERE expires_at <= now();

-- name: InsertLocalCeremony :exec
INSERT INTO local_ceremonies (token_hash, account_id, kind, challenge_hash, session_data, password_hash, incident_reason, authorization_version)
VALUES (sqlc.arg(token_hash), sqlc.arg(account_id), sqlc.arg(kind), sqlc.arg(challenge_hash), sqlc.arg(session_data), sqlc.arg(password_hash), sqlc.arg(incident_reason), sqlc.arg(authorization_version));

-- name: ConsumeLocalCeremony :one
DELETE FROM local_ceremonies WHERE token_hash = sqlc.arg(token_hash)
  AND kind = sqlc.arg(kind) AND expires_at > now() RETURNING *;

-- name: InsertLocalSession :exec
INSERT INTO sessions (token_hash, principal_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at, break_glass, incident_reason)
VALUES (sqlc.arg(token_hash), sqlc.arg(principal_id), now(), now(),
  LEAST(now() + interval '30 minutes', sqlc.arg(expires_at)::timestamptz),
  LEAST(sqlc.arg(expires_at)::timestamptz,
    now() + CASE WHEN sqlc.arg(break_glass)::boolean THEN interval '1 hour' ELSE interval '12 hours' END),
  sqlc.arg(break_glass), sqlc.arg(incident_reason));

-- name: ActiveBreakGlassDeadline :one
SELECT LEAST(idle_expires_at, absolute_expires_at)::timestamptz AS deadline
FROM sessions WHERE principal_id = sqlc.arg(principal_id) AND break_glass
  AND revoked_at IS NULL AND idle_expires_at > clock_timestamp()
  AND absolute_expires_at > clock_timestamp()
ORDER BY absolute_expires_at DESC LIMIT 1;

-- name: ListBreakGlassPrincipals :many
SELECT DISTINCT principal_id FROM sessions WHERE break_glass AND revoked_at IS NULL ORDER BY principal_id;

-- name: RevokeBreakGlassSessions :execrows
UPDATE sessions SET revoked_at = now()
WHERE principal_id = sqlc.arg(principal_id) AND break_glass AND revoked_at IS NULL;

-- name: HasEnrolledBreakGlassOwner :one
SELECT EXISTS (
  SELECT 1 FROM local_accounts a
  JOIN principals p ON p.id = a.id
  WHERE a.enabled AND a.role = 'owner' AND a.break_glass AND a.password_hash <> ''
    AND p.issuer = sqlc.arg(local_issuer) AND p.subject = a.id::text
    AND EXISTS (SELECT 1 FROM local_credentials c WHERE c.account_id = a.id)
);
