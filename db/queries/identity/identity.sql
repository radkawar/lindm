-- name: CountOpenAuthFlows :one
SELECT count(*)::bigint AS open_count
FROM auth_flows
WHERE consumed_at IS NULL AND expires_at > now();

-- name: DeleteStaleAuthFlows :exec
DELETE FROM auth_flows
WHERE expires_at < now() - interval '1 hour';

-- name: PurgeConsumedVerifiers :exec
UPDATE auth_flows
SET code_verifier = ''
WHERE consumed_at IS NOT NULL AND code_verifier <> '';

-- name: InsertAuthFlow :exec
INSERT INTO auth_flows (
  state_hash, nonce_hash, code_verifier, browser_binding_hash, redirect_uri
) VALUES (
  sqlc.arg(state_hash),
  sqlc.arg(nonce_hash),
  sqlc.arg(code_verifier),
  sqlc.arg(browser_binding_hash),
  sqlc.arg(redirect_uri)
);

-- name: ConsumeAuthFlow :one
UPDATE auth_flows
SET consumed_at = now()
WHERE state_hash = sqlc.arg(state_hash)
  AND redirect_uri = sqlc.arg(redirect_uri)
  AND consumed_at IS NULL
  AND expires_at > now()
RETURNING id, nonce_hash, code_verifier, browser_binding_hash;

-- name: ClearAuthFlowVerifier :exec
UPDATE auth_flows
SET code_verifier = ''
WHERE id = sqlc.arg(id);

-- name: UpsertPrincipal :one
INSERT INTO principals (id, issuer, subject, display_name)
VALUES (
  sqlc.arg(id),
  sqlc.arg(issuer),
  sqlc.arg(subject),
  sqlc.arg(display_name)
)
ON CONFLICT (issuer, subject) DO UPDATE
SET display_name = EXCLUDED.display_name
RETURNING id, issuer, subject, display_name, pinned_role, created_at, deactivated_at,
  deactivation_source, directory_enabled, directory_observed_at,
  authorization_version, authorization_role;

-- name: GetPrincipalByID :one
SELECT id, issuer, subject, display_name, pinned_role, created_at, deactivated_at,
  deactivation_source, directory_enabled, directory_observed_at,
  authorization_version, authorization_role
FROM principals
WHERE id = sqlc.arg(id);

-- name: GetPrincipalForUpdate :one
SELECT id, issuer, subject, display_name, pinned_role, created_at, deactivated_at,
  deactivation_source, directory_enabled, directory_observed_at,
  authorization_version, authorization_role
FROM principals
WHERE id = sqlc.arg(id)
FOR UPDATE;

-- name: UpdatePrincipalAuthState :exec
UPDATE principals
SET display_name = sqlc.arg(display_name),
  directory_enabled = sqlc.arg(directory_enabled),
  directory_observed_at = sqlc.arg(directory_observed_at),
  deactivated_at = sqlc.arg(deactivated_at),
  deactivation_source = sqlc.arg(deactivation_source)
WHERE id = sqlc.arg(id);

-- name: GetPrincipalByIssuerSubject :one
SELECT id, issuer, subject, display_name, pinned_role, created_at, deactivated_at,
  deactivation_source, directory_enabled, directory_observed_at,
  authorization_version, authorization_role
FROM principals
WHERE issuer = sqlc.arg(issuer) AND subject = sqlc.arg(subject);


-- name: GetLineageByPrincipalID :one
SELECT principal_id, broker_issuer, broker_subject, upstream_provider, upstream_subject,
  directory_connector, upstream_observed_at, created_at
FROM principal_lineage
WHERE principal_id = sqlc.arg(principal_id);

-- name: GetLineageForUpdate :one
SELECT principal_id, broker_issuer, broker_subject, upstream_provider, upstream_subject,
  directory_connector, upstream_observed_at, created_at
FROM principal_lineage
WHERE principal_id = sqlc.arg(principal_id)
FOR UPDATE;

-- name: InsertLineage :exec
INSERT INTO principal_lineage (
  principal_id, broker_issuer, broker_subject, upstream_provider, upstream_subject,
  directory_connector, upstream_observed_at
) VALUES (
  sqlc.arg(principal_id),
  sqlc.arg(broker_issuer),
  sqlc.arg(broker_subject),
  sqlc.arg(upstream_provider),
  sqlc.arg(upstream_subject),
  sqlc.arg(directory_connector),
  sqlc.arg(upstream_observed_at)
);

-- name: UpdateLineage :exec
UPDATE principal_lineage
SET broker_issuer = sqlc.arg(broker_issuer),
  broker_subject = sqlc.arg(broker_subject),
  upstream_provider = sqlc.arg(upstream_provider),
  upstream_subject = sqlc.arg(upstream_subject),
  directory_connector = sqlc.arg(directory_connector),
  upstream_observed_at = sqlc.arg(upstream_observed_at)
WHERE principal_id = sqlc.arg(principal_id);

-- name: DeletePrincipalGroups :exec
DELETE FROM principal_groups
WHERE principal_id = sqlc.arg(principal_id);

-- name: InsertPrincipalGroup :exec
INSERT INTO principal_groups (principal_id, group_path)
VALUES (sqlc.arg(principal_id), sqlc.arg(group_path));

-- name: ListPrincipalGroupPaths :many
SELECT group_path
FROM principal_groups
WHERE principal_id = sqlc.arg(principal_id)
ORDER BY group_path;

-- name: InsertSession :exec
INSERT INTO sessions (
  token_hash, principal_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at
) VALUES (
  sqlc.arg(token_hash),
  sqlc.arg(principal_id),
  now(),
  now(),
  now() + interval '30 minutes',
  now() + interval '12 hours'
);

-- name: GetSessionByTokenHash :one
SELECT token_hash, principal_id, created_at, last_seen_at, idle_expires_at,
  absolute_expires_at, revoked_at, break_glass, incident_reason
FROM sessions
WHERE token_hash = sqlc.arg(token_hash);

-- name: TouchSession :one
UPDATE sessions
SET last_seen_at = now(),
  idle_expires_at = LEAST(absolute_expires_at, now() + interval '30 minutes')
WHERE token_hash = sqlc.arg(token_hash)
  AND revoked_at IS NULL
  AND idle_expires_at > now()
  AND absolute_expires_at > now()
RETURNING token_hash, principal_id, created_at, last_seen_at, idle_expires_at,
  absolute_expires_at, revoked_at, break_glass, incident_reason;

-- name: RevokeSessionByTokenHash :execrows
UPDATE sessions
SET revoked_at = now()
WHERE token_hash = sqlc.arg(token_hash) AND revoked_at IS NULL;

-- name: RevokePrincipalSessions :execrows
UPDATE sessions
SET revoked_at = now()
WHERE principal_id = sqlc.arg(principal_id) AND revoked_at IS NULL;

-- name: LockDeploymentIdentity :one
SELECT id, deployment_id, owner_principal_id, initialized_at
FROM deployment_identity
WHERE id = true
FOR UPDATE;

-- name: MarkDeploymentInitialized :execrows
UPDATE deployment_identity
SET owner_principal_id = sqlc.arg(owner_principal_id),
  initialized_at = now()
WHERE id = true AND owner_principal_id IS NULL;

-- name: PinOwnerRole :execrows
UPDATE principals
SET pinned_role = 'owner',
  authorization_version = authorization_version + CASE WHEN authorization_role = 'owner' THEN 0 ELSE 1 END,
  authorization_role = 'owner'
WHERE id = sqlc.arg(id) AND pinned_role = '';

-- name: InsertAuditEvent :exec
INSERT INTO audit_events (id, actor_id, action, resource_id, reason)
VALUES (
  sqlc.arg(id),
  sqlc.narg(actor_id),
  sqlc.arg(action),
  sqlc.arg(resource_id),
  sqlc.arg(reason)
);

-- name: SetPrincipalAuthorization :one
UPDATE principals
SET authorization_role = sqlc.arg(authorization_role),
  authorization_version = authorization_version + 1
WHERE id = sqlc.arg(id)
  AND authorization_version = sqlc.arg(expected_version)
  AND authorization_role <> sqlc.arg(authorization_role)
RETURNING authorization_version;

-- name: ReadAuthorizationClock :one
SELECT clock_timestamp()::timestamptz;
