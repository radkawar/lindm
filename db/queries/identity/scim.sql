-- name: LockSCIMConfiguration :exec
SELECT pg_advisory_xact_lock(741916423);

-- name: DisableSCIMConnectors :exec
UPDATE scim_connectors SET enabled = false, credential_hash = NULL WHERE NOT (id = ANY(sqlc.arg(active_ids)::text[]));

-- name: ConfigureSCIMConnector :exec
INSERT INTO scim_connectors(id, config_digest) VALUES ($1, $2)
ON CONFLICT (id) DO UPDATE SET enabled = true, config_digest = EXCLUDED.config_digest,
credential_hash = CASE WHEN scim_connectors.config_digest = EXCLUDED.config_digest THEN scim_connectors.credential_hash ELSE NULL END;

-- name: InsertSCIMCorrelation :exec
INSERT INTO scim_correlations(connector_id, provider_id, issuer, subject) VALUES ($1, $2, $3, $4)
ON CONFLICT (connector_id, provider_id) DO NOTHING;

-- name: GetSCIMCorrelation :one
SELECT * FROM scim_correlations WHERE connector_id = $1 AND provider_id = $2;

-- name: LockSCIMConnector :one
SELECT * FROM scim_connectors WHERE id = $1 FOR UPDATE;

-- name: AuthenticateSCIMConnector :one
SELECT * FROM scim_connectors WHERE credential_hash = $1 AND enabled FOR UPDATE;

-- name: RotateSCIMCredential :exec
UPDATE scim_connectors SET credential_hash = $2 WHERE id = $1;

-- name: InsertSCIMResource :one
INSERT INTO scim_resources(id, connector_id, resource_type, external_id, user_name, principal_id, document)
VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *;

-- name: GetSCIMResource :one
SELECT * FROM scim_resources WHERE connector_id = $1 AND resource_type = $2 AND id = $3 FOR UPDATE;


-- name: GetSCIMResourceByExternalID :one
SELECT * FROM scim_resources WHERE connector_id = $1 AND resource_type = $2 AND external_id = $3 FOR UPDATE;
-- name: CountSCIMResources :one
SELECT count(*) FROM scim_resources WHERE connector_id = $1 AND resource_type = $2 AND NOT deleted
AND (sqlc.arg(filter_attribute)::text = ''
OR (sqlc.arg(filter_attribute)::text = 'userName' AND lower(user_name) = lower(sqlc.arg(filter_value)::text))
OR (sqlc.arg(filter_attribute)::text = 'externalId' AND external_id = sqlc.arg(filter_value)::text));

-- name: ListSCIMResources :many
SELECT * FROM scim_resources WHERE connector_id = $1 AND resource_type = $2 AND NOT deleted
AND (sqlc.arg(filter_attribute)::text = ''
OR (sqlc.arg(filter_attribute)::text = 'userName' AND lower(user_name) = lower(sqlc.arg(filter_value)::text))
OR (sqlc.arg(filter_attribute)::text = 'externalId' AND external_id = sqlc.arg(filter_value)::text))
ORDER BY id LIMIT sqlc.arg(page_limit)::integer OFFSET sqlc.arg(page_offset)::integer;

-- name: UpdateSCIMResource :one
UPDATE scim_resources SET document = $4, user_name = $5, external_id = $6,
version = version + 1, modified_at = clock_timestamp(), deleted = $7
WHERE connector_id = $1 AND resource_type = $2 AND id = $3 RETURNING *;

-- name: ListSCIMMembers :many
SELECT r.id, r.user_name FROM scim_group_members m JOIN scim_resources r ON r.id = m.user_id
WHERE m.group_id = $1 ORDER BY r.id LIMIT 1001;

-- name: ClearSCIMMembers :exec
DELETE FROM scim_group_members WHERE group_id = $1;

-- name: InsertSCIMMember :exec
INSERT INTO scim_group_members(connector_id, group_id, user_id) VALUES ($1, $2, $3);

-- name: RemoveSCIMUserMemberships :exec
WITH removed AS (DELETE FROM scim_group_members WHERE user_id = $1 RETURNING group_id)
UPDATE scim_resources SET version = version + 1, modified_at = clock_timestamp()
WHERE id IN (SELECT group_id FROM removed);

-- name: SetSCIMPrincipalLifecycle :exec
UPDATE principals SET deactivated_at = CASE WHEN sqlc.arg(active)::boolean THEN
CASE WHEN deactivation_source = 'scim' THEN NULL ELSE deactivated_at END ELSE clock_timestamp() END,
deactivation_source = CASE WHEN sqlc.arg(active)::boolean THEN
CASE WHEN deactivation_source = 'scim' THEN '' ELSE deactivation_source END ELSE 'scim' END,
directory_enabled = false, directory_observed_at = NULL, lifecycle_not_before = clock_timestamp(),
authorization_role = '', authorization_digest = '', authorization_version = authorization_version + 1
WHERE id = $1;

-- name: ClearSCIMLineageObservation :exec
UPDATE principal_lineage SET upstream_observed_at = NULL WHERE principal_id = $1;
