-- name: InsertManagedSecret :exec
INSERT INTO managed_secrets (id, purpose, subject_binding_id, display_name, current_version, request_id, created_by)
VALUES (sqlc.arg(id), sqlc.arg(purpose), sqlc.arg(subject_binding_id), sqlc.arg(display_name), 1, sqlc.arg(request_id), sqlc.arg(created_by));

-- name: InsertManagedSecretVersion :exec
INSERT INTO managed_secret_versions (secret_id, version, request_id, binding_document, key_id, wrapped_key, ciphertext, reason, created_by)
VALUES (sqlc.arg(secret_id), sqlc.arg(version), sqlc.arg(request_id), sqlc.arg(binding_document), sqlc.arg(key_id), sqlc.arg(wrapped_key), sqlc.arg(ciphertext), sqlc.arg(reason), sqlc.arg(created_by));

-- name: LockManagedSecret :one
SELECT id, purpose, subject_binding_id, display_name, current_version, request_id, created_by, created_at, updated_at
FROM managed_secrets WHERE id = sqlc.arg(id) AND deleted_at IS NULL FOR UPDATE;

-- name: AdvanceManagedSecretVersion :execrows
UPDATE managed_secrets
SET current_version = sqlc.arg(version)::bigint, updated_at = greatest(clock_timestamp(), updated_at)
WHERE id = sqlc.arg(id) AND current_version = sqlc.arg(version)::bigint - 1;

-- name: GetManagedSecretSummary :one
SELECT s.id, s.purpose, s.subject_binding_id, s.display_name, s.current_version, s.created_by, s.created_at, s.updated_at,
    coalesce(nullif(creator.display_name, ''), account.username, '')::text AS creator_display_name
FROM managed_secrets s
LEFT JOIN principals creator ON creator.id = s.created_by
LEFT JOIN local_accounts account ON account.id = creator.id
WHERE s.id = sqlc.arg(id) AND s.deleted_at IS NULL;

-- name: ListManagedSecrets :many
SELECT s.id, s.purpose, s.subject_binding_id, s.display_name, s.current_version, s.created_by, s.created_at, s.updated_at,
    coalesce(nullif(creator.display_name, ''), account.username, '')::text AS creator_display_name
FROM managed_secrets s
LEFT JOIN principals creator ON creator.id = s.created_by
LEFT JOIN local_accounts account ON account.id = creator.id
WHERE s.deleted_at IS NULL
  AND (NOT sqlc.arg(has_cursor)::boolean OR (s.created_at, s.id) > (sqlc.arg(cursor_created_at)::timestamptz, sqlc.arg(cursor_id)::uuid))
  AND starts_with(lower(s.display_name), lower(sqlc.arg(name_prefix)::text))
ORDER BY s.created_at, s.id
LIMIT sqlc.arg(row_limit);

-- name: ListManagedSecretVersions :many
SELECT v.version, v.created_by, v.created_at, v.reason,
    coalesce(nullif(creator.display_name, ''), account.username, '')::text AS creator_display_name
FROM managed_secret_versions v
LEFT JOIN principals creator ON creator.id = v.created_by
LEFT JOIN local_accounts account ON account.id = creator.id
WHERE v.secret_id = sqlc.arg(secret_id)
ORDER BY v.version DESC
LIMIT 100;

-- name: GetManagedSecretVersion :one
SELECT v.secret_id, v.version, v.request_id, v.binding_document, v.key_id, v.wrapped_key, v.ciphertext,
    s.purpose, s.subject_binding_id
FROM managed_secret_versions v
JOIN managed_secrets s ON s.id = v.secret_id
WHERE v.secret_id = sqlc.arg(secret_id) AND v.version = sqlc.arg(version) AND s.deleted_at IS NULL;

-- name: GetManagedSecretVersionByRequest :one
SELECT v.secret_id, v.version, v.request_id, v.binding_document, v.key_id, v.wrapped_key, v.ciphertext, v.created_by,
    s.purpose, s.display_name, (s.deleted_at IS NOT NULL)::boolean AS deleted
FROM managed_secret_versions v
JOIN managed_secrets s ON s.id = v.secret_id
WHERE v.request_id = sqlc.arg(request_id);

-- name: DeleteManagedSecret :exec
UPDATE managed_secrets SET deleted_at = clock_timestamp(), deleted_by = sqlc.arg(deleted_by),
    updated_at = greatest(clock_timestamp(), updated_at)
WHERE id = sqlc.arg(id) AND deleted_at IS NULL;

-- name: EraseManagedSecretVersions :exec
UPDATE managed_secret_versions SET wrapped_key = '', ciphertext = '' WHERE secret_id = sqlc.arg(secret_id);

-- Secret uses are current references: each profile's head revision and the
-- assignment head of every device that is not revoked. Stored settings are
-- matched by the canonical secret ID text, which resource validation requires
-- of every SecretRef; callers decode each match for the pinned version.

-- name: CountSecretUses :one
WITH profile_uses AS (
    SELECT DISTINCT p.id
    FROM profiles p
    JOIN profile_resources r ON r.revision_id = p.head_revision_id
    WHERE position(sqlc.arg(needle)::bytea IN r.resource_proto) > 0
), device_uses AS (
    SELECT DISTINCT d.id
    FROM devices d
    JOIN resource_assignment_heads h ON h.generation_id = d.current_generation_id
    JOIN resource_assignment_resources r ON r.assignment_id = h.assignment_id
    WHERE d.state <> 'revoked' AND position(sqlc.arg(needle)::bytea IN r.document) > 0
)
SELECT (SELECT count(*) FROM profile_uses)::bigint AS profiles,
    (SELECT count(*) FROM device_uses)::bigint AS devices,
    (SELECT count(*) FROM device_uses u
     WHERE device_scope_matches(u.id, sqlc.arg('scope_unrestricted')::boolean, sqlc.arg('scopes')::jsonb))::bigint AS visible_devices;

-- name: ListSecretProfileUses :many
SELECT p.id AS profile_id, rev.name, rev.revision_number, r.resource_kind, r.canonical_key, r.resource_proto
FROM profiles p
JOIN profile_revisions rev ON rev.id = p.head_revision_id
JOIN profile_resources r ON r.revision_id = rev.id
WHERE position(sqlc.arg(needle)::bytea IN r.resource_proto) > 0
ORDER BY lower(rev.name), p.id, r.resource_kind, r.canonical_key
LIMIT 200;

-- name: ListSecretDeviceUses :many
SELECT d.id AS device_id, d.hostname, r.resource_kind, r.canonical_key, r.document
FROM devices d
JOIN resource_assignment_heads h ON h.generation_id = d.current_generation_id
JOIN resource_assignment_resources r ON r.assignment_id = h.assignment_id
WHERE d.state <> 'revoked' AND position(sqlc.arg(needle)::bytea IN r.document) > 0
  AND device_scope_matches(d.id, sqlc.arg('scope_unrestricted')::boolean, sqlc.arg('scopes')::jsonb)
ORDER BY lower(d.hostname), d.id, r.position
LIMIT 200;
