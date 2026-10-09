-- name: ReserveProfileRequest :execrows
INSERT INTO service_profile_requests (request_id, actor_id, request_digest, profile_id, revision_id, audit_id)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (request_id) DO NOTHING;

-- name: GetProfileRequest :one
SELECT request_id, actor_id, request_digest, profile_id, revision_id, audit_id
FROM service_profile_requests WHERE request_id = $1;

-- name: CreateProfile :execrows
INSERT INTO service_profiles (id, head_revision_id, created_at)
VALUES ($1, $2, clock_timestamp())
ON CONFLICT (id) DO NOTHING;

-- name: LockProfile :one
SELECT id, head_revision_id, created_at FROM service_profiles WHERE id = $1 FOR UPDATE;

-- name: GetProfileRevision :one
SELECT id, profile_id, revision_number, name, description, resource_count,
       spec_digest, actor_id, published_at
FROM service_profile_revisions
WHERE profile_id = sqlc.arg(profile_id)
  AND id = COALESCE(sqlc.narg(revision_id)::uuid,
      (SELECT head_revision_id FROM service_profiles WHERE id = sqlc.arg(profile_id)));

-- name: ListProfileHeads :many
SELECT r.id, r.profile_id, r.revision_number, r.name, r.description,
       r.resource_count, r.spec_digest, r.actor_id, r.published_at
FROM service_profiles p JOIN service_profile_revisions r ON r.id = p.head_revision_id AND r.profile_id = p.id
WHERE p.id > sqlc.arg(after_id)::uuid
ORDER BY p.id LIMIT sqlc.arg(page_limit)::integer;

-- name: InsertProfileRevision :exec
INSERT INTO service_profile_revisions (id, profile_id, revision_number, name, description,
    resource_count, spec_digest, actor_id, published_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: InsertProfileResources :copyfrom
INSERT INTO service_profile_resources (revision_id, resource_id, unit_name, runtime_state, enablement_state)
VALUES ($1, $2, $3, $4, $5);

-- name: InsertProfileDependencies :copyfrom
INSERT INTO service_profile_dependencies (revision_id, resource_id, dependency_id)
VALUES ($1, $2, $3);

-- name: ListProfileResources :many
SELECT resource_id, unit_name, runtime_state, enablement_state
FROM service_profile_resources WHERE revision_id = $1 ORDER BY resource_id LIMIT 65;

-- name: ListProfileDependencies :many
SELECT resource_id, dependency_id FROM service_profile_dependencies
WHERE revision_id = $1 ORDER BY resource_id, dependency_id LIMIT 4033;

-- name: AdvanceProfileHead :execrows
UPDATE service_profiles SET head_revision_id = sqlc.arg(next_id)
WHERE id = sqlc.arg(profile_id) AND head_revision_id = sqlc.arg(expected_id);

-- name: ProfileClock :one
SELECT clock_timestamp()::timestamptz AS now;

-- name: InsertProfileAudit :exec
INSERT INTO audit_events (id, occurred_at, actor_id, action, resource_id, reason)
VALUES ($1, $2, $3, 'service_profile.publish', $4, $5);
