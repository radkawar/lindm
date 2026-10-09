-- name: GetAuthority :one
SELECT * FROM execution_authority WHERE id = true;

-- name: LockAuthority :one
SELECT * FROM execution_authority WHERE id = true FOR UPDATE;

-- name: ReadClock :one
SELECT clock_timestamp()::timestamptz;

-- name: GetHistorySize :one
SELECT
    (SELECT count(*) FROM execution_authority_roots)::bigint AS root_count,
    (SELECT count(*) FROM execution_authority_updates)::bigint AS update_count,
    (SELECT count(*) FROM audit_events WHERE action = 'execution_authority.initialize')::bigint AS initialization_audits,
    (SELECT count(*) FROM audit_events WHERE action = 'execution_authority.update')::bigint AS update_audits,
    ((SELECT COALESCE(sum(octet_length(root_document) + octet_length(transition_document)), 0) FROM execution_authority_roots)
      + (SELECT COALESCE(sum(octet_length(request_document) + octet_length(receipt_document)), 0) FROM execution_authority_updates)
      + (SELECT octet_length(initial_root_json) + octet_length(initial_bootstrap_envelope) FROM execution_authority WHERE id = true))::bigint AS retained_bytes;
-- name: GetRoot :one
SELECT * FROM execution_authority_roots WHERE root_version = sqlc.arg('root_version');

-- name: ListRoots :many
SELECT * FROM execution_authority_roots
WHERE position <= sqlc.arg('last_position')
ORDER BY position;

-- name: ListRootRange :many
SELECT * FROM execution_authority_roots
WHERE position > sqlc.arg('first_position') AND position <= sqlc.arg('last_position')
ORDER BY position;

-- name: GetUpdate :one
SELECT * FROM execution_authority_updates WHERE request_digest = sqlc.arg('request_digest');

-- name: GetLatestUpdate :one
SELECT * FROM execution_authority_updates WHERE revision = sqlc.arg('revision');

-- name: SetAuthority :exec
UPDATE execution_authority SET
    deployment_id = sqlc.narg('deployment_id'),
    trust_domain_digest = sqlc.arg('trust_domain_digest'),
    root_document = sqlc.arg('root_document'),
    delegation_envelope = sqlc.arg('delegation_envelope'),
    accepted_at = sqlc.arg('accepted_at'),
    revision = sqlc.arg('revision'),
    root_count = sqlc.arg('root_count'),
    update_count = sqlc.arg('update_count'),
    retained_bytes = sqlc.arg('retained_bytes')
WHERE id = true;

-- name: InsertRoot :exec
INSERT INTO execution_authority_roots (
    position, root_version, root_digest, root_document, transition_document, accepted_at
) VALUES (
    sqlc.arg('position'), sqlc.arg('root_version'), sqlc.arg('root_digest'),
    sqlc.arg('root_document'), sqlc.arg('transition_document'), sqlc.arg('accepted_at')
);

-- name: InsertUpdate :exec
INSERT INTO execution_authority_updates (
    request_digest, request_document, receipt_document, revision, accepted_at, audit_id
) VALUES (
    sqlc.arg('request_digest'), sqlc.arg('request_document'), sqlc.arg('receipt_document'),
    sqlc.arg('revision'), sqlc.arg('accepted_at'), sqlc.arg('audit_id')
);

-- name: SetInitialBootstrap :exec
UPDATE execution_authority SET
    initial_root_json = sqlc.arg('initial_root_json'),
    initial_bootstrap_envelope = sqlc.arg('initial_bootstrap_envelope'),
    initialized_at = sqlc.arg('initialized_at'),
    deployment_id = sqlc.narg('deployment_id'),
    trust_domain_digest = sqlc.arg('trust_domain_digest'),
    root_document = sqlc.arg('root_document'),
    accepted_at = sqlc.arg('initialized_at'),
    revision = 1,
    root_count = 1,
    retained_bytes = sqlc.arg('retained_bytes')
WHERE id = true;
-- name: InsertAudit :exec

INSERT INTO audit_events (id, occurred_at, actor_id, action, resource_id, reason)
VALUES (
    sqlc.arg('id'), sqlc.arg('occurred_at'), sqlc.narg('actor_id'),
    sqlc.arg('action'), sqlc.arg('resource_id'), sqlc.arg('reason')
);
