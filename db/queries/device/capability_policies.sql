-- SPDX-License-Identifier: Apache-2.0

-- Scope kinds: 1 deployment, 2 static group, 3 dynamic group. group_id is the
-- nil UUID at deployment scope.

-- name: ListCapabilityPolicies :many
SELECT p.scope_kind,
    coalesce(p.static_group_id, p.dynamic_group_id, '00000000-0000-0000-0000-000000000000')::uuid AS group_id,
    p.capabilities, p.sysctl_keys, p.firewall, p.revision, p.updated_at,
    coalesce(sg.name, '')::text AS static_group_name,
    coalesce(dg.definition, ''::bytea)::bytea AS dynamic_group_definition,
    coalesce(nullif(actor.display_name, ''), account.username, '')::text AS updated_by
FROM capability_policies p
LEFT JOIN device_groups sg ON sg.id = p.static_group_id
LEFT JOIN dynamic_target_groups dg ON dg.id = p.dynamic_group_id
LEFT JOIN principals actor ON actor.id = p.updated_by
LEFT JOIN local_accounts account ON account.id = p.updated_by
ORDER BY p.scope_kind, group_id
LIMIT 101;

-- Every policy mutation holds the deployment row first, serializing scope
-- revisions, the group-policy ceiling and the firewall-settings invariant.
-- name: LockDeploymentCapabilityPolicy :one
SELECT capabilities, sysctl_keys, firewall, revision
FROM capability_policies WHERE scope_kind = 1 FOR UPDATE;

-- name: GetScopeCapabilityPolicy :one
SELECT capabilities, sysctl_keys, firewall, revision
FROM capability_policies
WHERE scope_kind = sqlc.arg(scope_kind)
  AND coalesce(static_group_id, dynamic_group_id, '00000000-0000-0000-0000-000000000000') = sqlc.arg(group_id)::uuid;

-- name: NextCapabilityPolicyRevision :one
SELECT nextval('capability_policy_revisions')::bigint AS revision;

-- name: UpdateCapabilityPolicy :execrows
UPDATE capability_policies
SET capabilities = sqlc.arg(capabilities), sysctl_keys = sqlc.arg(sysctl_keys), firewall = sqlc.arg(firewall),
    revision = sqlc.arg(revision), updated_at = sqlc.arg(updated_at), updated_by = sqlc.arg(updated_by)
WHERE scope_kind = sqlc.arg(scope_kind)
  AND coalesce(static_group_id, dynamic_group_id, '00000000-0000-0000-0000-000000000000') = sqlc.arg(group_id)::uuid
  AND revision = sqlc.arg(expected_revision);

-- name: InsertGroupCapabilityPolicy :exec
INSERT INTO capability_policies (scope_kind, static_group_id, dynamic_group_id, capabilities, sysctl_keys, revision, updated_at, updated_by)
VALUES (
    sqlc.arg(scope_kind),
    sqlc.narg(static_group_id),
    sqlc.narg(dynamic_group_id),
    sqlc.arg(capabilities),
    sqlc.arg(sysctl_keys),
    sqlc.arg(revision),
    sqlc.arg(updated_at),
    sqlc.arg(updated_by)
);

-- name: DeleteGroupCapabilityPolicy :execrows
DELETE FROM capability_policies
WHERE scope_kind = sqlc.arg(scope_kind) AND scope_kind <> 1
  AND coalesce(static_group_id, dynamic_group_id) = sqlc.arg(group_id)::uuid
  AND revision = sqlc.arg(expected_revision);

-- name: CountGroupCapabilityPolicies :one
SELECT count(*)::bigint FROM capability_policies WHERE scope_kind <> 1;

-- name: GroupCapabilityPoliciesGrant :one
SELECT EXISTS (
    SELECT 1 FROM capability_policies WHERE scope_kind <> 1 AND sqlc.arg(capability)::smallint = ANY(capabilities)
)::boolean;

-- name: LockCapabilityDynamicGroup :one
SELECT id FROM dynamic_target_groups WHERE id = sqlc.arg(id) FOR SHARE;

-- name: GetCapabilityPolicyRequest :one
SELECT digest, response FROM capability_policy_requests
WHERE actor_id = sqlc.arg(actor_id) AND request_id = sqlc.arg(request_id);

-- name: InsertCapabilityPolicyRequest :exec
INSERT INTO capability_policy_requests (actor_id, request_id, digest, response, created_at)
VALUES (sqlc.arg(actor_id), sqlc.arg(request_id), sqlc.arg(digest), sqlc.arg(response), sqlc.arg(created_at));

-- Candidate policies for one device: the deployment policy, static group
-- policies whose group contains it, and every dynamic group policy (membership
-- is evaluated by targeting). Bounded by the 100 group-policy ceiling.
-- name: ListDeviceCapabilityPolicyCandidates :many
SELECT p.scope_kind,
    coalesce(p.static_group_id, p.dynamic_group_id, '00000000-0000-0000-0000-000000000000')::uuid AS group_id,
    p.capabilities, p.sysctl_keys, p.firewall
FROM capability_policies p
WHERE p.scope_kind IN (1, 3)
   OR EXISTS (
       SELECT 1 FROM device_group_memberships m
       WHERE m.group_id = p.static_group_id AND m.device_id = sqlc.arg(device_id)
   )
ORDER BY p.scope_kind, group_id
LIMIT 101;

-- name: LatestDeviceCapabilityPolicy :one
SELECT version, content_sha256, envelope, issued_at
FROM device_capability_policies
WHERE device_id = sqlc.arg(device_id) AND generation_id = sqlc.arg(generation_id)
ORDER BY version DESC
LIMIT 1;

-- name: InsertDeviceCapabilityPolicy :exec
INSERT INTO device_capability_policies (device_id, generation_id, version, content_sha256, envelope, issued_at)
VALUES (sqlc.arg(device_id), sqlc.arg(generation_id), sqlc.arg(version), sqlc.arg(content_sha256), sqlc.arg(envelope), sqlc.arg(issued_at));

-- Superseded envelopes are never served again; retain a short history only.
-- name: PruneDeviceCapabilityPolicies :exec
DELETE FROM device_capability_policies
WHERE device_id = sqlc.arg(device_id) AND generation_id = sqlc.arg(generation_id)
  AND version <= sqlc.arg(latest)::bigint - 16;

-- Rows and releases the executor refused because a capability was not enabled
-- are dispatched again once the device's grant or its reported capability
-- status changed. Reports the number of assignment rows released.
-- name: ReleaseCapabilityHolds :execrows
WITH releases AS (
    UPDATE resource_releases
    SET state = 'pending', reason = ''
    WHERE generation_id = sqlc.arg(generation_id)
      AND state = 'release_conflict'
      AND reason LIKE 'capability\_%'
    RETURNING id
)
UPDATE resource_assignment_resources r
SET disposition = 1, reason = ''
FROM resource_assignment_heads h
WHERE h.generation_id = sqlc.arg(generation_id)
  AND r.assignment_id = h.assignment_id
  AND r.disposition = 5
  AND r.reason LIKE 'capability\_%';

-- Rows and releases the executor refused for device-local tool or package
-- state (an outdated or missing native tool, a unit no package installed, a
-- preinstalled package) are dispatched again once the device commits a
-- package snapshot whose content differs from the one it replaces. The agent
-- encodes batches deterministically (sorted packages, deterministic protobuf),
-- so equal batch digests mean equal packages and an unchanged periodic
-- snapshot releases nothing; the first snapshot of a generation always
-- releases. Reports the number of assignment rows released.
-- name: ReleasePackageStateHolds :execrows
WITH changed AS (
    SELECT sqlc.narg(previous_snapshot_id)::uuid IS NULL OR EXISTS (
        (SELECT batch_index, digest FROM snapshot_batches WHERE snapshot_id = sqlc.narg(previous_snapshot_id)::uuid
         EXCEPT
         SELECT batch_index, digest FROM snapshot_batches WHERE snapshot_id = sqlc.arg(snapshot_id)::uuid)
        UNION ALL
        (SELECT batch_index, digest FROM snapshot_batches WHERE snapshot_id = sqlc.arg(snapshot_id)::uuid
         EXCEPT
         SELECT batch_index, digest FROM snapshot_batches WHERE snapshot_id = sqlc.narg(previous_snapshot_id)::uuid)
    ) AS content_changed
), releases AS (
    UPDATE resource_releases
    SET state = 'pending', reason = ''
    WHERE generation_id = sqlc.arg(generation_id)
      AND state = 'release_conflict'
      AND reason IN ('native_tool_outdated', 'native_tool_missing', 'unit_not_installed', 'existing_package_unverified', 'existing_package')
      AND (SELECT content_changed FROM changed)
    RETURNING id
)
UPDATE resource_assignment_resources r
SET disposition = 1, reason = ''
FROM resource_assignment_heads h
WHERE h.generation_id = sqlc.arg(generation_id)
  AND r.assignment_id = h.assignment_id
  AND r.disposition IN (5, 6)
  AND r.reason IN ('native_tool_outdated', 'native_tool_missing', 'unit_not_installed', 'existing_package_unverified', 'existing_package')
  AND (SELECT content_changed FROM changed);
