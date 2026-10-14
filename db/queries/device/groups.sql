-- SPDX-License-Identifier: Apache-2.0

-- name: UpsertDeviceGroup :execrows
INSERT INTO device_groups (id, name) VALUES (sqlc.arg('id'), sqlc.arg('name'))
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name
WHERE NOT sqlc.arg('create_only')::boolean;

-- name: LockDeviceGroup :one
SELECT id, name FROM device_groups WHERE id = sqlc.arg('id') FOR UPDATE;

-- name: LockDeviceGroupMembers :many
SELECT d.id FROM devices d
WHERE d.id = ANY(sqlc.arg('device_ids')::uuid[])
   OR EXISTS (SELECT 1 FROM device_group_memberships m WHERE m.device_id = d.id AND m.group_id = sqlc.arg('group_id')::uuid)
ORDER BY d.id
FOR UPDATE OF d;

-- name: ClearDeviceGroupMembers :exec
DELETE FROM device_group_memberships WHERE group_id = sqlc.arg('group_id');

-- name: InsertDeviceGroupMembers :exec
INSERT INTO device_group_memberships (group_id, device_id)
SELECT sqlc.arg('group_id')::uuid, unnest(sqlc.arg('device_ids')::uuid[]);

-- name: DeleteDeviceGroup :exec
DELETE FROM device_groups WHERE id = sqlc.arg('id');

-- name: ListDeviceGroups :many
SELECT g.id, g.name,
    ARRAY(SELECT m.device_id::text FROM device_group_memberships m WHERE m.group_id = g.id ORDER BY m.device_id)::text[] AS device_ids
FROM device_groups g
WHERE g.id > sqlc.arg('after_id')::uuid
  AND (sqlc.arg('name_search')::text = '' OR strpos(lower(g.name), lower(sqlc.arg('name_search')::text)) > 0)
ORDER BY g.id
LIMIT sqlc.arg('row_limit')::int;

-- name: ListDeviceGroupsByID :many
SELECT g.id, g.name,
    ARRAY(SELECT m.device_id::text FROM device_group_memberships m WHERE m.group_id = g.id ORDER BY m.device_id)::text[] AS device_ids
FROM device_groups g
WHERE g.id = ANY(sqlc.arg('group_ids')::uuid[])
ORDER BY g.id;
