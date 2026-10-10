-- name: DeviceInScope :one
SELECT EXISTS (
    SELECT 1 FROM devices d
    WHERE d.id = sqlc.arg('id')::uuid
      AND device_scope_matches(d.id, sqlc.arg('scope_unrestricted')::boolean, sqlc.arg('scopes')::jsonb)
)::boolean;
