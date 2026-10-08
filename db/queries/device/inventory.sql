-- name: DeleteDevicePackages :exec
DELETE FROM device_packages
WHERE device_id = sqlc.arg('device_id');

-- name: InsertDevicePackage :exec
INSERT INTO device_packages (
    device_id,
    position,
    name,
    version,
    architecture,
    manager
) VALUES (
    sqlc.arg('device_id'),
    sqlc.arg('position'),
    sqlc.arg('name'),
    sqlc.arg('version'),
    sqlc.arg('architecture'),
    sqlc.arg('manager')
);
