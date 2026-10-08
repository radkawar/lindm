-- name: ReadState :one
SELECT revision, state FROM executor_state WHERE id = 1;

-- name: InitializeState :exec
INSERT INTO executor_state (id, revision, state) VALUES (1, 1, ?);

-- name: ReplaceState :execrows
UPDATE executor_state SET revision = revision + 1, state = ? WHERE id = 1 AND revision = ?;

-- name: ReadExecutionTrust :one
SELECT revision, state FROM execution_trust WHERE id = 1;

-- name: InitializeExecutionTrust :exec
INSERT INTO execution_trust (id, revision, state) VALUES (1, 1, ?);

-- name: ReplaceExecutionTrust :execrows
UPDATE execution_trust SET revision = revision + 1, state = ? WHERE id = 1 AND revision = ?;

-- name: InitializeServiceActionUsage :exec
INSERT INTO service_action_usage (id, record_count, record_bytes) VALUES (1, 0, 0);

-- name: ReadServiceActionUsage :one
SELECT record_count, record_bytes FROM service_action_usage WHERE id = 1;

-- name: ReplaceServiceActionUsage :execrows
UPDATE service_action_usage SET record_count = ?, record_bytes = ? WHERE id = 1;

-- name: ReadServiceAction :one
SELECT * FROM service_actions WHERE action_id = ?;

-- name: NextServiceAction :one
SELECT * FROM service_actions WHERE action_id > ? ORDER BY action_id LIMIT 1;

-- name: NextUnfinishedServiceAction :one
SELECT * FROM service_actions WHERE action_id > ? AND state IN (1, 2, 3) ORDER BY action_id LIMIT 1;

-- name: InsertServiceAction :exec
INSERT INTO service_actions (action_id, deployment_id, device_id, enrollment_generation, unit, resource_sequence, revision, state, record)
VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?);

-- name: ReplaceServiceAction :execrows
UPDATE service_actions SET revision = revision + 1, state = ?, record = ? WHERE action_id = ? AND revision = ?;

-- name: ReadServiceResourceFloor :one
SELECT * FROM service_resource_floors
WHERE deployment_id = ? AND device_id = ? AND enrollment_generation = ? AND unit = ?;

-- name: RaiseServiceResourceFloor :exec
INSERT INTO service_resource_floors (deployment_id, device_id, enrollment_generation, unit, resource_sequence, action_id)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (deployment_id, device_id, enrollment_generation, unit)
DO UPDATE SET resource_sequence = excluded.resource_sequence, action_id = excluded.action_id;

-- name: ServiceActionTotals :one
SELECT count(*) AS record_count,
    CAST(coalesce(sum(CASE WHEN state IN (1, 2, 3) THEN 131072 ELSE length(record) END), 0) AS INTEGER) AS record_bytes
FROM service_actions;

-- name: InvalidServiceResourceFloorCount :one
SELECT count(*) FROM service_resource_floors AS f
LEFT JOIN service_actions AS a ON a.action_id = f.action_id
WHERE a.action_id IS NULL OR a.deployment_id != f.deployment_id OR a.device_id != f.device_id
    OR a.enrollment_generation != f.enrollment_generation OR a.unit != f.unit OR a.resource_sequence != f.resource_sequence;

-- name: ServiceResourceActionCount :one
SELECT count(*) FROM service_actions
WHERE deployment_id = ? AND device_id = ? AND enrollment_generation = ? AND unit = ?;
