-- name: GetAgentUpdateReport :one
SELECT * FROM device_agent_update_reports WHERE generation_id = sqlc.arg('generation_id');

-- name: PutAgentUpdateReport :exec
INSERT INTO device_agent_update_reports (generation_id, session_epoch, status, event_digest, received_at)
VALUES (sqlc.arg('generation_id'), sqlc.arg('session_epoch'), sqlc.arg('status'), sqlc.arg('event_digest'), sqlc.arg('received_at'))
ON CONFLICT (generation_id) DO UPDATE SET session_epoch = EXCLUDED.session_epoch,
status = EXCLUDED.status, event_digest = EXCLUDED.event_digest, received_at = EXCLUDED.received_at;

-- name: InsertAgentUpdateEvent :exec
INSERT INTO device_agent_update_events (id, generation_id, session_epoch, status, received_at)
VALUES (sqlc.arg('id'), sqlc.arg('generation_id'), sqlc.arg('session_epoch'), sqlc.arg('status'), sqlc.arg('received_at'));
