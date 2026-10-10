-- name: LockReleaseControl :exec
SELECT id FROM release_control_lock WHERE id = true FOR UPDATE;

-- name: ListReleasedAgentSeries :many
SELECT * FROM released_agent_series ORDER BY major DESC, minor DESC LIMIT 1024;

-- name: PutReleasedAgentSeries :exec
INSERT INTO released_agent_series (major, minor, released_at, support_until, minimum_protocol, maximum_protocol)
VALUES (sqlc.arg('major'), sqlc.arg('minor'), sqlc.arg('released_at'), sqlc.arg('support_until'), sqlc.arg('minimum_protocol'), sqlc.arg('maximum_protocol'))
ON CONFLICT (major, minor) DO UPDATE SET support_until = EXCLUDED.support_until;

-- name: ExtendReleasedAgentSeriesNotice :exec
UPDATE released_agent_series SET support_until = GREATEST(support_until, sqlc.arg('support_until'))
WHERE (major, minor) IN (SELECT major, minor FROM released_agent_series ORDER BY major DESC, minor DESC LIMIT 3);

-- name: PutDeviceReleaseReport :exec
INSERT INTO device_release_reports (generation_id, session_epoch, agent_release, protocol_version, reported_at)
VALUES (sqlc.arg('generation_id'), sqlc.arg('session_epoch'), sqlc.arg('agent_release'), sqlc.arg('protocol_version'), sqlc.arg('reported_at'))
ON CONFLICT (generation_id) DO UPDATE SET session_epoch = EXCLUDED.session_epoch, agent_release = EXCLUDED.agent_release,
protocol_version = EXCLUDED.protocol_version, reported_at = EXCLUDED.reported_at;

-- name: GetDeviceReleaseReport :one
SELECT * FROM device_release_reports WHERE generation_id = sqlc.arg('generation_id');

-- name: InsertReleaseRollout :exec
INSERT INTO release_rollout_requests (request_id, actor_id, request_digest, ring, expected_generation, paused, eligible_percentage, reason)
VALUES (sqlc.arg('request_id'), sqlc.arg('actor_id'), sqlc.arg('request_digest'), sqlc.arg('ring'), sqlc.arg('expected_generation'), sqlc.arg('paused'), sqlc.arg('eligible_percentage'), sqlc.arg('reason'));

-- name: GetReleaseRollout :one
SELECT * FROM release_rollout_requests WHERE request_id = sqlc.arg('request_id');

-- name: GetPendingReleaseRollout :one
SELECT request_id FROM release_rollout_requests WHERE ring = sqlc.arg('ring') AND published_channel IS NULL;

-- name: CompleteReleaseRollout :exec
UPDATE release_rollout_requests SET published_channel = sqlc.arg('published_channel') WHERE request_id = sqlc.arg('request_id') AND published_channel IS NULL;
