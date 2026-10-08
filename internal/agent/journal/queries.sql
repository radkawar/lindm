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

