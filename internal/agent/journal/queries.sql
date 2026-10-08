-- name: ReadState :one
SELECT revision, state FROM executor_state WHERE id = 1;

-- name: InitializeState :exec
INSERT INTO executor_state (id, revision, state) VALUES (1, 1, ?);

-- name: ReplaceState :execrows
UPDATE executor_state SET revision = revision + 1, state = ? WHERE id = 1 AND revision = ?;

