-- name: LockCLIAdmission :exec
SELECT pg_advisory_xact_lock(812494232);

-- name: DeleteStaleCLIRequests :exec
DELETE FROM cli_auth_requests WHERE expires_at <= now();

-- name: DeleteStaleCLICodes :exec
DELETE FROM cli_auth_codes WHERE expires_at <= now();

-- name: CountCLIRequests :one
SELECT count(*) FROM cli_auth_requests;

-- name: CountCLICodes :one
SELECT count(*) FROM cli_auth_codes;

-- name: InsertCLIRequest :exec
INSERT INTO cli_auth_requests(binding_hash, redirect_uri, code_challenge, state)
VALUES ($1, $2, $3, $4);

-- name: GetCLIRequest :one
SELECT * FROM cli_auth_requests WHERE binding_hash = $1 AND expires_at > now();

-- name: ConsumeCLIRequest :one
DELETE FROM cli_auth_requests WHERE binding_hash = $1 AND expires_at > now() RETURNING *;

-- name: InsertCLICode :exec
INSERT INTO cli_auth_codes(code_hash, browser_session_hash, authorization_version, redirect_uri, code_challenge)
VALUES ($1, $2, $3, $4, $5);

-- name: GetCLICode :one
SELECT * FROM cli_auth_codes WHERE code_hash = $1 AND expires_at > now();

-- name: ConsumeCLICode :one
DELETE FROM cli_auth_codes WHERE code_hash = $1 AND expires_at > now()
  AND code_challenge = $2 AND redirect_uri = $3 RETURNING *;

-- name: InsertCLISession :one
INSERT INTO sessions(token_hash, principal_id, kind, created_at, last_seen_at,
  idle_expires_at, absolute_expires_at, break_glass, incident_reason)
SELECT sqlc.arg(token_hash), source.principal_id, 'cli', now(), now(),
  LEAST(now() + interval '15 minutes', source.absolute_expires_at),
  LEAST(now() + interval '8 hours', source.absolute_expires_at), source.break_glass, source.incident_reason
FROM sessions AS source WHERE source.token_hash = sqlc.arg(browser_session_hash)
  AND source.kind = 'browser' AND source.revoked_at IS NULL
  AND source.idle_expires_at > now() AND source.absolute_expires_at > now()
RETURNING sessions.absolute_expires_at;
