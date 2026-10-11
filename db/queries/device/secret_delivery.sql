-- Sealed deliveries minted with one resource action. Only HPKE ciphertext and
-- identifiers are stored; replays return these exact bytes in ordinal order.
-- name: InsertResourceActionSecret :exec
INSERT INTO resource_action_secrets(action_id, ordinal, secret_id, version, recipient_key_sha256, sealed)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: ListResourceActionSecrets :many
SELECT sealed FROM resource_action_secrets WHERE action_id = $1 ORDER BY ordinal LIMIT 8;
