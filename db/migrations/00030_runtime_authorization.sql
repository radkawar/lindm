-- +goose Up
-- A NULL runtime definition means configuration is the bootstrap authority.
-- Once written, even an empty policy is authoritative across all server restarts.
ALTER TABLE authorization_policy
  ADD COLUMN definition bytea,
  ADD COLUMN revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
  ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();

CREATE TABLE authorization_requests (
  actor_id uuid NOT NULL REFERENCES principals(id),
  request_id uuid NOT NULL,
  request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
  response bytea NOT NULL,
  PRIMARY KEY (actor_id, request_id)
);

-- +goose Down
DROP TABLE authorization_requests;
ALTER TABLE authorization_policy DROP COLUMN definition, DROP COLUMN revision, DROP COLUMN updated_at;
