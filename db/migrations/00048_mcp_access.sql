-- SPDX-License-Identifier: Apache-2.0

-- Dedicated assistant credentials cannot authenticate ordinary sessions.
-- +goose Up
CREATE TABLE mcp_settings (
  id boolean PRIMARY KEY DEFAULT true CHECK (id),
  enabled boolean NOT NULL DEFAULT false
);
INSERT INTO mcp_settings (id) VALUES (true);

CREATE TABLE mcp_tokens (
  id uuid PRIMARY KEY,
  principal_id uuid NOT NULL REFERENCES principals(id) ON DELETE RESTRICT,
  token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
  label text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 64 AND octet_length(label) <= 256),
  proposals_allowed boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '30 days')
);
CREATE INDEX mcp_tokens_owner ON mcp_tokens(principal_id, created_at, id)
  WHERE revoked_at IS NULL;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
  DROP TABLE mcp_tokens;
  DROP TABLE mcp_settings;
END $$;
-- +goose StatementEnd
