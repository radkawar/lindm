-- SPDX-License-Identifier: Apache-2.0

-- lindm:online-compatible minimum-runtime=51
-- +goose Up
ALTER TABLE sessions
  ADD COLUMN recovery_custody_step_up_digest bytea NOT NULL DEFAULT ''::bytea,
  ADD COLUMN recovery_custody_step_up_at timestamptz,
  ADD CONSTRAINT sessions_recovery_custody_step_up_pair CHECK (
    (octet_length(recovery_custody_step_up_digest) = 0 AND recovery_custody_step_up_at IS NULL)
    OR (octet_length(recovery_custody_step_up_digest) = 32
      AND recovery_custody_step_up_at IS NOT NULL
      AND recovery_custody_step_up_at >= created_at)
  );

CREATE TABLE recovery_key_custody_confirmations (
  deployment_id uuid NOT NULL,
  confirmation_digest text NOT NULL CHECK (confirmation_digest ~ '^[0-9a-f]{64}$'),
  owner_principal_id uuid NOT NULL REFERENCES principals (id) ON DELETE RESTRICT,
  confirmed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (deployment_id, confirmation_digest)
);

UPDATE lindm_schema_compatibility
SET migration_versions = (
  SELECT array_agg(version ORDER BY version)
  FROM (
    SELECT version FROM (
      SELECT DISTINCT ON (version_id) version_id AS version, is_applied
      FROM goose_db_version ORDER BY version_id, id DESC
    ) latest WHERE is_applied AND version > 0
    UNION SELECT 53::bigint
  ) versions
);

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
  RAISE EXCEPTION 'recovery custody attestations require an explicitly reviewed fenced restore';
END $$;
-- +goose StatementEnd
