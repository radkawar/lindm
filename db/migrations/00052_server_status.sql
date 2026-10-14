-- SPDX-License-Identifier: Apache-2.0

-- lindm:online-compatible minimum-runtime=51
-- +goose Up
CREATE TABLE server_status_alerts (
  instance text NOT NULL CHECK (char_length(instance) = 32),
  component text NOT NULL CHECK (component IN ('database','admin_database','https_certificate','device_ca','backups','server_release_feed','agent_repository','advisory_feeds','disk','job_queue')),
  state integer NOT NULL CHECK (state BETWEEN 1 AND 5),
  has_degradation boolean NOT NULL,
  evidence_key text NOT NULL CHECK (char_length(evidence_key) IN (0,64)),
  notified_at timestamptz NOT NULL,
  PRIMARY KEY (instance, component)
);

UPDATE lindm_schema_compatibility
SET migration_versions = (
  SELECT array_agg(version ORDER BY version)
  FROM (
    SELECT version FROM (
      SELECT DISTINCT ON (version_id) version_id AS version, is_applied
      FROM goose_db_version ORDER BY version_id, id DESC
    ) latest WHERE is_applied AND version > 0
    UNION SELECT 52::bigint
  ) versions
);

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
  RAISE EXCEPTION 'server status audit state requires an explicitly reviewed fenced restore';
END $$;
-- +goose StatementEnd
