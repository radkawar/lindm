-- SPDX-License-Identifier: Apache-2.0

-- +goose Up
-- Counts describe the latest attempted refresh, not the published snapshot.
ALTER TABLE advisory_feeds
 ADD COLUMN request_retry_count bigint NOT NULL DEFAULT 0 CHECK (request_retry_count >= 0);

UPDATE lindm_schema_compatibility
SET minimum_runtime_version = 60,
 migration_versions = (
  SELECT array_agg(version ORDER BY version)
  FROM (
   SELECT version FROM (
    SELECT DISTINCT ON(version_id) version_id AS version, is_applied
    FROM goose_db_version ORDER BY version_id, id DESC
   ) latest WHERE is_applied AND version > 0
   UNION SELECT 60::bigint
  ) versions
 );

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 RAISE EXCEPTION 'advisory request retry status requires a fenced compatible backup restore';
END $$;
-- +goose StatementEnd
