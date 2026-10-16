-- SPDX-License-Identifier: Apache-2.0

-- +goose Up
-- Counts describe additional consistent vendor sets in the latest refresh,
-- independently of HTTP request retries and published snapshot coverage.
ALTER TABLE advisory_feeds
 ADD COLUMN vendor_race_refetch_count bigint NOT NULL DEFAULT 0 CHECK (vendor_race_refetch_count >= 0);

UPDATE lindm_schema_compatibility
SET minimum_runtime_version = 61,
 migration_versions = (
  SELECT array_agg(version ORDER BY version)
  FROM (
   SELECT version FROM (
    SELECT DISTINCT ON(version_id) version_id AS version, is_applied
    FROM goose_db_version ORDER BY version_id, id DESC
   ) latest WHERE is_applied AND version > 0
   UNION SELECT 61::bigint
  ) versions
 );

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 RAISE EXCEPTION 'advisory vendor publication race status requires a fenced compatible backup restore';
END $$;
-- +goose StatementEnd
