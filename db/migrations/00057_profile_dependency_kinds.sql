-- SPDX-License-Identifier: Apache-2.0

-- lindm:online-compatible minimum-runtime=51
-- +goose Up
-- Match the expanded typed resource registry without rewriting applied history.
ALTER TABLE profile_dependencies
    DROP CONSTRAINT profile_dependencies_dependency_kind_check,
    ADD CONSTRAINT profile_dependencies_dependency_kind_check CHECK (dependency_kind BETWEEN 1 AND 24);

UPDATE lindm_schema_compatibility
SET migration_versions = (
  SELECT array_agg(version ORDER BY version)
  FROM (
    SELECT version FROM (
      SELECT DISTINCT ON (version_id) version_id AS version, is_applied
      FROM goose_db_version ORDER BY version_id, id DESC
    ) latest WHERE is_applied AND version > 0
    UNION SELECT 57::bigint
  ) versions
);

-- +goose Down
-- Serialize the retained-edge check with publications before narrowing the enum.
LOCK TABLE profile_dependencies IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM profile_dependencies WHERE dependency_kind > 20)
     OR EXISTS (SELECT 1 FROM lindm_schema_compatibility WHERE minimum_runtime_version > 51) THEN
    RAISE EXCEPTION 'retained expanded profile dependencies or compatibility floor requires a fenced backup restore';
  END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE profile_dependencies
    DROP CONSTRAINT profile_dependencies_dependency_kind_check,
    ADD CONSTRAINT profile_dependencies_dependency_kind_check CHECK (dependency_kind BETWEEN 1 AND 20);
UPDATE lindm_schema_compatibility
SET minimum_runtime_version = LEAST(minimum_runtime_version, 51),
    migration_versions = array_remove(migration_versions, 57::bigint);
