-- SPDX-License-Identifier: Apache-2.0

-- +goose Up
-- Architecture-specific source configuration and live-refresh authority require
-- the new runtime. No reviewed-online marker: the installer fences this change.
ALTER TABLE advisory_feeds ADD COLUMN architecture text NOT NULL DEFAULT '';
ALTER TABLE advisory_feeds DROP CONSTRAINT advisory_feeds_distro_release_platform_stream_key;
ALTER TABLE advisory_feeds ADD UNIQUE (distro,release,platform_stream,architecture);
ALTER TABLE advisory_generation_cleanup ADD COLUMN started_at timestamptz;
ALTER TABLE advisory_generation_cleanup ADD COLUMN config_bytes bytea NOT NULL DEFAULT '';
-- Derived current-host projection, never a second source configuration.
ALTER TABLE host_observations ADD COLUMN advisory_eligible boolean NOT NULL DEFAULT false;
ALTER TABLE host_observations ADD COLUMN advisory_platform_stream text NOT NULL DEFAULT '';
ALTER TABLE host_observations ADD COLUMN advisory_registry_revision bytea NOT NULL DEFAULT '';
CREATE INDEX host_observations_advisory_projection_idx ON host_observations(advisory_registry_revision,generation_id);

UPDATE lindm_schema_compatibility
SET minimum_runtime_version = 58,
    migration_versions = (
        SELECT array_agg(version ORDER BY version)
        FROM (
            SELECT version FROM (
                SELECT DISTINCT ON(version_id) version_id AS version, is_applied
                FROM goose_db_version ORDER BY version_id, id DESC
            ) latest WHERE is_applied AND version > 0
            UNION SELECT 58::bigint
        ) versions
    );

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'automatic advisory source authority requires a fenced compatible backup restore';
END $$;
-- +goose StatementEnd
