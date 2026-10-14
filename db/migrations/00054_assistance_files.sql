-- SPDX-License-Identifier: Apache-2.0

-- lindm:online-compatible minimum-runtime=51
-- +goose Up
-- Policy now includes bounded MIME/extension sets. No content or source paths
-- are stored: request_metadata and report contain only validated wire metadata.
ALTER TABLE assistance_sessions
    DROP CONSTRAINT assistance_sessions_requested_capabilities_check,
    DROP CONSTRAINT assistance_sessions_effective_capabilities_check,
    ADD CHECK (octet_length(requested_capabilities) <= 4096),
    ADD CHECK (octet_length(effective_capabilities) <= 4096),
    ADD COLUMN input_epoch bigint NOT NULL DEFAULT 1 CHECK (input_epoch BETWEEN 1 AND 4294967295),
    ADD COLUMN input_paused boolean NOT NULL DEFAULT false;
ALTER TABLE assistance_policies DROP CONSTRAINT assistance_policies_policy_check,
    ADD CHECK (octet_length(policy) <= 4096);
ALTER TABLE assistance_policy_requests DROP CONSTRAINT assistance_policy_requests_policy_check,
    ADD CHECK (octet_length(policy) <= 4096);
ALTER TABLE assistance_commands DROP CONSTRAINT assistance_commands_policy_check,
    ADD CHECK (octet_length(policy) <= 4096);

CREATE TABLE assistance_file_transfers (
    request_id uuid PRIMARY KEY,
    session_id uuid NOT NULL REFERENCES assistance_sessions(id),
    device_id uuid NOT NULL REFERENCES devices(id),
    operator_id uuid NOT NULL REFERENCES principals(id),
    owner_instance uuid NOT NULL,
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    request_number smallint NOT NULL CHECK (request_number BETWEEN 1 AND 32),
    direction smallint NOT NULL CHECK (direction IN (1, 2)),
    request_metadata bytea NOT NULL CHECK (octet_length(request_metadata) BETWEEN 1 AND 4096),
    report bytea NOT NULL CHECK (octet_length(report) BETWEEN 1 AND 1024),
    reserved_bytes bigint NOT NULL CHECK (reserved_bytes BETWEEN 0 AND 16777216),
    bytes_transferred bigint NOT NULL DEFAULT 0 CHECK (bytes_transferred BETWEEN 0 AND reserved_bytes),
    state smallint NOT NULL DEFAULT 1 CHECK (state BETWEEN 1 AND 7),
    created_at timestamptz NOT NULL,
    deadline timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (session_id, request_number),
    CHECK (deadline > created_at AND deadline <= created_at + interval '5 minutes'),
    CHECK ((state < 4) = (completed_at IS NULL))
);
CREATE UNIQUE INDEX assistance_files_one_active ON assistance_file_transfers(session_id) WHERE state < 4;
CREATE INDEX assistance_files_session_idx ON assistance_file_transfers(session_id, created_at DESC, request_id);
CREATE INDEX assistance_files_device_idx ON assistance_file_transfers(device_id);
CREATE INDEX assistance_files_operator_idx ON assistance_file_transfers(operator_id);

UPDATE lindm_schema_compatibility
SET migration_versions = (
  SELECT array_agg(version ORDER BY version)
  FROM (
    SELECT version FROM (
      SELECT DISTINCT ON (version_id) version_id AS version, is_applied
      FROM goose_db_version ORDER BY version_id, id DESC
    ) latest WHERE is_applied AND version > 0
    UNION SELECT 54::bigint
  ) versions
);

-- +goose Down
DROP TABLE assistance_file_transfers;
ALTER TABLE assistance_sessions DROP COLUMN input_epoch, DROP COLUMN input_paused;
-- Do not discard policy metadata on rollback. The bounded wider columns remain
-- readable by the prior version, whose absent file capability fails closed.
