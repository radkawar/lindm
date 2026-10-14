-- SPDX-License-Identifier: Apache-2.0

-- lindm:online-compatible minimum-runtime=51
-- +goose Up
-- Reconnect remembers bounded workflow metadata only: never a grant, portal
-- token, relay credential, media key or DTLS identity. Recordings store
-- helper-sealed HPKE/AES-256-GCM segments exactly as produced; plaintext,
-- recording keys and retrieval output never enter SQL.
CREATE TABLE assistance_reconnect_workflows (
    id uuid PRIMARY KEY,
    device_id uuid NOT NULL REFERENCES devices(id),
    operator_id uuid NOT NULL REFERENCES principals(id),
    origin_session_id uuid NOT NULL UNIQUE REFERENCES assistance_sessions(id),
    latest_session_id uuid NOT NULL REFERENCES assistance_sessions(id),
    mode smallint NOT NULL CHECK (mode IN (2, 3)),
    window_seconds integer NOT NULL CHECK (window_seconds BETWEEN 60 AND 14400),
    max_reconnects smallint NOT NULL CHECK (max_reconnects BETWEEN 1 AND 8),
    reconnects smallint NOT NULL DEFAULT 0 CHECK (reconnects BETWEEN 0 AND 8 AND reconnects <= max_reconnects),
    -- Bound at the first consent; a reconnect never targets another account.
    target_username text NOT NULL DEFAULT '' CHECK (target_username ~ '^([a-zA-Z_][a-zA-Z0-9_.-]{0,31})?$'),
    approved boolean NOT NULL DEFAULT false,
    state smallint NOT NULL DEFAULT 1 CHECK (state BETWEEN 1 AND 4),
    created_at timestamptz NOT NULL,
    expires_at timestamptz,
    next_attempt_at timestamptz,
    ended_at timestamptz,
    end_reason text NOT NULL DEFAULT '' CHECK (end_reason ~ '^[a-z0-9_]{0,64}$'),
    CHECK (state <> 2 OR (expires_at IS NOT NULL AND approved AND target_username <> '')),
    CHECK ((state >= 3) = (ended_at IS NOT NULL))
);
CREATE UNIQUE INDEX assistance_reconnect_one_open ON assistance_reconnect_workflows(device_id) WHERE state < 3;
CREATE INDEX assistance_reconnect_operator_idx ON assistance_reconnect_workflows(operator_id);
CREATE INDEX assistance_reconnect_latest_idx ON assistance_reconnect_workflows(latest_session_id);
CREATE INDEX assistance_reconnect_waiting_idx ON assistance_reconnect_workflows(expires_at) WHERE state = 2;

ALTER TABLE assistance_sessions
    ADD COLUMN reconnect_workflow_id uuid REFERENCES assistance_reconnect_workflows(id),
    ADD COLUMN reconnect_of uuid REFERENCES assistance_sessions(id),
    ADD CHECK (reconnect_of IS NULL OR reconnect_workflow_id IS NOT NULL);
CREATE INDEX assistance_sessions_reconnect_workflow_idx ON assistance_sessions(reconnect_workflow_id);
CREATE UNIQUE INDEX assistance_sessions_reconnect_of_idx ON assistance_sessions(reconnect_of);

CREATE TABLE assistance_recordings (
    id uuid PRIMARY KEY,
    session_id uuid NOT NULL UNIQUE REFERENCES assistance_sessions(id),
    device_id uuid NOT NULL REFERENCES devices(id),
    operator_id uuid NOT NULL REFERENCES principals(id),
    required boolean NOT NULL,
    key_id text NOT NULL CHECK (key_id ~ '^[0-9a-f]{64}$'),
    max_bytes bigint NOT NULL CHECK (max_bytes BETWEEN 1048576 AND 1073741824),
    retention_days smallint NOT NULL CHECK (retention_days BETWEEN 1 AND 365),
    state smallint NOT NULL DEFAULT 1 CHECK (state BETWEEN 1 AND 7),
    encapsulated_key bytea CHECK (encapsulated_key IS NULL OR octet_length(encapsulated_key) = 1120),
    segments integer NOT NULL DEFAULT 0 CHECK (segments BETWEEN 0 AND 65536),
    stored_bytes bigint NOT NULL DEFAULT 0 CHECK (stored_bytes BETWEEN 0 AND max_bytes),
    -- Serialized running SHA-256 of the ciphertext stream, then its digest.
    hash_state bytea NOT NULL DEFAULT '' CHECK (octet_length(hash_state) <= 256),
    ciphertext_sha256 bytea CHECK (ciphertext_sha256 IS NULL OR octet_length(ciphertext_sha256) = 32),
    created_at timestamptz NOT NULL,
    started_at timestamptz,
    last_segment_at timestamptz,
    finalized_at timestamptz,
    retain_until timestamptz,
    deleted_at timestamptz,
    reason text NOT NULL DEFAULT '' CHECK (reason ~ '^[a-z0-9_]{0,64}$'),
    CHECK ((state >= 3) = (finalized_at IS NOT NULL)),
    CHECK ((state = 7) = (deleted_at IS NOT NULL)),
    CHECK ((state IN (3, 4)) = (retain_until IS NOT NULL AND ciphertext_sha256 IS NOT NULL)),
    CHECK (state NOT IN (5, 6) OR segments = 0),
    CHECK (((segments = 0) = (encapsulated_key IS NULL)) OR state = 7)
);
CREATE INDEX assistance_recordings_device_idx ON assistance_recordings(device_id, created_at DESC, id DESC);
CREATE INDEX assistance_recordings_operator_idx ON assistance_recordings(operator_id);
CREATE INDEX assistance_recordings_retention_idx ON assistance_recordings(retain_until) WHERE state IN (3, 4);
CREATE INDEX assistance_recordings_open_idx ON assistance_recordings(created_at) WHERE state IN (1, 2);

CREATE TABLE assistance_recording_segments (
    recording_id uuid NOT NULL REFERENCES assistance_recordings(id),
    sequence integer NOT NULL CHECK (sequence BETWEEN 0 AND 65535),
    final boolean NOT NULL,
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 16 AND 196624),
    digest bytea NOT NULL CHECK (octet_length(digest) = 32),
    stored_at timestamptz NOT NULL,
    PRIMARY KEY (recording_id, sequence)
);
CREATE UNIQUE INDEX assistance_recording_segments_one_final ON assistance_recording_segments(recording_id) WHERE final;

-- Expiring, operator-bound retrievals. Each open is audited; reads are not.
CREATE TABLE assistance_recording_retrievals (
    id uuid PRIMARY KEY,
    recording_id uuid NOT NULL REFERENCES assistance_recordings(id),
    operator_id uuid NOT NULL REFERENCES principals(id),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '30 minutes')
);
CREATE INDEX assistance_recording_retrievals_recording_idx ON assistance_recording_retrievals(recording_id);
CREATE INDEX assistance_recording_retrievals_operator_idx ON assistance_recording_retrievals(operator_id);
CREATE INDEX assistance_recording_retrievals_expiry_idx ON assistance_recording_retrievals(expires_at);

CREATE TABLE assistance_recording_deletions (
    request_id uuid PRIMARY KEY,
    recording_id uuid NOT NULL REFERENCES assistance_recordings(id),
    operator_id uuid NOT NULL REFERENCES principals(id),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32)
);
CREATE INDEX assistance_recording_deletions_recording_idx ON assistance_recording_deletions(recording_id);
CREATE INDEX assistance_recording_deletions_operator_idx ON assistance_recording_deletions(operator_id);

UPDATE lindm_schema_compatibility
SET migration_versions = (
  SELECT array_agg(version ORDER BY version)
  FROM (
    SELECT version FROM (
      SELECT DISTINCT ON (version_id) version_id AS version, is_applied
      FROM goose_db_version ORDER BY version_id, id DESC
    ) latest WHERE is_applied AND version > 0
    UNION SELECT 55::bigint
  ) versions
);

-- +goose Down
DROP TABLE assistance_recording_deletions;
DROP TABLE assistance_recording_retrievals;
DROP TABLE assistance_recording_segments;
DROP TABLE assistance_recordings;
ALTER TABLE assistance_sessions DROP COLUMN reconnect_of, DROP COLUMN reconnect_workflow_id;
DROP TABLE assistance_reconnect_workflows;
