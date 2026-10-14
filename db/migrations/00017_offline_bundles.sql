-- SPDX-License-Identifier: Apache-2.0

-- +goose Up

-- Replay ledger for signed offline bundles. A sequence is admitted once per
-- deployment; an identical interrupted manifest may resume, a different
-- manifest at an admitted sequence is equivocation and is rejected.
CREATE TABLE offline_bundle_imports (
    sequence bigint PRIMARY KEY CHECK (sequence > 0),
    bundle_id uuid NOT NULL UNIQUE,
    manifest_sha256 bytea NOT NULL CHECK (octet_length(manifest_sha256) = 32),
    signing_key_id text NOT NULL CHECK (signing_key_id ~ '^[a-f0-9]{64}$'),
    release_version text NOT NULL CHECK (release_version ~ '^[0-9]+\.[0-9]+\.[0-9]+$'),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    imported_at timestamptz,
    state text NOT NULL CHECK (state IN ('importing', 'imported')),
    CHECK (expires_at > created_at),
    CHECK ((state = 'imported') = (imported_at IS NOT NULL))
);

-- +goose Down
DROP TABLE offline_bundle_imports;
