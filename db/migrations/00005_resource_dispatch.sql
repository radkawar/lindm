-- SPDX-License-Identifier: Apache-2.0

-- +goose Up
-- Device-owned immutable desired heads and exact signed execution leases.
CREATE TABLE resource_assignments (
    id uuid PRIMARY KEY,
    device_id uuid NOT NULL REFERENCES devices(id),
    generation_id uuid NOT NULL REFERENCES enrollment_generations(id),
    request_id uuid NOT NULL UNIQUE,
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    actor_id uuid NOT NULL REFERENCES principals(id),
    authorization_version bigint NOT NULL CHECK (authorization_version > 0),
    revision_id uuid REFERENCES profile_revisions(id),
    document bytea NOT NULL CHECK (octet_length(document) BETWEEN 1 AND 1048576),
    assigned_at timestamptz NOT NULL,
    reconcile_interval_seconds integer NOT NULL DEFAULT 900 CHECK (reconcile_interval_seconds BETWEEN 300 AND 86400),
    blocked_reason text NOT NULL DEFAULT '' CHECK (char_length(blocked_reason) <= 128),
    UNIQUE (generation_id, id)
);
CREATE TABLE resource_assignment_heads (
    generation_id uuid PRIMARY KEY REFERENCES enrollment_generations(id),
    assignment_id uuid NOT NULL,
    FOREIGN KEY (generation_id, assignment_id) REFERENCES resource_assignments(generation_id, id)
);
CREATE TABLE resource_sequences (
    generation_id uuid NOT NULL REFERENCES enrollment_generations(id),
    resource_kind smallint NOT NULL CHECK (resource_kind BETWEEN 1 AND 20),
    canonical_key text NOT NULL CHECK (octet_length(canonical_key) BETWEEN 1 AND 1024),
    sequence bigint NOT NULL CHECK (sequence > 0),
    PRIMARY KEY (generation_id, resource_kind, canonical_key)
);
CREATE TABLE resource_assignment_resources (
    assignment_id uuid NOT NULL REFERENCES resource_assignments(id),
    resource_id uuid NOT NULL,
    resource_kind smallint NOT NULL CHECK (resource_kind BETWEEN 1 AND 20),
    canonical_key text NOT NULL CHECK (octet_length(canonical_key) BETWEEN 1 AND 1024),
    position integer NOT NULL CHECK (position BETWEEN 0 AND 8191),
    document bytea NOT NULL CHECK (octet_length(document) BETWEEN 1 AND 65536),
    depends_on uuid[] NOT NULL DEFAULT '{}' CHECK (cardinality(depends_on) <= 8191),
    disposition smallint NOT NULL DEFAULT 1 CHECK (disposition BETWEEN 1 AND 7),
    reason text NOT NULL DEFAULT '' CHECK (char_length(reason) <= 128),
    last_verified_at timestamptz,
    observed_at timestamptz,
    drift_remediated boolean NOT NULL DEFAULT false,
    verification_max_age_seconds integer NOT NULL DEFAULT 1800 CHECK (verification_max_age_seconds BETWEEN 30 AND 604800),
    PRIMARY KEY (assignment_id, resource_id),
    UNIQUE (assignment_id, resource_kind, canonical_key),
    UNIQUE (assignment_id, position)
);
CREATE TABLE resource_actions (
    id uuid PRIMARY KEY,
    device_id uuid NOT NULL REFERENCES devices(id),
    generation_id uuid NOT NULL REFERENCES enrollment_generations(id),
    assignment_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    resource_sequence bigint NOT NULL CHECK (resource_sequence > 0),
    intent_envelope bytea NOT NULL CHECK (octet_length(intent_envelope) BETWEEN 1 AND 16384),
    intent_document bytea NOT NULL CHECK (octet_length(intent_document) BETWEEN 1 AND 8192),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > issued_at),
    challenge_proof bytea NOT NULL DEFAULT '' CHECK (octet_length(challenge_proof) <= 16384),
    start_grant_envelope bytea NOT NULL DEFAULT '' CHECK (octet_length(start_grant_envelope) <= 16384),
    start_authorized_at timestamptz,
    closed_at timestamptz,
    closed_reason text NOT NULL DEFAULT '' CHECK (char_length(closed_reason) <= 128),
    result_nonce bytea NOT NULL DEFAULT '' CHECK (octet_length(result_nonce) IN (0, 32)),
    nonce_expires_at timestamptz,
    action_revision numeric(20,0) NOT NULL DEFAULT 0 CHECK (action_revision BETWEEN 0 AND 18446744073709551615),
    attestation_envelope bytea NOT NULL DEFAULT '' CHECK (octet_length(attestation_envelope) <= 65536),
    attestation_certificate bytea NOT NULL DEFAULT '' CHECK (octet_length(attestation_certificate) <= 16384),
    status_document bytea NOT NULL DEFAULT '' CHECK (octet_length(status_document) <= 49152),
    attested_at timestamptz,
    received_at timestamptz,
    read_only_success boolean NOT NULL DEFAULT false,
    FOREIGN KEY (generation_id, assignment_id) REFERENCES resource_assignments(generation_id, id),
    FOREIGN KEY (assignment_id, resource_id) REFERENCES resource_assignment_resources(assignment_id, resource_id),
    CHECK ((closed_at IS NULL) = (closed_reason = '')),
    CHECK ((start_authorized_at IS NULL) = (octet_length(start_grant_envelope) = 0)),
    CHECK ((octet_length(challenge_proof) = 0) = (octet_length(start_grant_envelope) = 0)),
    CHECK (NOT read_only_success OR (closed_at IS NOT NULL AND closed_reason = 'result' AND octet_length(start_grant_envelope) = 0 AND received_at IS NOT NULL))
);
CREATE UNIQUE INDEX resource_actions_one_open ON resource_actions(device_id) WHERE closed_at IS NULL;
CREATE INDEX resource_actions_resource ON resource_actions(assignment_id, resource_id, resource_sequence DESC);
CREATE INDEX resource_actions_recent ON resource_actions(generation_id, issued_at DESC, id DESC);
CREATE INDEX resource_actions_read_only ON resource_actions(generation_id, issued_at DESC, id DESC) WHERE read_only_success;

-- Unassignment schedules ownership-safe release; Phase 1 never fabricates a
-- pre-management baseline or interprets removal from a head as native deletion.
CREATE TABLE resource_releases (
    id uuid PRIMARY KEY,
    generation_id uuid NOT NULL REFERENCES enrollment_generations(id),
    source_assignment_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    resource_kind smallint NOT NULL CHECK (resource_kind BETWEEN 1 AND 20),
    canonical_key text NOT NULL CHECK (octet_length(canonical_key) BETWEEN 1 AND 1024),
    superseding_assignment_id uuid NOT NULL REFERENCES resource_assignments(id),
    state text NOT NULL DEFAULT 'baseline_unknown' CHECK (state IN ('baseline_unknown', 'pending', 'released', 'release_conflict')),
    reason text NOT NULL DEFAULT 'ownership_baseline_unavailable' CHECK (char_length(reason) <= 128),
    requested_at timestamptz NOT NULL,
    completed_at timestamptz,
    FOREIGN KEY (source_assignment_id, resource_id) REFERENCES resource_assignment_resources(assignment_id, resource_id),
    UNIQUE (source_assignment_id, resource_id, superseding_assignment_id),
    CHECK ((state = 'released') = (completed_at IS NOT NULL))
);

-- +goose Down
DROP TABLE resource_releases;
DROP TABLE resource_actions;
DROP TABLE resource_assignment_resources;
DROP TABLE resource_sequences;
DROP TABLE resource_assignment_heads;
DROP TABLE resource_assignments;
