-- +goose Up
-- Device-owned immutable desired heads and exact signed execution leases.
CREATE TABLE service_assignments (
    id uuid PRIMARY KEY,
    device_id uuid NOT NULL REFERENCES devices(id),
    generation_id uuid NOT NULL REFERENCES enrollment_generations(id),
    request_id uuid NOT NULL UNIQUE,
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    actor_id uuid NOT NULL REFERENCES principals(id),
    authorization_version bigint NOT NULL CHECK (authorization_version > 0),
    revision_id uuid REFERENCES service_profile_revisions(id),
    document bytea NOT NULL CHECK (octet_length(document) BETWEEN 1 AND 4096),
    assigned_at timestamptz NOT NULL,
    blocked_reason text NOT NULL DEFAULT '' CHECK (char_length(blocked_reason) <= 128),
    UNIQUE (generation_id, id)
);
CREATE TABLE service_assignment_heads (
    generation_id uuid PRIMARY KEY REFERENCES enrollment_generations(id),
    assignment_id uuid NOT NULL,
    FOREIGN KEY (generation_id, assignment_id) REFERENCES service_assignments(generation_id, id)
);
CREATE TABLE service_resource_sequences (
    generation_id uuid NOT NULL REFERENCES enrollment_generations(id),
    unit_name text NOT NULL CHECK (char_length(unit_name) BETWEEN 1 AND 255),
    sequence bigint NOT NULL CHECK (sequence > 0),
    PRIMARY KEY (generation_id, unit_name)
);
CREATE TABLE service_assignment_resources (
    assignment_id uuid NOT NULL REFERENCES service_assignments(id),
    resource_id uuid NOT NULL,
    unit_name text NOT NULL CHECK (char_length(unit_name) BETWEEN 1 AND 255),
    position integer NOT NULL CHECK (position BETWEEN 0 AND 63),
    document bytea NOT NULL CHECK (octet_length(document) BETWEEN 1 AND 8192),
    disposition smallint NOT NULL DEFAULT 1 CHECK (disposition BETWEEN 1 AND 5),
    reason text NOT NULL DEFAULT '' CHECK (char_length(reason) <= 128),
    PRIMARY KEY (assignment_id, resource_id),
    UNIQUE (assignment_id, unit_name),
    UNIQUE (assignment_id, position)
);
CREATE TABLE service_actions (
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
    FOREIGN KEY (generation_id, assignment_id) REFERENCES service_assignments(generation_id, id),
    FOREIGN KEY (assignment_id, resource_id) REFERENCES service_assignment_resources(assignment_id, resource_id),
    CHECK ((closed_at IS NULL) = (closed_reason = '')),
    CHECK ((start_authorized_at IS NULL) = (octet_length(start_grant_envelope) = 0)),
    CHECK ((octet_length(challenge_proof) = 0) = (octet_length(start_grant_envelope) = 0))
);
CREATE UNIQUE INDEX service_actions_one_open ON service_actions(device_id) WHERE closed_at IS NULL;
CREATE INDEX service_actions_resource ON service_actions(assignment_id, resource_id, resource_sequence DESC);
CREATE INDEX service_actions_recent ON service_actions(generation_id, issued_at DESC, id DESC);

-- +goose Down
DROP TABLE service_actions;
DROP TABLE service_assignment_resources;
DROP TABLE service_resource_sequences;
DROP TABLE service_assignment_heads;
DROP TABLE service_assignments;
