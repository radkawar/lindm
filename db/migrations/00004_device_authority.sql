-- +goose Up

ALTER TABLE devices DROP CONSTRAINT devices_state_check;
ALTER TABLE devices ADD CONSTRAINT devices_state_check
    CHECK (state IN ('pending', 'active', 'recovery_hold', 'revoked'));
ALTER TABLE enrollment_generations DROP CONSTRAINT enrollment_generations_state_check;
ALTER TABLE enrollment_generations ADD CONSTRAINT enrollment_generations_state_check
    CHECK (state IN ('pending', 'active', 'recovery_hold', 'revoked'));

-- Existing generations have no session authority, not a fabricated acquisition.
-- Inventory and enrollment records are preserved; a signed predecessor-zero CAS
-- is required before any fenced mutation. Counts bound durable admission without
-- expiring receipts or forgetting consumed predecessors in the active generation.
ALTER TABLE enrollment_generations
    ADD COLUMN session_epoch bigint NOT NULL DEFAULT 0,
    ADD COLUMN renewal_issuance_count integer NOT NULL DEFAULT 0,
    ADD CONSTRAINT enrollment_generations_session_bounds CHECK (session_epoch BETWEEN 0 AND 65536),
    ADD CONSTRAINT enrollment_generations_renewal_bounds CHECK (renewal_issuance_count BETWEEN 0 AND 4096);

CREATE TABLE device_session_receipts (
    generation_id uuid NOT NULL REFERENCES enrollment_generations (id) ON DELETE RESTRICT,
    request_id uuid NOT NULL,
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    session_epoch bigint NOT NULL CHECK (session_epoch BETWEEN 1 AND 65536),
    host_sequence bigint NOT NULL CHECK (host_sequence >= 0),
    package_sequence bigint NOT NULL CHECK (package_sequence >= 0),
    accepted_at timestamptz NOT NULL,
    PRIMARY KEY (generation_id, request_id),
    UNIQUE (generation_id, session_epoch),
    CHECK (request_id <> '00000000-0000-0000-0000-000000000000')
);

CREATE TABLE device_renewal_receipts (
    generation_id uuid NOT NULL REFERENCES enrollment_generations (id) ON DELETE RESTRICT,
    request_id uuid NOT NULL,
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    presented_certificate_id uuid NOT NULL REFERENCES device_certificates (id) ON DELETE RESTRICT,
    issued_certificate_id uuid NOT NULL REFERENCES device_certificates (id) ON DELETE RESTRICT,
    issued_at timestamptz NOT NULL,
    PRIMARY KEY (generation_id, request_id),
    UNIQUE (issued_certificate_id),
    CHECK (request_id <> '00000000-0000-0000-0000-000000000000')
);

-- +goose Down

-- Refuse to silently turn a held generation back into ordinary authority.
ALTER TABLE devices DROP CONSTRAINT devices_state_check;
ALTER TABLE devices ADD CONSTRAINT devices_state_check CHECK (state IN ('pending', 'active', 'revoked'));
ALTER TABLE enrollment_generations DROP CONSTRAINT enrollment_generations_state_check;
ALTER TABLE enrollment_generations ADD CONSTRAINT enrollment_generations_state_check CHECK (state IN ('pending', 'active', 'revoked'));
DROP TABLE device_renewal_receipts;
DROP TABLE device_session_receipts;
ALTER TABLE enrollment_generations
    DROP COLUMN session_epoch,
    DROP COLUMN renewal_issuance_count;
