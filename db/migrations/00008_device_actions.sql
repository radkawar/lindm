-- +goose Up
-- Imperative actions never reconcile or reissue effects after start authority.
CREATE TABLE device_actions (
    id uuid PRIMARY KEY,
    device_id uuid NOT NULL REFERENCES devices(id),
    generation_id uuid NOT NULL REFERENCES enrollment_generations(id),
    capability text NOT NULL CHECK (capability IN ('device.escrow-rotate.v1', 'device.tpm2-bind.v1', 'device.lock-sessions.v1', 'device.release-lock.v1', 'device.quarantine.v1', 'device.release-quarantine.v1', 'device.crypto-erase.v1', 'device.sanitize.v1')),
    luks_uuids uuid[] NOT NULL DEFAULT '{}' CHECK (cardinality(luks_uuids) <= 64),
    request_id uuid NOT NULL UNIQUE,
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    request_document bytea NOT NULL CHECK (octet_length(request_document) BETWEEN 1 AND 16384),
    actor_id uuid NOT NULL REFERENCES principals(id),
    authorization_version bigint NOT NULL CHECK (authorization_version > 0),
    approval_id uuid REFERENCES approval_requests(id),
    intent_envelope bytea NOT NULL CHECK (octet_length(intent_envelope) BETWEEN 1 AND 32768),
    intent_document bytea NOT NULL CHECK (octet_length(intent_document) BETWEEN 1 AND 16384),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > issued_at),
    challenge_proof bytea NOT NULL DEFAULT '' CHECK (octet_length(challenge_proof) <= 65536),
    challenge_document bytea NOT NULL DEFAULT '' CHECK (octet_length(challenge_document) <= 49152),
    start_grant_envelope bytea NOT NULL DEFAULT '' CHECK (octet_length(start_grant_envelope) <= 65536),
    start_authorized_at timestamptz,
    outcome_unknown boolean NOT NULL DEFAULT false,
    closed_at timestamptz,
    closed_reason text NOT NULL DEFAULT '' CHECK (char_length(closed_reason) <= 128),
    result_nonce bytea NOT NULL DEFAULT '' CHECK (octet_length(result_nonce) IN (0,32)),
    nonce_expires_at timestamptz,
    action_revision numeric(20,0) NOT NULL DEFAULT 0 CHECK (action_revision BETWEEN 0 AND 18446744073709551615),
    attestation_envelope bytea NOT NULL DEFAULT '' CHECK (octet_length(attestation_envelope) <= 131072),
    attestation_certificate bytea NOT NULL DEFAULT '' CHECK (octet_length(attestation_certificate) <= 16384),
    status_document bytea NOT NULL DEFAULT '' CHECK (octet_length(status_document) <= 65536),
    received_at timestamptz,
    escrow_receipt_envelope bytea NOT NULL DEFAULT '' CHECK (octet_length(escrow_receipt_envelope) <= 32768),
    CHECK ((closed_at IS NULL) = (closed_reason = '')),
    CHECK ((start_authorized_at IS NULL) = (octet_length(start_grant_envelope) = 0)),
    CHECK ((octet_length(challenge_proof) = 0) = (octet_length(start_grant_envelope) = 0))
);
CREATE UNIQUE INDEX device_actions_one_open ON device_actions(device_id) WHERE closed_at IS NULL;
CREATE INDEX device_actions_recent ON device_actions(device_id, issued_at DESC, id DESC);
CREATE INDEX device_actions_volumes ON device_actions USING gin(luks_uuids);
CREATE TABLE device_action_escrow (
    action_id uuid PRIMARY KEY REFERENCES device_actions(id),
    binding_document bytea NOT NULL CHECK (octet_length(binding_document) BETWEEN 1 AND 8192),
    key_id text NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 128),
    wrapped_key bytea NOT NULL CHECK (octet_length(wrapped_key) BETWEEN 1 AND 1024),
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 1 AND 16384),
    secret_sha256 bytea NOT NULL CHECK (octet_length(secret_sha256) = 32),
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE device_action_restrictions (
    device_id uuid PRIMARY KEY REFERENCES devices(id),
    sessions_locked boolean NOT NULL DEFAULT false,
    lock_action_id uuid REFERENCES device_actions(id),
    quarantined boolean NOT NULL DEFAULT false,
    quarantine_until timestamptz,
    action_id uuid NOT NULL REFERENCES device_actions(id),
    updated_at timestamptz NOT NULL
);
CREATE TABLE device_action_recovery (
    action_id uuid PRIMARY KEY REFERENCES device_actions(id),
    credential_id uuid NOT NULL UNIQUE,
    certificate_id uuid NOT NULL REFERENCES device_certificates(id),
    session_epoch bigint NOT NULL CHECK (session_epoch > 0),
    public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
    handoff_proof bytea NOT NULL CHECK (octet_length(handoff_proof) BETWEEN 1 AND 65536),
    handoff_document bytea NOT NULL CHECK (octet_length(handoff_document) BETWEEN 1 AND 49152),
    credential_envelope bytea NOT NULL CHECK (octet_length(credential_envelope) BETWEEN 1 AND 65536),
    credential_sha256 bytea NOT NULL UNIQUE CHECK (octet_length(credential_sha256) = 32),
    credential_document bytea NOT NULL CHECK (octet_length(credential_document) BETWEEN 1 AND 49152),
    boot_grant_envelope bytea NOT NULL CHECK (octet_length(boot_grant_envelope) BETWEEN 1 AND 65536),
    root_json bytea NOT NULL CHECK (octet_length(root_json) BETWEEN 1 AND 16384),
    delegation_envelope bytea NOT NULL CHECK (octet_length(delegation_envelope) BETWEEN 1 AND 16384),
    expires_at timestamptz NOT NULL,
    challenge_document bytea NOT NULL DEFAULT '' CHECK (octet_length(challenge_document) <= 49152),
    start_grant_envelope bytea NOT NULL DEFAULT '' CHECK (octet_length(start_grant_envelope) <= 65536),
    start_authorized_at timestamptz,
    checkpoint_document bytea NOT NULL DEFAULT '' CHECK (octet_length(checkpoint_document) <= 8192),
    checkpoint_sha256 bytea NOT NULL DEFAULT '' CHECK (octet_length(checkpoint_sha256) IN (0,32)),
    checkpoint_sequence bigint NOT NULL DEFAULT 0 CHECK (checkpoint_sequence >= 0),
    checkpoint_receipt_envelope bytea NOT NULL DEFAULT '' CHECK (octet_length(checkpoint_receipt_envelope) <= 16384),
    journal_document bytea NOT NULL DEFAULT '' CHECK (octet_length(journal_document) <= 786432),
    effect_committed_at timestamptz,
    result_nonce bytea NOT NULL DEFAULT '' CHECK (octet_length(result_nonce) IN (0,32)),
    nonce_expires_at timestamptz,
    result_request_id uuid,
    result_proof bytea NOT NULL DEFAULT '' CHECK (octet_length(result_proof) <= 16384),
    result_document bytea NOT NULL DEFAULT '' CHECK (octet_length(result_document) <= 65536),
    CHECK ((start_authorized_at IS NULL) = (octet_length(start_grant_envelope) = 0))
);
CREATE TABLE device_action_recovery_requests (
    credential_id uuid NOT NULL REFERENCES device_action_recovery(credential_id),
    request_id uuid NOT NULL,
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 32),
    request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
    response_document bytea NOT NULL CHECK (octet_length(response_document) <= 1048576),
    PRIMARY KEY (credential_id, request_id),
    UNIQUE (credential_id, nonce)
);
-- +goose Down
DROP TABLE device_action_recovery_requests;
DROP TABLE device_action_recovery;
DROP TABLE device_action_restrictions;
DROP TABLE device_action_escrow;
DROP TABLE device_actions;
