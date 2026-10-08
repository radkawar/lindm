-- +goose Up

-- Device enrollment, certificates, inventory, and admin idempotency.
-- audit_events and principals are owned by 00001_identity.sql.
-- Text bounds match the annotated protobuf contracts. Pending devices have
-- empty inventory columns until the first accepted observation.

CREATE TABLE enrollment_grants (
    id uuid PRIMARY KEY,
    token_hash bytea NOT NULL,
    created_by uuid NOT NULL REFERENCES principals (id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    reason text NOT NULL,
    revoked_at timestamptz,
    revoked_by uuid REFERENCES principals (id) ON DELETE RESTRICT,
    revoke_reason text NOT NULL DEFAULT '',
    consumed_at timestamptz,
    device_id uuid,
    transaction_id uuid,
    public_key_fingerprint bytea,
    CONSTRAINT enrollment_grants_token_hash_len CHECK (octet_length(token_hash) = 32),
    CONSTRAINT enrollment_grants_token_hash_unique UNIQUE (token_hash),
    CONSTRAINT enrollment_grants_reason_len CHECK (char_length(reason) BETWEEN 1 AND 512 AND reason ~ '\S'),
    CONSTRAINT enrollment_grants_revoke_reason_len CHECK (char_length(revoke_reason) <= 512),
    CONSTRAINT enrollment_grants_lifetime CHECK (
        expires_at >= created_at + interval '60 seconds'
        AND expires_at <= created_at + interval '900 seconds'
    ),
    CONSTRAINT enrollment_grants_consume_shape CHECK (
        (
            consumed_at IS NULL
            AND device_id IS NULL
            AND transaction_id IS NULL
            AND public_key_fingerprint IS NULL
        )
        OR (
            consumed_at IS NOT NULL
            AND device_id IS NOT NULL
            AND transaction_id IS NOT NULL
            AND octet_length(public_key_fingerprint) = 32
        )
    ),
    CONSTRAINT enrollment_grants_revoke_shape CHECK (
        (revoked_at IS NULL AND revoked_by IS NULL AND revoke_reason = '')
        OR (revoked_at IS NOT NULL AND revoked_by IS NOT NULL AND revoke_reason ~ '\S' AND char_length(revoke_reason) <= 512)
    )
);

CREATE TABLE devices (
    id uuid PRIMARY KEY,
    state text NOT NULL,
    current_generation_id uuid,
    hostname text NOT NULL DEFAULT '',
    os_id text NOT NULL DEFAULT '',
    os_version text NOT NULL DEFAULT '',
    architecture text NOT NULL DEFAULT '',
    enrolled_at timestamptz NOT NULL,
    last_seen_at timestamptz,
    inventory_sequence bigint NOT NULL DEFAULT 0,
    inventory_digest bytea,
    boot_id uuid,
    package_snapshot_sequence bigint NOT NULL DEFAULT 0,
    package_snapshot_complete boolean NOT NULL DEFAULT false,
    revoked_at timestamptz,
    revoked_by uuid REFERENCES principals (id) ON DELETE RESTRICT,
    revoke_reason text NOT NULL DEFAULT '',
    CONSTRAINT devices_state_check CHECK (state IN ('pending', 'active', 'revoked')),
    CONSTRAINT devices_sequence_bounds CHECK (
        inventory_sequence >= 0
        AND inventory_sequence <= 9223372036854775807
        AND package_snapshot_sequence >= 0
        AND package_snapshot_sequence <= inventory_sequence
    ),
    CONSTRAINT devices_os_version_len CHECK (char_length(os_version) <= 128),
    CONSTRAINT devices_revoke_reason_len CHECK (char_length(revoke_reason) <= 512),
    CONSTRAINT devices_inventory_shape CHECK (
        (
            inventory_sequence = 0
            AND hostname = ''
            AND os_id = ''
            AND architecture = ''
            AND boot_id IS NULL
            AND inventory_digest IS NULL
            AND package_snapshot_sequence = 0
            AND NOT package_snapshot_complete
        )
        OR (
            inventory_sequence > 0
            AND char_length(hostname) BETWEEN 1 AND 253
            AND char_length(os_id) BETWEEN 1 AND 64
            AND char_length(architecture) BETWEEN 1 AND 64
            AND boot_id IS NOT NULL
            AND octet_length(inventory_digest) = 32
        )
    ),
    CONSTRAINT devices_package_snapshot_shape CHECK (
        (package_snapshot_sequence = 0 AND NOT package_snapshot_complete)
        OR package_snapshot_sequence > 0
    ),
    CONSTRAINT devices_revoke_shape CHECK (
        (state <> 'revoked' AND revoked_at IS NULL AND revoked_by IS NULL AND revoke_reason = '')
        OR (state = 'revoked' AND revoked_at IS NOT NULL AND revoked_by IS NOT NULL AND revoke_reason ~ '\S')
    )
);

CREATE TABLE enrollment_generations (
    id uuid PRIMARY KEY,
    device_id uuid NOT NULL REFERENCES devices (id) ON DELETE RESTRICT,
    state text NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT enrollment_generations_state_check CHECK (state IN ('pending', 'active', 'revoked'))
);

ALTER TABLE devices
    ADD CONSTRAINT devices_current_generation_fk
    FOREIGN KEY (current_generation_id) REFERENCES enrollment_generations (id) ON DELETE RESTRICT;

ALTER TABLE enrollment_grants
    ADD CONSTRAINT enrollment_grants_device_fk
    FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE RESTRICT;

CREATE TABLE device_certificates (
    id uuid PRIMARY KEY,
    device_id uuid NOT NULL REFERENCES devices (id) ON DELETE RESTRICT,
    generation_id uuid NOT NULL REFERENCES enrollment_generations (id) ON DELETE RESTRICT,
    serial bytea NOT NULL,
    fingerprint bytea NOT NULL,
    public_key_fingerprint bytea NOT NULL,
    pem text NOT NULL,
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    issued_at timestamptz NOT NULL,
    status text NOT NULL,
    revoked_at timestamptz,
    revoke_reason text NOT NULL DEFAULT '',
    overlap_until timestamptz,
    CONSTRAINT device_certificates_serial_unique UNIQUE (serial),
    CONSTRAINT device_certificates_fingerprint_unique UNIQUE (fingerprint),
    CONSTRAINT device_certificates_serial_len CHECK (octet_length(serial) BETWEEN 1 AND 20),
    CONSTRAINT device_certificates_fingerprint_len CHECK (octet_length(fingerprint) = 32),
    CONSTRAINT device_certificates_pubkey_len CHECK (octet_length(public_key_fingerprint) = 32),
    CONSTRAINT device_certificates_pem_len CHECK (char_length(pem) BETWEEN 1 AND 16384),
    CONSTRAINT device_certificates_window CHECK (not_after > not_before),
    CONSTRAINT device_certificates_status_check CHECK (status IN ('active', 'overlapping', 'revoked')),
    CONSTRAINT device_certificates_revoke_reason_len CHECK (char_length(revoke_reason) <= 512),
    CONSTRAINT device_certificates_overlap_shape CHECK (
        (status = 'overlapping' AND overlap_until IS NOT NULL)
        OR status <> 'overlapping'
    ),
    CONSTRAINT device_certificates_revoked_shape CHECK (
        (status = 'revoked' AND revoked_at IS NOT NULL)
        OR (status <> 'revoked' AND revoked_at IS NULL)
    )
);

CREATE UNIQUE INDEX device_certificates_one_active
    ON device_certificates (generation_id)
    WHERE status = 'active';

CREATE UNIQUE INDEX device_certificates_one_overlapping
    ON device_certificates (generation_id)
    WHERE status = 'overlapping';

CREATE TABLE device_packages (
    device_id uuid NOT NULL REFERENCES devices (id) ON DELETE RESTRICT,
    position integer NOT NULL,
    name text NOT NULL,
    version text NOT NULL,
    architecture text NOT NULL,
    manager text NOT NULL,
    PRIMARY KEY (device_id, position),
    CONSTRAINT device_packages_position_check CHECK (position >= 0 AND position < 500),
    CONSTRAINT device_packages_name_len CHECK (char_length(name) BETWEEN 1 AND 512),
    CONSTRAINT device_packages_version_len CHECK (char_length(version) BETWEEN 1 AND 2048),
    CONSTRAINT device_packages_architecture_len CHECK (char_length(architecture) <= 64),
    CONSTRAINT device_packages_manager_len CHECK (char_length(manager) BETWEEN 1 AND 64)
);

-- Zero UUIDs and epoch mean "unset". Completed grant issuance always replaces them.
-- The plaintext grant secret is never stored.
CREATE TABLE device_admin_requests (
    actor_id uuid NOT NULL REFERENCES principals (id) ON DELETE RESTRICT,
    method text NOT NULL,
    request_id uuid NOT NULL,
    request_digest bytea NOT NULL,
    grant_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    device_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    expires_at timestamptz NOT NULL DEFAULT 'epoch',
    completed boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (actor_id, method, request_id),
    CONSTRAINT device_admin_requests_digest_len CHECK (octet_length(request_digest) = 32),
    CONSTRAINT device_admin_requests_method_len CHECK (char_length(method) BETWEEN 1 AND 128),
    CONSTRAINT device_admin_requests_completed_grant CHECK (
        method <> 'CreateEnrollmentGrant'
        OR NOT completed
        OR (
            grant_id <> '00000000-0000-0000-0000-000000000000'
            AND expires_at > 'epoch'
        )
    )
);

CREATE INDEX devices_list_idx ON devices (enrolled_at DESC, id DESC);

-- +goose Down

DROP TABLE IF EXISTS device_packages;
DROP TABLE IF EXISTS device_certificates;
DROP TABLE IF EXISTS device_admin_requests;
ALTER TABLE IF EXISTS enrollment_grants DROP CONSTRAINT IF EXISTS enrollment_grants_device_fk;
DROP TABLE IF EXISTS enrollment_grants;
ALTER TABLE IF EXISTS devices DROP CONSTRAINT IF EXISTS devices_current_generation_fk;
DROP TABLE IF EXISTS enrollment_generations;
DROP TABLE IF EXISTS devices;
