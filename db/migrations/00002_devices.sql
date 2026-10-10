-- +goose Up

-- Device enrollment, certificates, inventory, and admin idempotency.
-- audit_events and principals are owned by 00001_identity.sql.
-- Text bounds match the annotated protobuf contracts. Pending devices have
-- empty inventory columns until the first accepted observation.

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
    open_snapshot_id uuid,
    reserved_inventory_bytes bigint NOT NULL DEFAULT 0,
    published_sequence bigint NOT NULL DEFAULT 0,
    host_received_at timestamptz,
    package_attempt_received_at timestamptz,
    snapshot_received_at timestamptz,
    revoked_at timestamptz,
    revoked_by uuid REFERENCES principals (id) ON DELETE RESTRICT,
    revoke_reason text NOT NULL DEFAULT '',
    metadata jsonb NOT NULL DEFAULT '{}',
    owner_principal_id uuid REFERENCES principals (id) ON DELETE RESTRICT,
    CONSTRAINT devices_metadata_object CHECK (jsonb_typeof(metadata) = 'object' AND octet_length(metadata::text) <= 262144),
    CONSTRAINT devices_state_check CHECK (state IN ('pending', 'active', 'recovery_hold', 'revoked')),
    CONSTRAINT devices_hostname_len CHECK (char_length(hostname) <= 4096),
    CONSTRAINT devices_os_id_len CHECK (char_length(os_id) <= 4096),
    CONSTRAINT devices_os_version_len CHECK (char_length(os_version) <= 4096),
    CONSTRAINT devices_architecture_len CHECK (char_length(architecture) <= 4096),
    CONSTRAINT devices_reserved_inventory_check CHECK (reserved_inventory_bytes BETWEEN 0 AND 268435456),
    CONSTRAINT devices_published_sequence_check CHECK (published_sequence BETWEEN 0 AND 9223372036854775807),
    CONSTRAINT devices_revoke_reason_len CHECK (char_length(revoke_reason) <= 512),
    CONSTRAINT devices_revoke_shape CHECK (
        (state <> 'revoked' AND revoked_at IS NULL AND revoked_by IS NULL AND revoke_reason = '')
        OR (state = 'revoked' AND revoked_at IS NOT NULL AND revoked_by IS NOT NULL AND revoke_reason ~ '\S')
    )
);

CREATE TABLE device_labels (
    device_id uuid NOT NULL REFERENCES devices (id) ON DELETE RESTRICT,
    label text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 64),
    PRIMARY KEY (device_id, label)
);
CREATE INDEX device_labels_search_idx ON device_labels (label, device_id);
CREATE INDEX devices_metadata_search_idx ON devices USING gin (metadata jsonb_path_ops);
CREATE INDEX devices_os_search_idx ON devices (os_id, os_version, enrolled_at DESC, id DESC);
CREATE INDEX devices_seen_search_idx ON devices (last_seen_at);

-- Serializes definition changes with metadata writes, including new keys.
CREATE TABLE inventory_metadata_lock (
    singleton boolean PRIMARY KEY CHECK (singleton)
);
INSERT INTO inventory_metadata_lock VALUES (true);

CREATE TABLE inventory_attribute_definitions (
    key text PRIMARY KEY CHECK (char_length(key) BETWEEN 1 AND 64),
    definition bytea NOT NULL CHECK (octet_length(definition) <= 65536)
);

CREATE TABLE device_search_cursors (
    id uuid PRIMARY KEY,
    actor_id uuid NOT NULL REFERENCES principals (id) ON DELETE RESTRICT,
    filter_digest bytea NOT NULL CHECK (octet_length(filter_digest) = 32),
    upper_enrolled_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX device_search_cursors_expiry_idx ON device_search_cursors (expires_at);

CREATE TABLE enrollment_generations (
    id uuid PRIMARY KEY,
    device_id uuid NOT NULL REFERENCES devices (id) ON DELETE RESTRICT,
    state text NOT NULL,
    created_at timestamptz NOT NULL,
    session_epoch bigint NOT NULL DEFAULT 0,
    renewal_issuance_count integer NOT NULL DEFAULT 0,
    host_sequence bigint NOT NULL DEFAULT 0,
    package_sequence bigint NOT NULL DEFAULT 0,
    last_host_admission_at timestamptz,
    last_package_admission_at timestamptz,
    current_snapshot_id uuid,
    CONSTRAINT enrollment_generations_state_check CHECK (state IN ('pending', 'active', 'recovery_hold', 'revoked')),
    CONSTRAINT enrollment_generations_session_bounds CHECK (session_epoch BETWEEN 0 AND 65536),
    CONSTRAINT enrollment_generations_renewal_bounds CHECK (renewal_issuance_count BETWEEN 0 AND 4096),
    CONSTRAINT enrollment_generations_host_sequence_check CHECK (host_sequence BETWEEN 0 AND 9223372036854775807),
    CONSTRAINT enrollment_generations_package_sequence_check CHECK (package_sequence BETWEEN 0 AND 9223372036854775807)
);

ALTER TABLE devices
    ADD CONSTRAINT devices_current_generation_fk
    FOREIGN KEY (current_generation_id) REFERENCES enrollment_generations (id) ON DELETE RESTRICT;

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

CREATE INDEX device_certificates_identity_keys
    ON device_certificates (device_id, public_key_fingerprint);

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
    device_id uuid REFERENCES devices (id) ON DELETE RESTRICT,
    transaction_id uuid,
    public_key_fingerprint bytea,
    certificate_id uuid REFERENCES device_certificates (id) ON DELETE RESTRICT,
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
            AND certificate_id IS NULL
        )
        OR (
            consumed_at IS NOT NULL
            AND device_id IS NOT NULL
            AND transaction_id IS NOT NULL
            AND octet_length(public_key_fingerprint) = 32
            AND certificate_id IS NOT NULL
        )
    ),
    CONSTRAINT enrollment_grants_revoke_shape CHECK (
        (revoked_at IS NULL AND revoked_by IS NULL AND revoke_reason = '')
        OR (revoked_at IS NOT NULL AND revoked_by IS NOT NULL AND revoke_reason ~ '\S' AND char_length(revoke_reason) <= 512)
    )
);

CREATE TABLE enrollment_recovery_grants (
    grant_id uuid PRIMARY KEY REFERENCES enrollment_grants (id) ON DELETE RESTRICT,
    device_id uuid NOT NULL REFERENCES devices (id) ON DELETE RESTRICT,
    expected_generation_id uuid NOT NULL REFERENCES enrollment_generations (id) ON DELETE RESTRICT,
    expected_revoked_at timestamptz CHECK (expected_revoked_at IS NULL OR isfinite(expected_revoked_at))
);

CREATE TABLE enrollment_installations (
    generation_id uuid PRIMARY KEY REFERENCES enrollment_generations (id) ON DELETE RESTRICT,
    installation_id uuid NOT NULL CHECK (installation_id <> '00000000-0000-0000-0000-000000000000'),
    boot_id uuid
);

-- Only a SHA-256 credential digest is retained. Assignment bytes are immutable.
CREATE TABLE provisioning_tokens (
    id uuid PRIMARY KEY,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    created_by uuid NOT NULL REFERENCES principals (id) ON DELETE RESTRICT,
    authorization_version bigint NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    max_uses integer NOT NULL CHECK (max_uses BETWEEN 1 AND 10000),
    used_count integer NOT NULL DEFAULT 0 CHECK (used_count BETWEEN 0 AND max_uses),
    approval_required boolean NOT NULL,
    assignment bytea NOT NULL CHECK (octet_length(assignment) <= 262144),
    reason text NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 512 AND reason ~ '\S'),
    revoked_at timestamptz,
    revoked_by uuid REFERENCES principals (id) ON DELETE RESTRICT,
    revoke_reason text NOT NULL DEFAULT '',
    CHECK (expires_at BETWEEN created_at + interval '60 seconds' AND created_at + interval '24 hours'),
    CHECK ((revoked_at IS NULL AND revoked_by IS NULL AND revoke_reason = '')
        OR (revoked_at IS NOT NULL AND revoked_by IS NOT NULL AND revoke_reason ~ '\S' AND char_length(revoke_reason) <= 512))
);

CREATE TABLE provisioning_enrollments (
    transaction_id uuid PRIMARY KEY,
    token_id uuid NOT NULL REFERENCES provisioning_tokens (id) ON DELETE RESTRICT,
    installation_id uuid NOT NULL UNIQUE,
    device_id uuid NOT NULL UNIQUE REFERENCES devices (id) ON DELETE RESTRICT,
    generation_id uuid NOT NULL UNIQUE REFERENCES enrollment_generations (id) ON DELETE RESTRICT,
    csr_pem bytea NOT NULL CHECK (octet_length(csr_pem) BETWEEN 64 AND 16384),
    csr_sha256 bytea NOT NULL CHECK (octet_length(csr_sha256) = 32),
    state text NOT NULL CHECK (state IN ('pending_approval', 'ready', 'rejected', 'revoked')),
    approval_id uuid,
    certificate_id uuid REFERENCES device_certificates (id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CHECK ((state = 'ready') = (certificate_id IS NOT NULL)),
    CHECK (state <> 'pending_approval' OR approval_id IS NOT NULL)
);
CREATE INDEX provisioning_enrollments_token_idx ON provisioning_enrollments (token_id, transaction_id);

CREATE TABLE offline_enrollment_authorizations (
    id uuid PRIMARY KEY,
    token_id uuid NOT NULL REFERENCES provisioning_tokens (id) ON DELETE RESTRICT,
    actor_id uuid NOT NULL REFERENCES principals (id) ON DELETE RESTRICT,
    request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
    authorization_envelope bytea NOT NULL CHECK (octet_length(authorization_envelope) <= 524288),
    expires_at timestamptz NOT NULL
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
        method NOT IN ('CreateEnrollmentGrant', 'CreateRecoveryEnrollmentGrant', 'CreateProvisioningToken')
        OR NOT completed
        OR (
            grant_id <> '00000000-0000-0000-0000-000000000000'
            AND expires_at > 'epoch'
        )
    )
);

CREATE INDEX devices_list_idx ON devices (enrolled_at DESC, id DESC);

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

-- Host and package sequences are independent and generation-scoped. Heartbeats
-- allocate neither. Receipts last 90 days; uploads last 24 hours from acceptance.
CREATE TABLE inventory_reservation (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    reserved_bytes bigint NOT NULL CHECK (reserved_bytes >= 0)
);

INSERT INTO inventory_reservation (reserved_bytes) VALUES (0);

CREATE TABLE package_snapshots (
    id uuid PRIMARY KEY,
    device_id uuid NOT NULL REFERENCES devices (id) ON DELETE RESTRICT,
    generation_id uuid NOT NULL REFERENCES enrollment_generations (id) ON DELETE RESTRICT,
    sequence bigint NOT NULL,
    state text NOT NULL,
    manifest_digest bytea NOT NULL,
    manifest_bytes bytea NOT NULL,
    created_at timestamptz NOT NULL,
    started_at timestamptz NOT NULL,
    finished_at timestamptz NOT NULL,
    accepted_at timestamptz NOT NULL,
    open_until timestamptz NOT NULL,
    receipt_expires_at timestamptz NOT NULL,
    committed_at timestamptz,
    superseded_at timestamptz,
    backend text NOT NULL,
    package_count integer NOT NULL,
    batch_count integer NOT NULL,
    encoded_bytes bigint NOT NULL,
    metadata_bytes bigint NOT NULL,
    reserved_bytes bigint NOT NULL,
    bulk_retained boolean NOT NULL,
    CONSTRAINT package_snapshots_sequence_check CHECK (sequence BETWEEN 1 AND 9223372036854775807),
    CONSTRAINT package_snapshots_state_check CHECK (state IN ('staging', 'committed', 'superseded', 'expired')),
    CONSTRAINT package_snapshots_digest_len CHECK (octet_length(manifest_digest) = 32),
    CONSTRAINT package_snapshots_manifest_len CHECK (octet_length(manifest_bytes) BETWEEN 1 AND 65536),
    CONSTRAINT package_snapshots_backend_len CHECK (char_length(backend) <= 64),
    CONSTRAINT package_snapshots_counts CHECK (
        package_count BETWEEN 0 AND 100000
        AND batch_count BETWEEN 0 AND 512
        AND encoded_bytes BETWEEN 0 AND 67108864
        AND metadata_bytes >= 0
        AND reserved_bytes >= 0
    ),
    CONSTRAINT package_snapshots_time_order CHECK (finished_at >= started_at),
    CONSTRAINT package_snapshots_open_ttl CHECK (open_until = accepted_at + interval '24 hours'),
    CONSTRAINT package_snapshots_receipt_ttl CHECK (receipt_expires_at = accepted_at + interval '2160 hours'),
    CONSTRAINT package_snapshots_state_shape CHECK (
        (state = 'staging' AND committed_at IS NULL AND superseded_at IS NULL AND bulk_retained)
        OR (state = 'committed' AND committed_at IS NOT NULL AND superseded_at IS NULL AND bulk_retained)
        OR (state = 'superseded' AND superseded_at IS NOT NULL)
        OR (state = 'expired' AND committed_at IS NULL AND superseded_at IS NULL AND NOT bulk_retained)
    ),
    CONSTRAINT package_snapshots_generation_sequence_unique UNIQUE (generation_id, sequence)
);

CREATE UNIQUE INDEX package_snapshots_one_staging
    ON package_snapshots (device_id)
    WHERE state = 'staging';

CREATE UNIQUE INDEX package_snapshots_one_committed
    ON package_snapshots (device_id)
    WHERE state = 'committed';

CREATE INDEX package_snapshots_device_idx ON package_snapshots (device_id, state);

CREATE TABLE snapshot_batches (
    snapshot_id uuid NOT NULL REFERENCES package_snapshots (id) ON DELETE RESTRICT,
    batch_index integer NOT NULL,
    digest bytea NOT NULL,
    record_count integer NOT NULL,
    encoded_size integer NOT NULL,
    first_position integer NOT NULL,
    stored boolean NOT NULL,
    PRIMARY KEY (snapshot_id, batch_index),
    CONSTRAINT snapshot_batches_index_check CHECK (batch_index BETWEEN 0 AND 511),
    CONSTRAINT snapshot_batches_digest_len CHECK (octet_length(digest) = 32),
    CONSTRAINT snapshot_batches_count_check CHECK (record_count BETWEEN 1 AND 500),
    CONSTRAINT snapshot_batches_size_check CHECK (encoded_size BETWEEN 1 AND 786432),
    CONSTRAINT snapshot_batches_position_check CHECK (first_position BETWEEN 0 AND 99999)
);

CREATE TABLE snapshot_packages (
    snapshot_id uuid NOT NULL REFERENCES package_snapshots (id) ON DELETE RESTRICT,
    position integer NOT NULL,
    name text NOT NULL,
    version text NOT NULL,
    architecture text NOT NULL,
    manager text NOT NULL,
    source_name text NOT NULL DEFAULT '',
    source_version text NOT NULL DEFAULT '',
    module_status integer NOT NULL DEFAULT 0,
    module_name text NOT NULL DEFAULT '',
    module_stream text NOT NULL DEFAULT '',
    module_version text NOT NULL DEFAULT '',
    module_context text NOT NULL DEFAULT '',
    PRIMARY KEY (snapshot_id, position),
    CONSTRAINT snapshot_packages_position_check CHECK (position BETWEEN 0 AND 99999),
    CONSTRAINT snapshot_packages_name_len CHECK (char_length(name) BETWEEN 1 AND 512),
    CONSTRAINT snapshot_packages_version_len CHECK (char_length(version) BETWEEN 1 AND 2048),
    CONSTRAINT snapshot_packages_architecture_len CHECK (char_length(architecture) <= 64),
    CONSTRAINT snapshot_packages_manager_len CHECK (char_length(manager) BETWEEN 1 AND 64),
    CONSTRAINT snapshot_packages_source_name_len CHECK (char_length(source_name) <= 512),
    CONSTRAINT snapshot_packages_source_version_len CHECK (char_length(source_version) <= 2048),
    CONSTRAINT snapshot_packages_source_shape CHECK ((source_name = '') = (source_version = '')),
    CONSTRAINT snapshot_packages_module_status CHECK (module_status BETWEEN 0 AND 7),
    CONSTRAINT snapshot_packages_module_name_len CHECK (char_length(module_name) <= 256),
    CONSTRAINT snapshot_packages_module_stream_len CHECK (char_length(module_stream) <= 256),
    CONSTRAINT snapshot_packages_module_version_shape CHECK (
        char_length(module_version) <= 32 AND module_version ~ '^[0-9]*$'
    ),
    CONSTRAINT snapshot_packages_module_context_len CHECK (char_length(module_context) <= 256),
    CONSTRAINT snapshot_packages_module_shape CHECK (
        (module_name = '' AND module_stream = '' AND module_version = '' AND module_context = '')
        OR (module_status = 1 AND module_name <> '' AND module_stream <> '' AND module_version <> '' AND module_context <> '')
    )
);

CREATE TABLE host_observations (
    generation_id uuid PRIMARY KEY REFERENCES enrollment_generations (id) ON DELETE RESTRICT,
    sequence bigint NOT NULL,
    started_at timestamptz NOT NULL,
    finished_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL,
    digest bytea NOT NULL,
    boot_id_status smallint NOT NULL,
    boot_id_value text NOT NULL,
    hostname_status smallint NOT NULL,
    hostname_value text NOT NULL,
    os_id_status smallint NOT NULL,
    os_id_value text NOT NULL,
    os_version_status smallint NOT NULL,
    os_version_value text NOT NULL,
    architecture_status smallint NOT NULL,
    architecture_value text NOT NULL,
    kernel_release_status smallint NOT NULL,
    kernel_release_value text NOT NULL,
    hardware_vendor_status smallint NOT NULL,
    hardware_vendor_value text NOT NULL,
    hardware_model_status smallint NOT NULL,
    hardware_model_value text NOT NULL,
    hardware_serial_status smallint NOT NULL,
    hardware_serial_value text NOT NULL,
    details bytea NOT NULL DEFAULT '',
    CONSTRAINT host_observations_details_len CHECK (octet_length(details) <= 786432),
    CONSTRAINT host_observations_sequence_check CHECK (sequence BETWEEN 1 AND 9223372036854775807),
    CONSTRAINT host_observations_digest_len CHECK (octet_length(digest) = 32),
    CONSTRAINT host_observations_time_order CHECK (finished_at >= started_at),
    CONSTRAINT host_observations_boot_id_status CHECK (boot_id_status BETWEEN 1 AND 7 AND ((boot_id_status = 1) = (boot_id_value <> '')) AND char_length(boot_id_value) <= 4096),
    CONSTRAINT host_observations_hostname_status CHECK (hostname_status BETWEEN 1 AND 7 AND ((hostname_status = 1) = (hostname_value <> '')) AND char_length(hostname_value) <= 4096),
    CONSTRAINT host_observations_os_id_status CHECK (os_id_status BETWEEN 1 AND 7 AND ((os_id_status = 1) = (os_id_value <> '')) AND char_length(os_id_value) <= 4096),
    CONSTRAINT host_observations_os_version_status CHECK (os_version_status BETWEEN 1 AND 7 AND ((os_version_status = 1) = (os_version_value <> '')) AND char_length(os_version_value) <= 4096),
    CONSTRAINT host_observations_architecture_status CHECK (architecture_status BETWEEN 1 AND 7 AND ((architecture_status = 1) = (architecture_value <> '')) AND char_length(architecture_value) <= 4096),
    CONSTRAINT host_observations_kernel_status CHECK (kernel_release_status BETWEEN 1 AND 7 AND ((kernel_release_status = 1) = (kernel_release_value <> '')) AND char_length(kernel_release_value) <= 4096),
    CONSTRAINT host_observations_vendor_status CHECK (hardware_vendor_status BETWEEN 1 AND 7 AND ((hardware_vendor_status = 1) = (hardware_vendor_value <> '')) AND char_length(hardware_vendor_value) <= 4096),
    CONSTRAINT host_observations_model_status CHECK (hardware_model_status BETWEEN 1 AND 7 AND ((hardware_model_status = 1) = (hardware_model_value <> '')) AND char_length(hardware_model_value) <= 4096),
    CONSTRAINT host_observations_serial_status CHECK (hardware_serial_status BETWEEN 1 AND 7 AND ((hardware_serial_status = 1) = (hardware_serial_value <> '')) AND char_length(hardware_serial_value) <= 4096)
);

CREATE TABLE package_attempts (
    generation_id uuid PRIMARY KEY REFERENCES enrollment_generations (id) ON DELETE RESTRICT,
    sequence bigint NOT NULL,
    started_at timestamptz NOT NULL,
    finished_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL,
    status smallint NOT NULL,
    backend text NOT NULL,
    snapshot_id uuid,
    digest bytea NOT NULL,
    CONSTRAINT package_attempts_sequence_check CHECK (sequence BETWEEN 1 AND 9223372036854775807),
    CONSTRAINT package_attempts_status_check CHECK (status BETWEEN 1 AND 7),
    CONSTRAINT package_attempts_backend_len CHECK (char_length(backend) <= 64),
    CONSTRAINT package_attempts_digest_len CHECK (octet_length(digest) = 32),
    CONSTRAINT package_attempts_time_order CHECK (finished_at >= started_at),
    CONSTRAINT package_attempts_success_shape CHECK ((status = 1) = (snapshot_id IS NOT NULL))
);

CREATE TABLE package_page_cursors (
    id uuid PRIMARY KEY,
    actor_id uuid NOT NULL REFERENCES principals (id) ON DELETE RESTRICT,
    device_id uuid NOT NULL REFERENCES devices (id) ON DELETE RESTRICT,
    generation_id uuid NOT NULL REFERENCES enrollment_generations (id) ON DELETE RESTRICT,
    snapshot_id uuid NOT NULL REFERENCES package_snapshots (id) ON DELETE RESTRICT,
    manager text NOT NULL,
    name_prefix text NOT NULL,
    next_position integer NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT package_page_cursors_manager_len CHECK (char_length(manager) <= 64),
    CONSTRAINT package_page_cursors_prefix_len CHECK (char_length(name_prefix) <= 512),
    CONSTRAINT package_page_cursors_position_check CHECK (next_position BETWEEN 0 AND 100000),
    CONSTRAINT package_page_cursors_expiry CHECK (expires_at = created_at + interval '15 minutes')
);

CREATE INDEX package_page_cursors_snapshot_idx ON package_page_cursors (snapshot_id, expires_at);

-- Cyclic references are installed after all tables in this domain exist.
ALTER TABLE package_attempts
    ADD CONSTRAINT package_attempts_snapshot_fk
    FOREIGN KEY (snapshot_id) REFERENCES package_snapshots (id) ON DELETE RESTRICT;

ALTER TABLE enrollment_generations
    ADD CONSTRAINT enrollment_generations_current_snapshot_fk
    FOREIGN KEY (current_snapshot_id) REFERENCES package_snapshots (id) ON DELETE RESTRICT;

ALTER TABLE devices
    ADD CONSTRAINT devices_open_snapshot_fk
    FOREIGN KEY (open_snapshot_id) REFERENCES package_snapshots (id) ON DELETE RESTRICT;

CREATE TABLE device_groups (
    id uuid PRIMARY KEY,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128)
);

CREATE TABLE device_group_memberships (
    group_id uuid NOT NULL REFERENCES device_groups (id) ON DELETE CASCADE,
    device_id uuid NOT NULL REFERENCES devices (id) ON DELETE RESTRICT,
    PRIMARY KEY (group_id, device_id)
);

CREATE INDEX device_group_memberships_device_idx ON device_group_memberships (device_id, group_id);

-- Scope dimensions intersect; separate scopes are alternatives. A scoped grant
-- never gains access to global resources through this device-only predicate.
-- +goose StatementBegin
CREATE FUNCTION device_scope_matches(target uuid, unrestricted boolean, scopes jsonb)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT unrestricted OR EXISTS (
        SELECT 1 FROM jsonb_array_elements(scopes) AS scope
        WHERE jsonb_typeof(scope) = 'object' AND
            (coalesce(jsonb_array_length(scope->'device_ids'), 0) = 0
                OR (scope->'device_ids') ? target::text)
            AND NOT EXISTS (
                SELECT 1 FROM jsonb_array_elements_text(coalesce(scope->'labels', '[]'::jsonb)) AS required(label)
                WHERE NOT EXISTS (
                    SELECT 1 FROM device_labels l
                    WHERE l.device_id = target AND l.label = required.label
                )
            )
            AND (coalesce(jsonb_array_length(scope->'group_ids'), 0) = 0
                OR EXISTS (
                    SELECT 1 FROM device_group_memberships m
                    WHERE m.device_id = target AND (scope->'group_ids') ? m.group_id::text
                ))
    );
$$;
-- +goose StatementEnd

-- +goose Down

DROP FUNCTION IF EXISTS device_scope_matches(uuid, boolean, jsonb);
DROP TABLE IF EXISTS offline_enrollment_authorizations, provisioning_enrollments, provisioning_tokens,
    enrollment_recovery_grants, enrollment_installations;
DROP TABLE IF EXISTS device_group_memberships, device_groups;

DROP TABLE IF EXISTS device_search_cursors, inventory_attribute_definitions, inventory_metadata_lock, device_labels,
    package_page_cursors, package_attempts, host_observations,
    snapshot_packages, snapshot_batches, package_snapshots, inventory_reservation,
    device_renewal_receipts, device_session_receipts, enrollment_grants,
    device_certificates, device_admin_requests, enrollment_generations, devices;
