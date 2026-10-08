-- +goose Up

-- Staged package snapshots replace the G1 whole-report inventory. Host and package
-- sequences are independent and generation-scoped. Heartbeats allocate neither.
-- Compact receipts last 90 days (2160 hours) from first acceptance. Open uploads
-- last 24 hours from first acceptance. Neither interval is extended by retries.

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
    PRIMARY KEY (snapshot_id, position),
    CONSTRAINT snapshot_packages_position_check CHECK (position BETWEEN 0 AND 99999),
    CONSTRAINT snapshot_packages_name_len CHECK (char_length(name) BETWEEN 1 AND 512),
    CONSTRAINT snapshot_packages_version_len CHECK (char_length(version) BETWEEN 1 AND 2048),
    CONSTRAINT snapshot_packages_architecture_len CHECK (char_length(architecture) <= 64),
    CONSTRAINT snapshot_packages_manager_len CHECK (char_length(manager) BETWEEN 1 AND 64)
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

ALTER TABLE enrollment_generations
    ADD COLUMN host_sequence bigint NOT NULL DEFAULT 0,
    ADD COLUMN package_sequence bigint NOT NULL DEFAULT 0,
    ADD COLUMN last_host_admission_at timestamptz,
    ADD COLUMN last_package_admission_at timestamptz,
    ADD COLUMN current_snapshot_id uuid,
    ADD CONSTRAINT enrollment_generations_host_sequence_check CHECK (host_sequence BETWEEN 0 AND 9223372036854775807),
    ADD CONSTRAINT enrollment_generations_package_sequence_check CHECK (package_sequence BETWEEN 0 AND 9223372036854775807);

ALTER TABLE devices
    ADD COLUMN open_snapshot_id uuid,
    ADD COLUMN reserved_inventory_bytes bigint NOT NULL DEFAULT 0,
    ADD COLUMN published_sequence bigint NOT NULL DEFAULT 0,
    ADD COLUMN host_received_at timestamptz,
    ADD COLUMN package_attempt_received_at timestamptz,
    ADD COLUMN snapshot_received_at timestamptz,
    ADD CONSTRAINT devices_reserved_inventory_check CHECK (reserved_inventory_bytes BETWEEN 0 AND 268435456),
    ADD CONSTRAINT devices_published_sequence_check CHECK (published_sequence BETWEEN 0 AND 9223372036854775807);

-- Preserve G1 high-water marks. Typed host rows are not fabricated: the old
-- columns were successful strings, not per-field availability.
UPDATE enrollment_generations g
SET host_sequence = d.inventory_sequence,
    package_sequence = d.package_snapshot_sequence
FROM devices d
WHERE d.current_generation_id = g.id;

WITH migrated AS (
    INSERT INTO package_snapshots (
        id, device_id, generation_id, sequence, state, manifest_digest, manifest_bytes,
        created_at, started_at, finished_at, accepted_at, open_until, receipt_expires_at,
        committed_at, backend, package_count, batch_count, encoded_bytes, metadata_bytes,
        reserved_bytes, bulk_retained
    )
    SELECT
        gen_random_uuid(),
        d.id,
        d.current_generation_id,
        d.package_snapshot_sequence,
        'committed',
        decode('684afe3598e23a380f6a7f9783e24cbc284453b3edc3f59c24fb2160ca38df39', 'hex'),
        convert_to('lindm-g1-migrated-snapshot', 'UTF8'),
        COALESCE(d.last_seen_at, d.enrolled_at),
        COALESCE(d.last_seen_at, d.enrolled_at),
        COALESCE(d.last_seen_at, d.enrolled_at),
        COALESCE(d.last_seen_at, d.enrolled_at),
        COALESCE(d.last_seen_at, d.enrolled_at) + interval '24 hours',
        COALESCE(d.last_seen_at, d.enrolled_at) + interval '2160 hours',
        COALESCE(d.last_seen_at, d.enrolled_at),
        '',
        (SELECT count(*)::integer FROM device_packages p WHERE p.device_id = d.id),
        0,
        (
            SELECT coalesce(sum(octet_length(p.name) + octet_length(p.version) + octet_length(p.architecture) + octet_length(p.manager) + 32), 0)
            FROM device_packages p WHERE p.device_id = d.id
        ),
        1024,
        (
            SELECT coalesce(sum(octet_length(p.name) + octet_length(p.version) + octet_length(p.architecture) + octet_length(p.manager) + 32), 0) + 1024
            FROM device_packages p WHERE p.device_id = d.id
        ),
        true
    FROM devices d
    WHERE d.package_snapshot_complete
      AND d.current_generation_id IS NOT NULL
      AND d.package_snapshot_sequence > 0
    RETURNING id, device_id, generation_id, sequence, started_at, finished_at, accepted_at, manifest_digest, backend, reserved_bytes
),
copied AS (
    INSERT INTO snapshot_packages (snapshot_id, position, name, version, architecture, manager)
    SELECT m.id, p.position, p.name, p.version, p.architecture, p.manager
    FROM migrated m
    JOIN device_packages p ON p.device_id = m.device_id
    RETURNING snapshot_id
),
attempts AS (
    INSERT INTO package_attempts (
        generation_id, sequence, started_at, finished_at, received_at, status, backend, snapshot_id, digest
    )
    SELECT m.generation_id, m.sequence, m.started_at, m.finished_at, m.accepted_at, 1, m.backend, m.id, m.manifest_digest
    FROM migrated m
    RETURNING generation_id
)
UPDATE enrollment_generations g
SET current_snapshot_id = m.id
FROM migrated m
WHERE g.id = m.generation_id;

UPDATE devices d
SET published_sequence = s.sequence,
    snapshot_received_at = s.accepted_at,
    package_attempt_received_at = s.accepted_at,
    reserved_inventory_bytes = s.reserved_bytes
FROM package_snapshots s
WHERE s.device_id = d.id;

UPDATE inventory_reservation
SET reserved_bytes = (SELECT coalesce(sum(reserved_bytes), 0) FROM package_snapshots);

ALTER TABLE package_attempts
    ADD CONSTRAINT package_attempts_snapshot_fk
    FOREIGN KEY (snapshot_id) REFERENCES package_snapshots (id) ON DELETE RESTRICT;

ALTER TABLE enrollment_generations
    ADD CONSTRAINT enrollment_generations_current_snapshot_fk
    FOREIGN KEY (current_snapshot_id) REFERENCES package_snapshots (id) ON DELETE RESTRICT;

ALTER TABLE devices
    ADD CONSTRAINT devices_open_snapshot_fk
    FOREIGN KEY (open_snapshot_id) REFERENCES package_snapshots (id) ON DELETE RESTRICT;

ALTER TABLE devices DROP CONSTRAINT devices_sequence_bounds;
ALTER TABLE devices DROP CONSTRAINT devices_inventory_shape;
ALTER TABLE devices DROP CONSTRAINT devices_package_snapshot_shape;
ALTER TABLE devices DROP CONSTRAINT devices_os_version_len;

ALTER TABLE devices
    DROP COLUMN inventory_sequence,
    DROP COLUMN inventory_digest,
    DROP COLUMN boot_id,
    DROP COLUMN package_snapshot_sequence,
    DROP COLUMN package_snapshot_complete;

ALTER TABLE devices
    ADD CONSTRAINT devices_hostname_len CHECK (char_length(hostname) <= 4096),
    ADD CONSTRAINT devices_os_id_len CHECK (char_length(os_id) <= 4096),
    ADD CONSTRAINT devices_os_version_len CHECK (char_length(os_version) <= 4096),
    ADD CONSTRAINT devices_architecture_len CHECK (char_length(architecture) <= 4096);

DROP TABLE device_packages;

-- +goose Down

-- Not a data-preserving rollback. G1 inventory columns return empty.
ALTER TABLE devices DROP CONSTRAINT devices_open_snapshot_fk;
ALTER TABLE enrollment_generations DROP CONSTRAINT enrollment_generations_current_snapshot_fk;
ALTER TABLE package_attempts DROP CONSTRAINT package_attempts_snapshot_fk;

DROP TABLE package_page_cursors;
DROP TABLE package_attempts;
DROP TABLE host_observations;
DROP TABLE snapshot_packages;
DROP TABLE snapshot_batches;
DROP TABLE package_snapshots;
DROP TABLE inventory_reservation;

ALTER TABLE devices DROP CONSTRAINT devices_reserved_inventory_check;
ALTER TABLE devices DROP CONSTRAINT devices_published_sequence_check;
ALTER TABLE devices DROP CONSTRAINT devices_hostname_len;
ALTER TABLE devices DROP CONSTRAINT devices_os_id_len;
ALTER TABLE devices DROP CONSTRAINT devices_os_version_len;
ALTER TABLE devices DROP CONSTRAINT devices_architecture_len;

ALTER TABLE devices
    DROP COLUMN open_snapshot_id,
    DROP COLUMN reserved_inventory_bytes,
    DROP COLUMN published_sequence,
    DROP COLUMN host_received_at,
    DROP COLUMN package_attempt_received_at,
    DROP COLUMN snapshot_received_at;

ALTER TABLE enrollment_generations
    DROP CONSTRAINT enrollment_generations_host_sequence_check,
    DROP CONSTRAINT enrollment_generations_package_sequence_check,
    DROP COLUMN host_sequence,
    DROP COLUMN package_sequence,
    DROP COLUMN last_host_admission_at,
    DROP COLUMN last_package_admission_at,
    DROP COLUMN current_snapshot_id;

UPDATE devices
SET hostname = '', os_id = '', os_version = '', architecture = '';

ALTER TABLE devices
    ADD COLUMN inventory_sequence bigint NOT NULL DEFAULT 0,
    ADD COLUMN inventory_digest bytea,
    ADD COLUMN boot_id uuid,
    ADD COLUMN package_snapshot_sequence bigint NOT NULL DEFAULT 0,
    ADD COLUMN package_snapshot_complete boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT devices_sequence_bounds CHECK (
        inventory_sequence >= 0
        AND inventory_sequence <= 9223372036854775807
        AND package_snapshot_sequence >= 0
        AND package_snapshot_sequence <= inventory_sequence
    ),
    ADD CONSTRAINT devices_os_version_len CHECK (char_length(os_version) <= 128),
    ADD CONSTRAINT devices_inventory_shape CHECK (
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
    ADD CONSTRAINT devices_package_snapshot_shape CHECK (
        (package_snapshot_sequence = 0 AND NOT package_snapshot_complete)
        OR package_snapshot_sequence > 0
    );

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
