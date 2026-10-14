-- SPDX-License-Identifier: Apache-2.0

-- Unprivileged observation spool. Bounded metadata, counters and receipts only.
-- Package batch bytes live in owned collection directories, never in this database.
-- Only the current schema is supported; unexpected versions require recovery.

CREATE TABLE scope (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    deployment TEXT NOT NULL CHECK (length(deployment) = 36),
    device TEXT NOT NULL CHECK (length(device) = 36),
    generation TEXT NOT NULL CHECK (length(generation) = 36),
    host_allocated INTEGER NOT NULL CHECK (host_allocated >= 0),
    package_allocated INTEGER NOT NULL CHECK (package_allocated >= 0),
    host_highwater INTEGER NOT NULL CHECK (host_highwater >= 0),
    package_highwater INTEGER NOT NULL CHECK (package_highwater >= 0),
    synced INTEGER NOT NULL CHECK (synced IN (0, 1)),
    loss_recovered INTEGER NOT NULL CHECK (loss_recovered IN (0, 1))
) STRICT;

CREATE TABLE host_slot (
    kind INTEGER PRIMARY KEY CHECK (kind IN (1, 2)),
    sequence INTEGER NOT NULL CHECK ((kind = 1 AND sequence > 0) OR (kind = 2 AND sequence = 0)),
    observation BLOB NOT NULL CHECK (length(observation) BETWEEN 1 AND 65536)
) STRICT;

CREATE TABLE package_slot (
    kind INTEGER PRIMARY KEY CHECK (kind IN (1, 2)),
    sequence INTEGER NOT NULL CHECK ((kind = 1 AND sequence > 0) OR (kind = 2 AND sequence = 0)),
    success INTEGER NOT NULL CHECK (success IN (0, 1)),
    status INTEGER NOT NULL CHECK (status BETWEEN 1 AND 7),
    backend TEXT NOT NULL CHECK (length(backend) <= 64),
    started_unix INTEGER NOT NULL,
    finished_unix INTEGER NOT NULL CHECK (finished_unix >= started_unix),
    snapshot_id TEXT NOT NULL CHECK (snapshot_id = '' OR length(snapshot_id) = 36),
    created_unix INTEGER NOT NULL CHECK (created_unix >= 0),
    collection_id TEXT NOT NULL CHECK (collection_id = '' OR length(collection_id) = 36),
    begin_accepted INTEGER NOT NULL CHECK (begin_accepted IN (0, 1)),
    accepted_mask BLOB NOT NULL CHECK (length(accepted_mask) = 64),
    manifest BLOB NOT NULL CHECK (length(manifest) <= 65536),
    CHECK ((success = 1) = (status = 1)),
    CHECK (
        (success = 0 AND snapshot_id = '' AND collection_id = '' AND length(manifest) = 0 AND begin_accepted = 0)
        OR (success = 1 AND kind = 2 AND snapshot_id = '' AND length(manifest) = 0 AND begin_accepted = 0)
        OR (success = 1 AND kind = 1 AND length(snapshot_id) = 36 AND length(manifest) BETWEEN 1 AND 65536)
    )
) STRICT;

CREATE TABLE owned_dir (
    collection_id TEXT PRIMARY KEY CHECK (length(collection_id) = 36),
    referenced INTEGER NOT NULL CHECK (referenced IN (0, 1)),
    byte_size INTEGER NOT NULL CHECK (byte_size >= 0 AND byte_size <= 67108864)
) STRICT;

CREATE TABLE batch_descriptor (
    collection_id TEXT NOT NULL REFERENCES owned_dir (collection_id),
    batch_index INTEGER NOT NULL CHECK (batch_index BETWEEN 0 AND 511),
    sha256 BLOB NOT NULL CHECK (length(sha256) = 32),
    record_count INTEGER NOT NULL CHECK (record_count BETWEEN 1 AND 500),
    encoded_size INTEGER NOT NULL CHECK (encoded_size BETWEEN 1 AND 786432),
    PRIMARY KEY (collection_id, batch_index)
) STRICT;

CREATE TABLE recovery (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 64)
) STRICT;

PRAGMA user_version = 1;
PRAGMA application_id = 1397776204;
