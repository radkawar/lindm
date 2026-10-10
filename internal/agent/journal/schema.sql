-- Protected authority and trust retain independent revisions. Resource actions,
-- monotonic kind/key floors and capacity accounting commit in one transaction.
-- Only this schema is supported; older journals hold for re-provisioning.
CREATE TABLE executor_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    revision INTEGER NOT NULL CHECK (revision > 0),
    state BLOB NOT NULL CHECK (length(state) BETWEEN 1 AND 1048576)
) STRICT;

CREATE TABLE execution_trust (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    revision INTEGER NOT NULL CHECK (revision > 0),
    state BLOB NOT NULL CHECK (length(state) BETWEEN 1 AND 131072)
) STRICT;

CREATE TABLE resource_actions (
    action_id TEXT PRIMARY KEY NOT NULL,
    deployment_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    enrollment_generation TEXT NOT NULL,
    kind INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 24),
    canonical_key TEXT NOT NULL,
    resource_sequence INTEGER NOT NULL CHECK (resource_sequence > 0),
    revision INTEGER NOT NULL CHECK (revision > 0),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 9),
    record BLOB NOT NULL CHECK (length(record) BETWEEN 1 AND 1048576),
    read_only_terminal INTEGER NOT NULL CHECK (read_only_terminal IN (0, 1) AND (read_only_terminal = 0 OR state IN (4, 5))),
    UNIQUE (deployment_id, device_id, enrollment_generation, kind, canonical_key, resource_sequence)
) STRICT;
CREATE INDEX resource_actions_read_only ON resource_actions(read_only_terminal);

CREATE TABLE resource_floors (
    deployment_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    enrollment_generation TEXT NOT NULL,
    kind INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 24),
    canonical_key TEXT NOT NULL,
    resource_sequence INTEGER NOT NULL CHECK (resource_sequence > 0),
    action_id TEXT NOT NULL UNIQUE REFERENCES resource_actions(action_id),
    PRIMARY KEY (deployment_id, device_id, enrollment_generation, kind, canonical_key)
) STRICT;

-- Unfinished actions reserve their complete 1MiB lifecycle before admission.
CREATE TABLE resource_action_usage (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    record_count INTEGER NOT NULL CHECK (record_count BETWEEN 0 AND 65536),
    record_bytes INTEGER NOT NULL CHECK (record_bytes BETWEEN 0 AND 268435456)
) STRICT;

-- Never delete released ledgers: their revisions prevent ABA ownership claims.
-- Each ledger reserves 1MiB for baseline, before-effect and durable after-state.
CREATE TABLE resource_ownership (
    ledger_id INTEGER PRIMARY KEY,
    deployment_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    enrollment_generation TEXT NOT NULL,
    kind INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 24),
    canonical_key TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    record BLOB NOT NULL CHECK (length(record) BETWEEN 1 AND 1048576),
    UNIQUE (deployment_id, device_id, enrollment_generation, kind, canonical_key)
) STRICT;

CREATE TABLE resource_ownership_usage (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    record_count INTEGER NOT NULL CHECK (record_count BETWEEN 0 AND 256)
) STRICT;

-- Durable undo capacity is reserved before native preparation starts. It is
-- consumed by a typed claim or released when unclaimed work terminates.
CREATE TABLE resource_ownership_reservations (
    action_id TEXT PRIMARY KEY NOT NULL REFERENCES resource_actions(action_id),
    deployment_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    enrollment_generation TEXT NOT NULL,
    kind INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 24),
    canonical_key TEXT NOT NULL,
    UNIQUE (deployment_id, device_id, enrollment_generation, kind, canonical_key)
) STRICT;

-- Imperative actions are never evicted or replayed. Each admitted row reserves
-- its complete 128KiB lifecycle; admission caps serialized records at 256MiB.
CREATE TABLE device_actions (
    action_id TEXT PRIMARY KEY NOT NULL,
    deployment_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    enrollment_generation TEXT NOT NULL,
    action_sequence INTEGER NOT NULL CHECK (action_sequence > 0),
    revision INTEGER NOT NULL CHECK (revision > 0),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 9),
    record BLOB NOT NULL CHECK (length(record) BETWEEN 1 AND 131072),
    UNIQUE (deployment_id, device_id, enrollment_generation, action_sequence)
) STRICT;

CREATE TABLE device_action_usage (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    record_count INTEGER NOT NULL CHECK (record_count BETWEEN 0 AND 2048)
) STRICT;

-- Exact local shadow snapshots never leave this protected journal. Each retained
-- ledger reserves 2MiB; admission permits at most 128 ledgers (256MiB total).
CREATE TABLE account_locks (
    lock_action_id TEXT PRIMARY KEY NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    record BLOB NOT NULL CHECK (length(record) BETWEEN 1 AND 2097152)
) STRICT;

CREATE TABLE account_lock_owners (
    username TEXT PRIMARY KEY NOT NULL,
    uid INTEGER NOT NULL UNIQUE CHECK (uid > 0 AND uid <= 4294967295),
    lock_action_id TEXT NOT NULL REFERENCES account_locks(lock_action_id)
) STRICT;

CREATE TABLE account_lock_usage (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    record_count INTEGER NOT NULL CHECK (record_count BETWEEN 0 AND 128)
) STRICT;

-- Cancellation before delivery is denial-only. It does not advance a resource
-- floor or claim native evidence, but permanently fences late exact preparation.
CREATE TABLE resource_preparation_cancellations (
    action_id TEXT PRIMARY KEY NOT NULL,
    enrollment_generation TEXT NOT NULL,
    intent_sha256 BLOB NOT NULL CHECK (length(intent_sha256) = 32)
) STRICT;

PRAGMA user_version = 2;
PRAGMA application_id = 1279872580;
