-- Protected authority and trust retain independent revisions. Service actions,
-- monotonic resource floors and capacity accounting commit in one transaction.
-- Only this schema is supported; unexpected versions or damage are held.
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

CREATE TABLE service_actions (
    action_id TEXT PRIMARY KEY NOT NULL,
    deployment_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    enrollment_generation TEXT NOT NULL,
    unit TEXT NOT NULL,
    resource_sequence INTEGER NOT NULL CHECK (resource_sequence > 0),
    revision INTEGER NOT NULL CHECK (revision > 0),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 8),
    record BLOB NOT NULL CHECK (length(record) BETWEEN 1 AND 131072),
    read_only_success INTEGER NOT NULL CHECK (read_only_success IN (0, 1) AND (read_only_success = 0 OR state = 4)),
    UNIQUE (deployment_id, device_id, enrollment_generation, unit, resource_sequence)
) STRICT;
CREATE INDEX service_actions_read_only ON service_actions(read_only_success);

CREATE TABLE service_resource_floors (
    deployment_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    enrollment_generation TEXT NOT NULL,
    unit TEXT NOT NULL,
    resource_sequence INTEGER NOT NULL CHECK (resource_sequence > 0),
    action_id TEXT NOT NULL UNIQUE REFERENCES service_actions(action_id),
    PRIMARY KEY (deployment_id, device_id, enrollment_generation, unit)
) STRICT;

-- record_bytes is charged capacity: unfinished actions reserve their full
-- 128KiB lifecycle bound; terminal records retain only their serialized length.
CREATE TABLE service_action_usage (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    record_count INTEGER NOT NULL CHECK (record_count BETWEEN 0 AND 65536),
    record_bytes INTEGER NOT NULL CHECK (record_bytes BETWEEN 0 AND 268435456)
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

PRAGMA user_version = 1;
PRAGMA application_id = 1279872580;
