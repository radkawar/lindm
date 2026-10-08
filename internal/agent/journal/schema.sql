-- Protected authority and trust retain independent revisions. Service actions,
-- monotonic resource floors and capacity accounting commit in one transaction.
-- Schema changes require explicit migration; damaged installations are held.
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
    UNIQUE (deployment_id, device_id, enrollment_generation, unit, resource_sequence)
) STRICT;

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

PRAGMA user_version = 3;
PRAGMA application_id = 1279872580;
