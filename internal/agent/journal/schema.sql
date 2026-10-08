-- The protected journal stores one bounded authority record and one bounded
-- execution-trust record. Schema changes require an explicit reviewed
-- migration, never recreation.
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

PRAGMA user_version = 2;
PRAGMA application_id = 1279872580;
