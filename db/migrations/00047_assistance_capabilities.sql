-- SPDX-License-Identifier: Apache-2.0

-- +goose Up
-- Only bounded capability/display projection and operation identity are durable.
-- Clipboard and notification text, including read results, never enter SQL.
ALTER TABLE assistance_sessions
    ADD COLUMN authorized_until timestamptz NOT NULL DEFAULT 'epoch',
    ADD COLUMN requested_capabilities bytea NOT NULL DEFAULT '' CHECK (octet_length(requested_capabilities) <= 64),
    ADD COLUMN effective_capabilities bytea NOT NULL DEFAULT '' CHECK (octet_length(effective_capabilities) <= 64),
    ADD COLUMN capability_projection bytea NOT NULL DEFAULT '' CHECK (octet_length(capability_projection) <= 8192);

CREATE TABLE assistance_policies (
    device_id uuid PRIMARY KEY REFERENCES devices(id),
    policy bytea NOT NULL CHECK (octet_length(policy) <= 64)
);
CREATE TABLE assistance_policy_requests (
    request_id uuid PRIMARY KEY,
    device_id uuid NOT NULL REFERENCES devices(id),
    operator_id uuid NOT NULL REFERENCES principals(id),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    policy bytea NOT NULL CHECK (octet_length(policy) <= 64)
);
CREATE INDEX assistance_policy_requests_device_idx ON assistance_policy_requests(device_id);
CREATE INDEX assistance_policy_requests_operator_idx ON assistance_policy_requests(operator_id);

CREATE TABLE assistance_commands (
    request_id uuid PRIMARY KEY,
    session_id uuid NOT NULL REFERENCES assistance_sessions(id),
    device_id uuid NOT NULL REFERENCES devices(id),
    operator_id uuid NOT NULL REFERENCES principals(id),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    kind smallint NOT NULL CHECK (kind BETWEEN 1 AND 5),
    policy bytea NOT NULL CHECK (octet_length(policy) <= 64),
    byte_count integer NOT NULL DEFAULT 0 CHECK (byte_count BETWEEN 0 AND 16384),
    special_key smallint NOT NULL DEFAULT 0 CHECK (special_key BETWEEN 0 AND 4),
    display_id text NOT NULL DEFAULT '' CHECK (display_id ~ '^[A-Za-z0-9_.-]{0,64}$'),
    deadline timestamptz NOT NULL,
    status smallint NOT NULL CHECK (status BETWEEN 1 AND 5),
    reason text NOT NULL DEFAULT '' CHECK (reason ~ '^[a-z0-9_]{0,64}$'),
    completed_at timestamptz,
    CHECK ((status = 1) = (completed_at IS NULL))
);
CREATE UNIQUE INDEX assistance_commands_one_pending ON assistance_commands(session_id) WHERE status = 1;
CREATE INDEX assistance_commands_operator_idx ON assistance_commands(operator_id);
CREATE INDEX assistance_commands_session_idx ON assistance_commands(session_id);
CREATE INDEX assistance_commands_device_idx ON assistance_commands(device_id);

-- +goose Down
DROP TABLE assistance_commands;
DROP TABLE assistance_policy_requests;
DROP TABLE assistance_policies;
ALTER TABLE assistance_sessions DROP COLUMN capability_projection, DROP COLUMN effective_capabilities, DROP COLUMN requested_capabilities, DROP COLUMN authorized_until;
