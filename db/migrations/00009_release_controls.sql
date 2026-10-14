-- SPDX-License-Identifier: Apache-2.0

-- +goose Up
-- A singleton row establishes one lock order for global release policy/publication.
CREATE TABLE release_control_lock (id boolean PRIMARY KEY CHECK (id));
INSERT INTO release_control_lock VALUES (true);
CREATE TABLE released_agent_series (
    major integer NOT NULL CHECK (major >= 0),
    minor integer NOT NULL CHECK (minor >= 0),
    released_at timestamptz NOT NULL,
    support_until timestamptz NOT NULL CHECK (support_until >= released_at + interval '90 days'),
    minimum_protocol integer NOT NULL CHECK (minimum_protocol > 0),
    maximum_protocol integer NOT NULL CHECK (maximum_protocol >= minimum_protocol),
    PRIMARY KEY (major, minor)
);
CREATE TABLE device_release_reports (
    generation_id uuid PRIMARY KEY REFERENCES enrollment_generations(id),
    session_epoch bigint NOT NULL CHECK (session_epoch > 0),
    agent_release text NOT NULL CHECK (length(agent_release) <= 128),
    protocol_version integer NOT NULL CHECK (protocol_version >= 0),
    reported_at timestamptz NOT NULL
);
CREATE TABLE release_rollout_requests (
    request_id uuid PRIMARY KEY,
    actor_id uuid NOT NULL REFERENCES principals(id),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    ring text NOT NULL CHECK (length(ring) <= 64 AND ring ~ '^[a-z][a-z0-9-]*$'),
    expected_generation bigint NOT NULL CHECK (expected_generation > 0),
    paused boolean NOT NULL,
    eligible_percentage integer NOT NULL CHECK (eligible_percentage BETWEEN 0 AND 100),
    reason text NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT now(),
    published_channel bytea CHECK (octet_length(published_channel) <= 1048576)
);
CREATE UNIQUE INDEX release_rollout_pending_ring ON release_rollout_requests(ring) WHERE published_channel IS NULL;
-- +goose Down
DROP TABLE release_rollout_requests;
DROP TABLE device_release_reports;
DROP TABLE released_agent_series;
DROP TABLE release_control_lock;
