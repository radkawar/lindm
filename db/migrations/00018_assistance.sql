-- +goose Up
-- Graphical remote assistance invitations. One row is one single-use support
-- session; SDP is signaling state, never credentials. State and end_cause use
-- the lindm.admin.v1.AssistanceState and lindm.agent.v1.AssistanceEndCause
-- numbers. Relay credentials are derived per process and never stored.
CREATE TABLE assistance_sessions (
    id uuid PRIMARY KEY,
    device_id uuid NOT NULL REFERENCES devices(id),
    generation_id uuid NOT NULL REFERENCES enrollment_generations(id),
    request_id uuid NOT NULL UNIQUE,
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    operator_id uuid NOT NULL REFERENCES principals(id) ON DELETE RESTRICT,
    operator_display text NOT NULL CHECK (char_length(operator_display) BETWEEN 1 AND 256),
    mode smallint NOT NULL CHECK (mode IN (1, 2)),
    reason text NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 512),
    target_username text NOT NULL DEFAULT '' CHECK (target_username ~ '^([a-zA-Z_][a-zA-Z0-9_.-]{0,31})?$'),
    state smallint NOT NULL CHECK (state BETWEEN 1 AND 6),
    created_at timestamptz NOT NULL,
    consent_deadline timestamptz NOT NULL CHECK (consent_deadline > created_at),
    ends_at timestamptz NOT NULL CHECK (ends_at > created_at AND ends_at <= created_at + interval '30 minutes'),
    prompted_at timestamptz,
    consented_at timestamptz,
    answered_at timestamptz,
    started_at timestamptz,
    ended_at timestamptz,
    end_cause smallint NOT NULL DEFAULT 0 CHECK (end_cause BETWEEN 0 AND 13),
    end_detail text NOT NULL DEFAULT '' CHECK (char_length(end_detail) <= 256),
    device_synced_at timestamptz,
    device_ended boolean NOT NULL DEFAULT false,
    control_granted boolean NOT NULL DEFAULT false CHECK (NOT control_granted OR mode = 2),
    local_username text NOT NULL DEFAULT '' CHECK (local_username ~ '^([a-zA-Z_][a-zA-Z0-9_.-]{0,31})?$'),
    local_uid bigint NOT NULL DEFAULT 0 CHECK (local_uid BETWEEN 0 AND 4294967295),
    local_logind_session text NOT NULL DEFAULT '' CHECK (local_logind_session ~ '^[A-Za-z0-9_.-]{0,64}$'),
    local_session_type text NOT NULL DEFAULT '' CHECK (local_session_type IN ('', 'wayland', 'x11')),
    local_desktop text NOT NULL DEFAULT '' CHECK (char_length(local_desktop) <= 64),
    offer_sdp text NOT NULL DEFAULT '' CHECK (octet_length(offer_sdp) <= 16384),
    offer_fingerprint text NOT NULL DEFAULT '' CHECK (char_length(offer_fingerprint) <= 128),
    answer_sdp text NOT NULL DEFAULT '' CHECK (octet_length(answer_sdp) <= 16384),
    answer_fingerprint text NOT NULL DEFAULT '' CHECK (char_length(answer_fingerprint) <= 128),
    CHECK ((state = 6) = (ended_at IS NOT NULL)),
    CHECK ((state = 6) = (end_cause <> 0)),
    CHECK (state = 6 OR NOT device_ended),
    CHECK (state IN (1, 6) OR local_logind_session <> ''),
    CHECK (state NOT IN (3, 4, 5) OR (consented_at IS NOT NULL AND offer_fingerprint <> '')),
    CHECK (state NOT IN (4, 5) OR (answered_at IS NOT NULL AND answer_fingerprint <> '')),
    CHECK (state <> 5 OR started_at IS NOT NULL)
);
-- At most one non-ended invitation per device, independent of handler checks.
CREATE UNIQUE INDEX assistance_sessions_one_open ON assistance_sessions(device_id) WHERE state <> 6;
CREATE INDEX assistance_sessions_recent ON assistance_sessions(device_id, created_at DESC, id DESC);
CREATE INDEX assistance_sessions_open ON assistance_sessions(created_at) WHERE state <> 6;
CREATE INDEX assistance_sessions_operator_id_idx ON assistance_sessions(operator_id);
CREATE INDEX assistance_sessions_generation_id_idx ON assistance_sessions(generation_id);

-- +goose Down
DROP TABLE assistance_sessions;
