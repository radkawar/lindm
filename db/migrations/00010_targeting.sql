-- +goose Up

-- Dynamic targeting is not an RBAC membership source. Static targeting reuses
-- device_groups/device_group_memberships, labels and typed inventory metadata.
CREATE TABLE targeting_lock (singleton boolean PRIMARY KEY CHECK (singleton), revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0));
INSERT INTO targeting_lock(singleton) VALUES (true);
CREATE TABLE dynamic_target_groups (
    id uuid PRIMARY KEY,
    revision bigint NOT NULL CHECK (revision > 0),
    definition bytea NOT NULL CHECK (octet_length(definition) BETWEEN 1 AND 262144)
);
CREATE TABLE dynamic_target_group_revisions (
    group_id uuid NOT NULL REFERENCES dynamic_target_groups(id),
    revision bigint NOT NULL CHECK (revision > 0),
    definition bytea NOT NULL CHECK (octet_length(definition) BETWEEN 1 AND 262144),
    actor_id uuid NOT NULL REFERENCES principals(id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (group_id, revision)
);
CREATE TABLE target_assignments (
    id uuid PRIMARY KEY,
    revision bigint NOT NULL CHECK (revision > 0),
    definition bytea NOT NULL CHECK (octet_length(definition) BETWEEN 1 AND 262144),
    actor_id uuid NOT NULL REFERENCES principals(id)
);
CREATE TABLE target_assignment_revisions (
    assignment_id uuid NOT NULL REFERENCES target_assignments(id),
    revision bigint NOT NULL CHECK (revision > 0),
    definition bytea NOT NULL CHECK (octet_length(definition) BETWEEN 1 AND 262144),
    actor_id uuid NOT NULL REFERENCES principals(id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (assignment_id, revision)
);
CREATE TABLE target_previews (
    id uuid PRIMARY KEY,
    device_id uuid NOT NULL REFERENCES devices(id),
    actor_id uuid NOT NULL REFERENCES principals(id),
    document bytea NOT NULL CHECK (octet_length(document) BETWEEN 1 AND 1048576),
    digest bytea NOT NULL CHECK (octet_length(digest) = 32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE target_execution_heads (
    device_id uuid PRIMARY KEY REFERENCES devices(id),
    preview_id uuid NOT NULL REFERENCES target_previews(id)
);
CREATE TABLE target_membership_snapshots (
    preview_id uuid NOT NULL REFERENCES target_previews(id),
    group_id uuid NOT NULL,
    group_kind smallint NOT NULL CHECK (group_kind IN (1,2)),
    group_revision bigint NOT NULL,
    device_id uuid NOT NULL REFERENCES devices(id),
    input_digest bytea NOT NULL CHECK (octet_length(input_digest) = 32),
    membership smallint NOT NULL CHECK (membership BETWEEN 1 AND 3),
    PRIMARY KEY (preview_id, group_kind, group_id, device_id)
);
CREATE TABLE resource_rollouts (
    id uuid PRIMARY KEY,
    definition bytea NOT NULL CHECK (octet_length(definition) BETWEEN 1 AND 262144),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    ring_index integer NOT NULL DEFAULT 0 CHECK (ring_index BETWEEN 0 AND 15),
    paused boolean NOT NULL DEFAULT false,
    pause_reason text NOT NULL DEFAULT '',
    stage_started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (char_length(pause_reason) <= 512)
);
CREATE TABLE resource_rollout_stages (
    rollout_id uuid NOT NULL REFERENCES resource_rollouts(id),
    ring_index integer NOT NULL,
    started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    selected_count integer NOT NULL CHECK (selected_count >= 0),
    pending_count integer NOT NULL CHECK (pending_count >= 0),
    excluded_count integer NOT NULL CHECK (excluded_count >= 0),
    PRIMARY KEY (rollout_id, ring_index)
);
CREATE TABLE resource_rollout_members (
    rollout_id uuid NOT NULL,
    ring_index integer NOT NULL,
    device_id uuid NOT NULL REFERENCES devices(id),
    generation_id uuid REFERENCES enrollment_generations(id),
    bucket integer NOT NULL CHECK (bucket BETWEEN 0 AND 9999),
    membership smallint NOT NULL CHECK (membership BETWEEN 1 AND 3),
    health smallint NOT NULL DEFAULT 3 CHECK (health BETWEEN 1 AND 4),
    received_at timestamptz,
    health_valid_until timestamptz,
    evidence_assignment_id uuid REFERENCES resource_assignments(id),
    PRIMARY KEY (rollout_id, ring_index, device_id),
    FOREIGN KEY (rollout_id, ring_index) REFERENCES resource_rollout_stages(rollout_id, ring_index)
);
CREATE TABLE resource_rollout_events (
    id uuid PRIMARY KEY,
    rollout_id uuid NOT NULL REFERENCES resource_rollouts(id),
    revision bigint NOT NULL,
    actor_id uuid REFERENCES principals(id),
    reason text NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 512),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE targeting_requests (
    actor_id uuid NOT NULL REFERENCES principals(id),
    request_id uuid NOT NULL,
    method text NOT NULL,
    digest bytea NOT NULL CHECK (octet_length(digest) = 32),
    response bytea NOT NULL CHECK (octet_length(response) <= 1048576),
    PRIMARY KEY (actor_id, request_id)
);

-- Immutable preview/revision rows are also protected against accidental UPDATE.
-- +goose StatementBegin
CREATE FUNCTION reject_targeting_history_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'immutable targeting history';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER immutable_target_preview BEFORE UPDATE OR DELETE ON target_previews FOR EACH ROW EXECUTE FUNCTION reject_targeting_history_mutation();
CREATE TRIGGER immutable_target_assignment_revision BEFORE UPDATE OR DELETE ON target_assignment_revisions FOR EACH ROW EXECUTE FUNCTION reject_targeting_history_mutation();
CREATE TRIGGER immutable_dynamic_group_revision BEFORE UPDATE OR DELETE ON dynamic_target_group_revisions FOR EACH ROW EXECUTE FUNCTION reject_targeting_history_mutation();
CREATE TRIGGER immutable_target_membership BEFORE UPDATE OR DELETE ON target_membership_snapshots FOR EACH ROW EXECUTE FUNCTION reject_targeting_history_mutation();
CREATE TRIGGER immutable_rollout_stage BEFORE UPDATE OR DELETE ON resource_rollout_stages FOR EACH ROW EXECUTE FUNCTION reject_targeting_history_mutation();
CREATE TRIGGER immutable_rollout_member BEFORE UPDATE OF rollout_id, ring_index, device_id, generation_id, bucket, membership OR DELETE ON resource_rollout_members FOR EACH ROW EXECUTE FUNCTION reject_targeting_history_mutation();
CREATE TRIGGER immutable_rollout_definition BEFORE UPDATE OF id, definition OR DELETE ON resource_rollouts FOR EACH ROW EXECUTE FUNCTION reject_targeting_history_mutation();

-- +goose Down
DROP TABLE targeting_requests, resource_rollout_events, resource_rollout_members, resource_rollout_stages, resource_rollouts, target_membership_snapshots, target_execution_heads, target_previews, target_assignment_revisions, target_assignments, dynamic_target_group_revisions, dynamic_target_groups, targeting_lock;
DROP FUNCTION reject_targeting_history_mutation();
