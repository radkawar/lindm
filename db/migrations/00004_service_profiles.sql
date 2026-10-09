-- Catalog publication is separate from assignment/activation. Historical
-- revisions and request receipts are append-only; moving a head cannot rewrite
-- a pinned revision or make it execute on a device.
-- +goose Up
CREATE TABLE service_profiles (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'),
    head_revision_id uuid NOT NULL UNIQUE,
    created_at timestamptz NOT NULL
);

CREATE TABLE service_profile_revisions (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'),
    profile_id uuid NOT NULL REFERENCES service_profiles (id) ON DELETE RESTRICT,
    revision_number bigint NOT NULL CHECK (revision_number > 0),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 160),
    description text NOT NULL CHECK (char_length(description) <= 4096),
    resource_count integer NOT NULL CHECK (resource_count BETWEEN 1 AND 64),
    spec_digest bytea NOT NULL CHECK (octet_length(spec_digest) = 32),
    actor_id uuid NOT NULL REFERENCES principals (id) ON DELETE RESTRICT,
    published_at timestamptz NOT NULL,
    UNIQUE (profile_id, revision_number),
    UNIQUE (profile_id, id)
);
ALTER TABLE service_profiles ADD CONSTRAINT service_profile_head
    FOREIGN KEY (id, head_revision_id) REFERENCES service_profile_revisions (profile_id, id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE service_profile_resources (
    revision_id uuid NOT NULL REFERENCES service_profile_revisions (id) ON DELETE RESTRICT,
    resource_id uuid NOT NULL CHECK (resource_id <> '00000000-0000-0000-0000-000000000000'),
    unit_name text NOT NULL CHECK (char_length(unit_name) BETWEEN 1 AND 255),
    runtime_state smallint NOT NULL CHECK (runtime_state BETWEEN 1 AND 3),
    enablement_state smallint NOT NULL CHECK (enablement_state BETWEEN 1 AND 3),
    PRIMARY KEY (revision_id, resource_id),
    UNIQUE (revision_id, unit_name),
    CHECK (runtime_state <> 1 OR enablement_state <> 1)
);

CREATE TABLE service_profile_dependencies (
    revision_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    dependency_id uuid NOT NULL,
    PRIMARY KEY (revision_id, resource_id, dependency_id),
    FOREIGN KEY (revision_id, resource_id) REFERENCES service_profile_resources (revision_id, resource_id) ON DELETE RESTRICT,
    FOREIGN KEY (revision_id, dependency_id) REFERENCES service_profile_resources (revision_id, resource_id) ON DELETE RESTRICT,
    CHECK (resource_id <> dependency_id)
);

-- A transaction reserves its exact receipt identity before taking a profile
-- lock. Deferred references prevent an incomplete accepted receipt from commit.
CREATE TABLE service_profile_requests (
    request_id uuid PRIMARY KEY CHECK (request_id <> '00000000-0000-0000-0000-000000000000'),
    actor_id uuid NOT NULL REFERENCES principals (id) ON DELETE RESTRICT,
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    profile_id uuid NOT NULL,
    revision_id uuid NOT NULL UNIQUE,
    audit_id uuid NOT NULL UNIQUE REFERENCES audit_events (id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (profile_id, revision_id) REFERENCES service_profile_revisions (profile_id, id)
        DEFERRABLE INITIALLY DEFERRED
);

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    DROP TABLE service_profile_requests;
    DROP TABLE service_profile_dependencies;
    DROP TABLE service_profile_resources;
    DROP TABLE service_profile_revisions, service_profiles;
END $$;
-- +goose StatementEnd
