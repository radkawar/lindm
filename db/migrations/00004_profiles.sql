-- SPDX-License-Identifier: Apache-2.0

-- Catalog publication does not activate resources. Immutable protobuf resource
-- records retain all typed desired dimensions, ownership and verification policy.
-- +goose Up
CREATE TABLE profiles (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'),
    head_revision_id uuid NOT NULL UNIQUE,
    created_at timestamptz NOT NULL
);
CREATE TABLE profile_revisions (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'),
    profile_id uuid NOT NULL REFERENCES profiles (id) ON DELETE RESTRICT,
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
ALTER TABLE profiles ADD CONSTRAINT profile_head
    FOREIGN KEY (id, head_revision_id) REFERENCES profile_revisions (profile_id, id)
    DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE profile_resources (
    revision_id uuid NOT NULL REFERENCES profile_revisions (id) ON DELETE RESTRICT,
    resource_id uuid NOT NULL CHECK (resource_id <> '00000000-0000-0000-0000-000000000000'),
    resource_kind smallint NOT NULL CHECK (resource_kind BETWEEN 1 AND 20),
    canonical_key text NOT NULL CHECK (octet_length(canonical_key) BETWEEN 1 AND 1024),
    resource_proto bytea NOT NULL CHECK (octet_length(resource_proto) BETWEEN 1 AND 1048576),
    PRIMARY KEY (revision_id, resource_id),
    UNIQUE (revision_id, resource_kind, canonical_key)
);
CREATE TABLE profile_dependencies (
    revision_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    dependency_kind smallint NOT NULL CHECK (dependency_kind BETWEEN 1 AND 20),
    dependency_key text NOT NULL,
    condition smallint NOT NULL CHECK (condition BETWEEN 1 AND 4),
    PRIMARY KEY (revision_id, resource_id, dependency_kind, dependency_key),
    FOREIGN KEY (revision_id, resource_id) REFERENCES profile_resources (revision_id, resource_id) ON DELETE RESTRICT,
    FOREIGN KEY (revision_id, dependency_kind, dependency_key) REFERENCES profile_resources (revision_id, resource_kind, canonical_key) ON DELETE RESTRICT
);
-- The deferred receipt references prevent incomplete acceptance from committing.
CREATE TABLE profile_requests (
    request_id uuid PRIMARY KEY CHECK (request_id <> '00000000-0000-0000-0000-000000000000'),
    actor_id uuid NOT NULL REFERENCES principals (id) ON DELETE RESTRICT,
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    profile_id uuid NOT NULL,
    revision_id uuid NOT NULL UNIQUE,
    audit_id uuid NOT NULL UNIQUE REFERENCES audit_events (id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (profile_id, revision_id) REFERENCES profile_revisions (profile_id, id)
        DEFERRABLE INITIALLY DEFERRED
);
-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    DROP TABLE profile_requests;
    DROP TABLE profile_dependencies;
    DROP TABLE profile_resources;
    DROP TABLE profile_revisions, profiles;
END $$;
-- +goose StatementEnd
