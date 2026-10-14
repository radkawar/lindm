-- SPDX-License-Identifier: Apache-2.0

-- Public execution authority only. No execution signing keys belong in this schema.
-- Histories are append-only: capacity exhaustion refuses admission, never prunes
-- the evidence needed for exact retries or authenticated root catch-up.
-- +goose Up
CREATE TABLE execution_authority (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    deployment_id uuid NULL,
    trust_domain_digest bytea NOT NULL DEFAULT '' CHECK (octet_length(trust_domain_digest) IN (0, 32)),
    root_document bytea NOT NULL DEFAULT '' CHECK (octet_length(root_document) <= 65536),
    initial_root_json bytea NOT NULL DEFAULT '' CHECK (octet_length(initial_root_json) <= 65536),
    initial_bootstrap_envelope bytea NOT NULL DEFAULT '' CHECK (octet_length(initial_bootstrap_envelope) <= 524288),
    initialized_at timestamptz NULL,
    delegation_envelope bytea NOT NULL DEFAULT '' CHECK (octet_length(delegation_envelope) <= 16384),
    accepted_at timestamptz NULL,
    revision bigint NOT NULL DEFAULT 0 CHECK (revision BETWEEN 0 AND 65537),
    root_count integer NOT NULL DEFAULT 0 CHECK (root_count BETWEEN 0 AND 4097),
    update_count integer NOT NULL DEFAULT 0 CHECK (update_count BETWEEN 0 AND 65536),
    retained_bytes bigint NOT NULL DEFAULT 0 CHECK (retained_bytes BETWEEN 0 AND 67108864),
    CHECK (
        (deployment_id IS NULL AND octet_length(trust_domain_digest) = 0
            AND octet_length(root_document) = 0 AND octet_length(delegation_envelope) = 0
            AND accepted_at IS NULL AND revision = 0 AND root_count = 0
            AND update_count = 0 AND retained_bytes = 0
            AND octet_length(initial_root_json) = 0 AND octet_length(initial_bootstrap_envelope) = 0
            AND initialized_at IS NULL)
        OR (deployment_id IS NOT NULL AND deployment_id <> '00000000-0000-0000-0000-000000000000'
            AND octet_length(trust_domain_digest) = 32 AND octet_length(root_document) > 0
            AND accepted_at IS NOT NULL AND revision = update_count + 1
            AND root_count > 0 AND retained_bytes > 0
            AND octet_length(initial_root_json) > 0 AND octet_length(initial_bootstrap_envelope) > 0
            AND initialized_at IS NOT NULL AND accepted_at >= initialized_at
            AND ((update_count = 0 AND octet_length(delegation_envelope) = 0)
                OR (update_count > 0 AND octet_length(delegation_envelope) > 0)))
    )
);
INSERT INTO execution_authority (id) VALUES (true);

CREATE TABLE execution_authority_roots (
    position integer PRIMARY KEY CHECK (position BETWEEN 1 AND 4097),
    -- Canonical decimal text preserves the entire protobuf uint64 domain.
    root_version text NOT NULL UNIQUE CHECK (
        root_version ~ '^[1-9][0-9]{0,19}$' AND root_version::numeric <= 18446744073709551615
    ),
    root_digest bytea NOT NULL UNIQUE CHECK (octet_length(root_digest) = 32),
    root_document bytea NOT NULL CHECK (octet_length(root_document) BETWEEN 1 AND 65536),
    transition_document bytea NOT NULL CHECK (octet_length(transition_document) <= 32784),
    accepted_at timestamptz NOT NULL,
    CHECK ((position = 1 AND octet_length(transition_document) = 0)
        OR (position > 1 AND octet_length(transition_document) > 0))
);

CREATE TABLE execution_authority_updates (
    request_digest bytea PRIMARY KEY CHECK (octet_length(request_digest) = 32),
    request_document bytea NOT NULL CHECK (octet_length(request_document) BETWEEN 1 AND 278656),
    receipt_document bytea NOT NULL CHECK (octet_length(receipt_document) BETWEEN 1 AND 128),
    revision bigint NOT NULL UNIQUE CHECK (revision BETWEEN 2 AND 65537),
    accepted_at timestamptz NOT NULL,
    audit_id uuid NOT NULL UNIQUE REFERENCES audit_events (id) ON DELETE RESTRICT
);

CREATE INDEX execution_authority_audit_actions ON audit_events (action)
    WHERE action IN ('execution_authority.initialize', 'execution_authority.update');

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    DROP INDEX execution_authority_audit_actions;
    DROP TABLE execution_authority_updates;
    DROP TABLE execution_authority_roots;
    DROP TABLE execution_authority;
END $$;
-- +goose StatementEnd
