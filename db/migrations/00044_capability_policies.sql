-- SPDX-License-Identifier: Apache-2.0

-- +goose Up
-- Device management capability policies (lindm.admin.v1.CapabilityPolicy). A
-- device's effective grant is the deployment policy united with every static or
-- dynamic group policy whose group contains it. capabilities holds remotely
-- enableable lindm.agent.v1.ManagementCapability numbers (1-7); firewall holds the
-- deterministic lindm.agent.v1.CapabilityFirewallSettings encoding (deployment
-- scope only, empty when absent). Revisions come from one sequence, so a removed
-- and recreated group policy never reuses a compare-and-swap token. updated_by is
-- NULL for the install-time system seed.
CREATE SEQUENCE capability_policy_revisions AS bigint START WITH 2 MINVALUE 1;

CREATE TABLE capability_policies (
    scope_kind smallint NOT NULL CHECK (scope_kind BETWEEN 1 AND 3),
    static_group_id uuid UNIQUE REFERENCES device_groups (id) ON DELETE CASCADE,
    dynamic_group_id uuid UNIQUE REFERENCES dynamic_target_groups (id) ON DELETE CASCADE,
    capabilities smallint [] NOT NULL CHECK (
        capabilities <@ ARRAY[1, 2, 3, 4, 5, 6, 7]::smallint [] AND cardinality(capabilities) <= 7
    ),
    sysctl_keys text [] NOT NULL DEFAULT '{}' CHECK (cardinality(sysctl_keys) <= 128),
    firewall bytea NOT NULL DEFAULT '' CHECK (octet_length(firewall) <= 65536),
    revision bigint NOT NULL UNIQUE CHECK (revision > 0),
    updated_at timestamptz NOT NULL,
    updated_by uuid REFERENCES principals (id) ON DELETE RESTRICT,
    CONSTRAINT capability_policies_scope CHECK (
        (scope_kind = 1 AND static_group_id IS NULL AND dynamic_group_id IS NULL)
        OR (scope_kind = 2 AND static_group_id IS NOT NULL AND dynamic_group_id IS NULL)
        OR (scope_kind = 3 AND static_group_id IS NULL AND dynamic_group_id IS NOT NULL)
    ),
    CONSTRAINT capability_policies_firewall_scope CHECK (scope_kind = 1 OR octet_length(firewall) = 0),
    CONSTRAINT capability_policies_group_nonempty CHECK (scope_kind = 1 OR cardinality(capabilities) > 0),
    CONSTRAINT capability_policies_sysctl CHECK ((cardinality(sysctl_keys) > 0) = (7 = ANY(capabilities)))
);

CREATE UNIQUE INDEX capability_policies_deployment ON capability_policies (scope_kind) WHERE scope_kind = 1;

-- Install-time default: packages, standard-root files, local accounts and OS
-- updates. Firewall, kernel-module blocklist and kernel settings are opt-in.
INSERT INTO capability_policies (scope_kind, capabilities, revision, updated_at)
VALUES (1, '{1,2,4,6}', 1, clock_timestamp());

-- Exact SetCapabilityPolicy replay receipts, keyed by the caller's request_id.
CREATE TABLE capability_policy_requests (
    actor_id uuid NOT NULL REFERENCES principals (id) ON DELETE RESTRICT,
    request_id uuid NOT NULL,
    digest bytea NOT NULL CHECK (octet_length(digest) = 32),
    response bytea NOT NULL CHECK (octet_length(response) <= 1048576),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (actor_id, request_id)
);

-- Signed lindm.agent.v1.AgentCapabilityPolicy envelopes per device enrollment
-- generation. content_sha256 covers the effective grant (capabilities, sysctl
-- keys, firewall settings) and binding, not version or issuance time.
CREATE TABLE device_capability_policies (
    device_id uuid NOT NULL REFERENCES devices (id) ON DELETE RESTRICT,
    generation_id uuid NOT NULL REFERENCES enrollment_generations (id) ON DELETE RESTRICT,
    version bigint NOT NULL CHECK (version > 0),
    content_sha256 bytea NOT NULL CHECK (octet_length(content_sha256) = 32),
    envelope bytea NOT NULL CHECK (octet_length(envelope) BETWEEN 1 AND 65536),
    issued_at timestamptz NOT NULL,
    PRIMARY KEY (device_id, generation_id, version)
);

-- +goose Down
DROP TABLE device_capability_policies, capability_policy_requests, capability_policies;
DROP SEQUENCE capability_policy_revisions;
