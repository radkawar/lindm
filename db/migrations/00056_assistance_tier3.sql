-- SPDX-License-Identifier: Apache-2.0

-- lindm:online-compatible minimum-runtime=51
-- +goose Up
-- Unattended access is two independent records: a server grant consumed from
-- an approval decided by a different person, and a device-reported local
-- opt-in. Neither stores a portal restore token; that stays on the device in
-- the opted-in user's own state and the desktop's permission store.
CREATE TABLE assistance_unattended_grants (
    id uuid PRIMARY KEY,
    request_id uuid NOT NULL UNIQUE,
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    approval_id uuid NOT NULL UNIQUE REFERENCES approval_requests(id),
    device_id uuid NOT NULL REFERENCES devices(id),
    operator_id uuid NOT NULL REFERENCES principals(id),
    approver_id uuid NOT NULL REFERENCES principals(id),
    mode smallint NOT NULL CHECK (mode IN (1, 2)),
    policy_mode smallint NOT NULL CHECK (policy_mode IN (2, 3)),
    reason text NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 512),
    target_username text NOT NULL CHECK (target_username ~ '^[a-zA-Z_][a-zA-Z0-9_.-]{0,31}$'),
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    schedule bytea NOT NULL DEFAULT '' CHECK (octet_length(schedule) <= 1024),
    requested_capabilities bytea NOT NULL CHECK (octet_length(requested_capabilities) <= 4096),
    max_session_seconds integer NOT NULL CHECK (max_session_seconds BETWEEN 60 AND 1800),
    created_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revoked_by uuid REFERENCES principals(id),
    revoke_reason text NOT NULL DEFAULT '' CHECK (char_length(revoke_reason) <= 512),
    CHECK (approver_id <> operator_id),
    CHECK (not_after > not_before AND not_after <= not_before + interval '30 days'),
    CHECK ((policy_mode = 3) = (octet_length(schedule) > 0)),
    CHECK ((revoked_at IS NULL) = (revoke_reason = ''))
);
CREATE INDEX assistance_unattended_grants_device_idx ON assistance_unattended_grants(device_id, created_at DESC, id DESC);
CREATE INDEX assistance_unattended_grants_operator_idx ON assistance_unattended_grants(operator_id);
CREATE INDEX assistance_unattended_grants_approver_idx ON assistance_unattended_grants(approver_id);
CREATE INDEX assistance_unattended_grants_revoker_idx ON assistance_unattended_grants(revoked_by);

-- state: 0 offered in an attended session, 1 enrolled (local opt-in plus the
-- desktop's persistent grant), 2 revoked, 3 declined.
CREATE TABLE assistance_unattended_enrollments (
    id uuid PRIMARY KEY,
    device_id uuid NOT NULL REFERENCES devices(id),
    session_id uuid NOT NULL UNIQUE REFERENCES assistance_sessions(id),
    mode smallint NOT NULL CHECK (mode IN (1, 2)),
    state smallint NOT NULL DEFAULT 0 CHECK (state BETWEEN 0 AND 3),
    username text NOT NULL DEFAULT '' CHECK (username ~ '^([a-zA-Z_][a-zA-Z0-9_.-]{0,31})?$'),
    uid bigint NOT NULL DEFAULT 0 CHECK (uid BETWEEN 0 AND 4294967295),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consented_at timestamptz,
    revoked_at timestamptz,
    revoke_reason text NOT NULL DEFAULT '' CHECK (revoke_reason ~ '^[a-z0-9_]{0,64}$'),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '90 days'),
    CHECK (state <> 1 OR (consented_at IS NOT NULL AND username <> '' AND uid > 0)),
    CHECK ((state = 2) = (revoked_at IS NOT NULL))
);
CREATE INDEX assistance_unattended_enrollments_device_idx ON assistance_unattended_enrollments(device_id, created_at DESC, id DESC);
CREATE UNIQUE INDEX assistance_unattended_enrollments_one_per_user ON assistance_unattended_enrollments(device_id, username) WHERE state = 1;

ALTER TABLE assistance_sessions
    ADD COLUMN unattended_grant_id uuid REFERENCES assistance_unattended_grants(id),
    ADD COLUMN unattended_enrollment_id uuid REFERENCES assistance_unattended_enrollments(id),
    ADD CHECK ((unattended_grant_id IS NULL) = (unattended_enrollment_id IS NULL)),
    ADD CHECK (unattended_grant_id IS NULL OR (mode IN (1, 2) AND target_username <> ''));
CREATE INDEX assistance_sessions_unattended_grant_idx ON assistance_sessions(unattended_grant_id);
CREATE INDEX assistance_sessions_unattended_enrollment_idx ON assistance_sessions(unattended_enrollment_id);

ALTER TABLE assistance_commands
    DROP CONSTRAINT assistance_commands_kind_check,
    ADD CONSTRAINT assistance_commands_kind_check CHECK (kind BETWEEN 1 AND 7),
    ADD COLUMN annotation_enabled boolean NOT NULL DEFAULT false,
    ADD CHECK (kind = 7 OR NOT annotation_enabled);

ALTER TABLE approval_requests DROP CONSTRAINT approval_requests_action_known;
ALTER TABLE approval_requests ADD CONSTRAINT approval_requests_action_known CHECK (action IN ('device.revoke', 'device.recover', 'enrollment.approve', 'resources.assign', 'resources.activate_preview', 'resources.rollout', 'execution_trust.manage', 'device.action', 'recovery_key.reveal', 'secret.reveal', 'local_admin.reveal', 'advisory_exception.accept', 'assistance.unattended'));
ALTER TABLE approval_requests DROP CONSTRAINT approval_requests_action_permission;
ALTER TABLE approval_requests ADD CONSTRAINT approval_requests_action_permission CHECK (
    (action IN ('device.revoke', 'resources.assign', 'execution_trust.manage') AND permission = action)
    OR (action = 'device.action' AND permission IN ('encryption.manage', 'actions.lock', 'actions.release-lock', 'actions.quarantine', 'destructive.execute', 'remote_execution.run', 'inventory.manage'))
    OR (action = 'resources.activate_preview' AND permission = 'resources.assign')
    OR (action = 'resources.rollout' AND permission = 'resources.assign' AND device_id IS NULL)
    OR (action = 'recovery_key.reveal' AND permission = 'recovery_keys.read')
    OR (action = 'device.recover' AND permission = 'device.revoke')
    OR (action = 'enrollment.approve' AND permission = 'enrollment.manage')
    OR (action IN ('secret.reveal', 'local_admin.reveal') AND permission = 'secrets.reveal')
    OR (action = 'advisory_exception.accept' AND permission = 'advisory_exceptions.manage')
    OR (action = 'assistance.unattended' AND permission = 'remote_assistance.unattended')
);

UPDATE lindm_schema_compatibility
SET migration_versions = (
  SELECT array_agg(version ORDER BY version)
  FROM (
    SELECT version FROM (
      SELECT DISTINCT ON (version_id) version_id AS version, is_applied
      FROM goose_db_version ORDER BY version_id, id DESC
    ) latest WHERE is_applied AND version > 0
    UNION SELECT 56::bigint
  ) versions
);

-- +goose Down
-- Unattended grants, approvals and command records are authorization evidence.
-- +goose StatementBegin
DO $$ BEGIN
  RAISE EXCEPTION 'unattended assistance authorization evidence requires an explicitly reviewed fenced backup restore';
END $$;
-- +goose StatementEnd
