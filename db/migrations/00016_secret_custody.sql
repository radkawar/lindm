-- +goose Up

-- Deployment-global secret custody. Each immutable version is an AES-256-GCM
-- envelope whose data key is wrapped by the escrow KEK. Storage AAD is derived
-- from binding_document, which is persisted and never rebuilt from mutable rows.
-- No plaintext digest is stored: material may be low-entropy.
CREATE TABLE managed_secrets (
    id uuid PRIMARY KEY,
    purpose smallint NOT NULL CHECK (purpose BETWEEN 1 AND 9),
    subject_binding_id uuid NOT NULL UNIQUE,
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 128),
    current_version bigint NOT NULL CHECK (current_version > 0),
    request_id uuid NOT NULL UNIQUE,
    created_by uuid NOT NULL REFERENCES principals(id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (updated_at >= created_at)
);
CREATE TABLE managed_secret_versions (
    secret_id uuid NOT NULL REFERENCES managed_secrets(id),
    version bigint NOT NULL CHECK (version > 0),
    request_id uuid NOT NULL UNIQUE,
    binding_document bytea NOT NULL CHECK (octet_length(binding_document) BETWEEN 1 AND 1024),
    key_id text NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 128),
    wrapped_key bytea NOT NULL CHECK (octet_length(wrapped_key) BETWEEN 1 AND 1024),
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 1 AND 8192),
    reason text NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 512),
    created_by uuid NOT NULL REFERENCES principals(id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (secret_id, version)
);
CREATE INDEX managed_secrets_page ON managed_secrets(created_at, id);

-- Identity-signed HPKE recipient keys. The identity fingerprint must equal the
-- SPKI fingerprint of an active or overlapping certificate of the generation.
CREATE TABLE device_encryption_keys (
    generation_id uuid NOT NULL REFERENCES enrollment_generations(id),
    public_key_sha256 bytea NOT NULL CHECK (octet_length(public_key_sha256) = 32),
    device_id uuid NOT NULL REFERENCES devices(id),
    identity_key_fingerprint bytea NOT NULL CHECK (octet_length(identity_key_fingerprint) = 32),
    kem_id integer NOT NULL CHECK (kem_id = 32),
    public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
    attestation_envelope bytea NOT NULL CHECK (octet_length(attestation_envelope) BETWEEN 1 AND 16384),
    registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (generation_id, public_key_sha256),
    UNIQUE (generation_id, identity_key_fingerprint)
);

-- Exact sealed deliveries minted with one resource action, replayed byte-exact.
-- Pruned with their action; they open only with the recipient device key.
CREATE TABLE resource_action_secrets (
    action_id uuid NOT NULL REFERENCES resource_actions(id) ON DELETE CASCADE,
    ordinal smallint NOT NULL CHECK (ordinal BETWEEN 0 AND 7),
    secret_id uuid NOT NULL,
    version bigint NOT NULL,
    recipient_key_sha256 bytea NOT NULL CHECK (octet_length(recipient_key_sha256) = 32),
    sealed bytea NOT NULL CHECK (octet_length(sealed) BETWEEN 1 AND 8192),
    PRIMARY KEY (action_id, ordinal),
    FOREIGN KEY (secret_id, version) REFERENCES managed_secret_versions(secret_id, version)
);
CREATE INDEX resource_action_secrets_version ON resource_action_secrets(secret_id, version);

-- Managed local-admin password rotation is an imperative device action.
ALTER TABLE device_actions DROP CONSTRAINT device_actions_capability_check;
ALTER TABLE device_actions ADD CONSTRAINT device_actions_capability_check CHECK (capability IN ('device.escrow-rotate.v1', 'device.tpm2-bind.v1', 'device.lock-sessions.v1', 'device.release-lock.v1', 'device.quarantine.v1', 'device.release-quarantine.v1', 'device.crypto-erase.v1', 'device.sanitize.v1', 'device.restart.v1', 'device.shutdown.v1', 'device.refresh-inventory.v1', 'device.local-admin-rotate.v1'));

-- One policy per device. The policy actor is freshly re-authorized whenever
-- the server mints a rotation; changed authority blocks instead of minting.
CREATE TABLE local_admin_password_policies (
    device_id uuid PRIMARY KEY REFERENCES devices(id),
    account_name text NOT NULL CHECK (account_name ~ '^[a-zA-Z_][a-zA-Z0-9_.-]{0,31}$' AND account_name <> 'root'),
    rotation_interval_seconds integer NOT NULL CHECK (rotation_interval_seconds BETWEEN 86400 AND 31536000),
    post_reveal_delay_seconds integer NOT NULL CHECK (post_reveal_delay_seconds BETWEEN 0 AND 86400),
    actor_id uuid NOT NULL REFERENCES principals(id),
    authorization_version bigint NOT NULL CHECK (authorization_version > 0),
    request_id uuid NOT NULL UNIQUE,
    rotate_due_at timestamptz NOT NULL,
    blocked_reason text NOT NULL DEFAULT '' CHECK (char_length(blocked_reason) <= 128),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX local_admin_password_policies_due ON local_admin_password_policies(rotate_due_at) WHERE blocked_reason = '';

-- Ciphertext lives in device_action_escrow (same envelope custody as recovery
-- keys, separate storage domain). This row tracks whether it is in effect.
CREATE TABLE local_admin_passwords (
    action_id uuid PRIMARY KEY REFERENCES device_action_escrow(action_id),
    device_id uuid NOT NULL REFERENCES devices(id),
    generation_id uuid NOT NULL REFERENCES enrollment_generations(id),
    account_name text NOT NULL CHECK (account_name ~ '^[a-zA-Z_][a-zA-Z0-9_.-]{0,31}$'),
    account_uid bigint NOT NULL CHECK (account_uid BETWEEN 1 AND 4294967294),
    state text NOT NULL CHECK (state IN ('escrowed', 'current', 'superseded', 'unknown', 'failed')),
    escrowed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    settled_at timestamptz,
    last_revealed_at timestamptz,
    CHECK ((state = 'escrowed') = (settled_at IS NULL))
);
CREATE UNIQUE INDEX local_admin_passwords_one_current ON local_admin_passwords(device_id) WHERE state = 'current';
CREATE INDEX local_admin_passwords_recent ON local_admin_passwords(device_id, escrowed_at DESC, action_id DESC);

-- Reveal approvals: secrets are deployment-global (no device target);
-- local-admin passwords are device-targeted.
-- +goose StatementBegin
DO $$
DECLARE c record;
BEGIN
  FOR c IN
    SELECT conname FROM pg_constraint
    WHERE conrelid = 'approval_requests'::regclass AND contype = 'c'
      AND (pg_get_constraintdef(oid) LIKE '%recovery_key.reveal%' OR pg_get_constraintdef(oid) LIKE '%device_id IS NULL%')
  LOOP
    EXECUTE format('ALTER TABLE approval_requests DROP CONSTRAINT %I', c.conname);
  END LOOP;
END $$;
-- +goose StatementEnd
ALTER TABLE approval_requests ADD CONSTRAINT approval_requests_action_known CHECK (action IN ('device.revoke', 'device.recover', 'enrollment.approve', 'resources.assign', 'resources.activate_preview', 'execution_trust.manage', 'device.action', 'recovery_key.reveal', 'secret.reveal', 'local_admin.reveal'));
ALTER TABLE approval_requests ADD CONSTRAINT approval_requests_action_permission CHECK (
    (action IN ('device.revoke', 'resources.assign', 'execution_trust.manage') AND permission = action)
    OR (action = 'device.action' AND permission IN ('encryption.manage', 'actions.lock', 'actions.release-lock', 'actions.quarantine', 'destructive.execute', 'remote_execution.run', 'inventory.manage'))
    OR (action = 'resources.activate_preview' AND permission = 'resources.assign')
    OR (action = 'recovery_key.reveal' AND permission = 'recovery_keys.read')
    OR (action = 'device.recover' AND permission = 'device.revoke')
    OR (action = 'enrollment.approve' AND permission = 'enrollment.manage')
    OR (action IN ('secret.reveal', 'local_admin.reveal') AND permission = 'secrets.reveal')
);
ALTER TABLE approval_requests ADD CONSTRAINT approval_requests_device_target CHECK ((action IN ('execution_trust.manage', 'secret.reveal')) = (device_id IS NULL));

-- +goose Down
DELETE FROM approval_requests WHERE action IN ('secret.reveal', 'local_admin.reveal');
ALTER TABLE approval_requests DROP CONSTRAINT approval_requests_device_target;
ALTER TABLE approval_requests DROP CONSTRAINT approval_requests_action_permission;
ALTER TABLE approval_requests DROP CONSTRAINT approval_requests_action_known;
ALTER TABLE approval_requests ADD CHECK (action IN ('device.revoke', 'device.recover', 'enrollment.approve', 'resources.assign', 'resources.activate_preview', 'execution_trust.manage', 'device.action', 'recovery_key.reveal'));
ALTER TABLE approval_requests ADD CHECK (
    (action IN ('device.revoke', 'resources.assign', 'execution_trust.manage') AND permission = action)
    OR (action = 'device.action' AND permission IN ('encryption.manage', 'actions.lock', 'actions.release-lock', 'actions.quarantine', 'destructive.execute', 'remote_execution.run', 'inventory.manage'))
    OR (action = 'resources.activate_preview' AND permission = 'resources.assign')
    OR (action = 'recovery_key.reveal' AND permission = 'recovery_keys.read')
    OR (action = 'device.recover' AND permission = 'device.revoke')
    OR (action = 'enrollment.approve' AND permission = 'enrollment.manage')
);
ALTER TABLE approval_requests ADD CHECK ((action = 'execution_trust.manage') = (device_id IS NULL));
DROP TABLE local_admin_passwords;
DROP TABLE local_admin_password_policies;
DELETE FROM device_action_escrow WHERE action_id IN (SELECT id FROM device_actions WHERE capability = 'device.local-admin-rotate.v1');
DELETE FROM device_actions WHERE capability = 'device.local-admin-rotate.v1';
ALTER TABLE device_actions DROP CONSTRAINT device_actions_capability_check;
ALTER TABLE device_actions ADD CONSTRAINT device_actions_capability_check CHECK (capability IN ('device.escrow-rotate.v1', 'device.tpm2-bind.v1', 'device.lock-sessions.v1', 'device.release-lock.v1', 'device.quarantine.v1', 'device.release-quarantine.v1', 'device.crypto-erase.v1', 'device.sanitize.v1', 'device.restart.v1', 'device.shutdown.v1', 'device.refresh-inventory.v1'));
DROP TABLE resource_action_secrets;
DROP TABLE device_encryption_keys;
DROP TABLE managed_secret_versions;
DROP TABLE managed_secrets;
