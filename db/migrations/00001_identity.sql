-- Identity, session, lineage, and audit schema.
-- Device queries may insert into audit_events and list by (occurred_at, id).
-- Do not delete principals; actor_id is ON DELETE RESTRICT.
-- sqlc: the Down section is a DO block so its DROP statements are not catalog drops.

-- +goose Up
CREATE TABLE principals (
  id uuid PRIMARY KEY,
  issuer text NOT NULL,
  subject text NOT NULL,
  display_name text NOT NULL DEFAULT '',
  pinned_role text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  deactivated_at timestamptz NULL,
  deactivation_source text NOT NULL DEFAULT '',
  directory_enabled boolean NOT NULL DEFAULT false,
  directory_observed_at timestamptz NULL,
  authorization_version bigint NOT NULL DEFAULT 1,
  authorization_role text NOT NULL DEFAULT '',
  authorization_digest bytea NOT NULL DEFAULT '' CHECK (octet_length(authorization_digest) IN (0, 32)),
  service_account boolean NOT NULL DEFAULT false,
  lifecycle_not_before timestamptz NOT NULL DEFAULT '-infinity',
  CONSTRAINT principals_authorization_version_positive CHECK (authorization_version > 0),
  CONSTRAINT principals_authorization_role_known CHECK (authorization_role = '' OR authorization_role ~ '^[a-z][a-z0-9_.-]{0,63}$'),
  CONSTRAINT principals_issuer_len CHECK (char_length(issuer) BETWEEN 1 AND 2048),
  CONSTRAINT principals_subject_len CHECK (char_length(subject) BETWEEN 1 AND 256),
  CONSTRAINT principals_display_name_len CHECK (char_length(display_name) <= 256),
  CONSTRAINT principals_pinned_role_chk CHECK (pinned_role IN ('', 'owner')),
  CONSTRAINT principals_deactivation_source_chk CHECK (deactivation_source IN ('', 'keycloak', 'entra', 'okta', 'google', 'scim')),
  CONSTRAINT principals_deactivation_pair CHECK (
    (deactivated_at IS NULL AND deactivation_source = '')
    OR (deactivated_at IS NOT NULL AND deactivation_source <> '')
  ),
  CONSTRAINT principals_issuer_subject_uidx UNIQUE (issuer, subject)
);

CREATE UNIQUE INDEX principals_one_owner ON principals (pinned_role) WHERE pinned_role = 'owner';

CREATE TABLE deployment_identity (
  id boolean PRIMARY KEY DEFAULT true CHECK (id),
  deployment_id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
  owner_principal_id uuid NULL REFERENCES principals (id) ON DELETE RESTRICT,
  initialized_at timestamptz NULL,
  CONSTRAINT deployment_identity_pair CHECK (
    (owner_principal_id IS NULL AND initialized_at IS NULL)
    OR (owner_principal_id IS NOT NULL AND initialized_at IS NOT NULL)
  )
);

INSERT INTO deployment_identity (id) VALUES (true);

-- The active startup policy fences old replicas and all pending actor authority.
CREATE TABLE authorization_policy (
  id boolean PRIMARY KEY DEFAULT true CHECK (id),
  digest bytea NOT NULL DEFAULT '' CHECK (octet_length(digest) IN (0, 32))
);
INSERT INTO authorization_policy (id) VALUES (true);

CREATE TABLE principal_lineage (
  principal_id uuid PRIMARY KEY REFERENCES principals (id) ON DELETE RESTRICT,
  broker_issuer text NOT NULL DEFAULT '',
  broker_subject text NOT NULL DEFAULT '',
  upstream_provider text NOT NULL DEFAULT '',
  upstream_subject text NOT NULL DEFAULT '',
  directory_connector text NOT NULL DEFAULT '',
  upstream_observed_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT principal_lineage_broker_issuer_len CHECK (char_length(broker_issuer) <= 2048),
  CONSTRAINT principal_lineage_broker_subject_len CHECK (char_length(broker_subject) <= 256),
  CONSTRAINT principal_lineage_upstream_provider_len CHECK (char_length(upstream_provider) <= 2048),
  CONSTRAINT principal_lineage_upstream_subject_len CHECK (char_length(upstream_subject) <= 256),
  CONSTRAINT principal_lineage_connector_len CHECK (char_length(directory_connector) <= 64)
);

CREATE UNIQUE INDEX principal_lineage_upstream_uidx
  ON principal_lineage (directory_connector, upstream_provider, upstream_subject)
  WHERE directory_connector <> '' AND upstream_subject <> '';

CREATE UNIQUE INDEX principal_lineage_broker_uidx
  ON principal_lineage (broker_issuer, broker_subject)
  WHERE broker_subject <> '';

CREATE TABLE principal_groups (
  principal_id uuid NOT NULL REFERENCES principals (id) ON DELETE RESTRICT,
  group_path text NOT NULL,
  PRIMARY KEY (principal_id, group_path),
  CONSTRAINT principal_groups_path_len CHECK (char_length(group_path) BETWEEN 1 AND 512)
);

CREATE TABLE sessions (
  token_hash bytea PRIMARY KEY,
  principal_id uuid NOT NULL REFERENCES principals (id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  idle_expires_at timestamptz NOT NULL,
  absolute_expires_at timestamptz NOT NULL,
  revoked_at timestamptz NULL,
  break_glass boolean NOT NULL DEFAULT false,
  incident_reason text NOT NULL DEFAULT '',
  kind text NOT NULL DEFAULT 'browser' CHECK (kind IN ('browser', 'cli')),
  CONSTRAINT sessions_incident_reason CHECK (
    (NOT break_glass AND incident_reason = '') OR
    (break_glass AND char_length(incident_reason) BETWEEN 1 AND 512
      AND absolute_expires_at <= created_at + interval '1 hour')
  ),
  CONSTRAINT sessions_token_hash_len CHECK (octet_length(token_hash) = 32),
  CONSTRAINT sessions_expiry CHECK (
    created_at <= last_seen_at
    AND created_at < absolute_expires_at
    AND idle_expires_at <= absolute_expires_at
    AND absolute_expires_at <= created_at + interval '12 hours'
    AND idle_expires_at <= last_seen_at + interval '30 minutes'
    AND idle_expires_at > created_at
  )
);

CREATE INDEX sessions_principal_active_idx ON sessions (principal_id) WHERE revoked_at IS NULL;

-- Browser-bound, bounded pending requests and hash-only one-use PKCE codes.
CREATE TABLE cli_auth_requests (
  binding_hash bytea PRIMARY KEY CHECK (octet_length(binding_hash) = 32),
  redirect_uri text NOT NULL CHECK (octet_length(redirect_uri) <= 128),
  code_challenge text NOT NULL CHECK (octet_length(code_challenge) = 43),
  state text NOT NULL CHECK (octet_length(state) = 43),
  expires_at timestamptz NOT NULL DEFAULT now() + interval '5 minutes'
);
CREATE INDEX cli_auth_requests_expiry ON cli_auth_requests(expires_at);

CREATE TABLE cli_auth_codes (
  code_hash bytea PRIMARY KEY CHECK (octet_length(code_hash) = 32),
  browser_session_hash bytea NOT NULL REFERENCES sessions(token_hash) ON DELETE CASCADE,
  authorization_version bigint NOT NULL,
  redirect_uri text NOT NULL CHECK (octet_length(redirect_uri) <= 128),
  code_challenge text NOT NULL CHECK (octet_length(code_challenge) = 43),
  expires_at timestamptz NOT NULL DEFAULT now() + interval '1 minute'
);
CREATE INDEX cli_auth_codes_expiry ON cli_auth_codes(expires_at);

CREATE TABLE auth_flows (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  state_hash bytea NOT NULL,
  nonce_hash bytea NOT NULL,
  code_verifier text NOT NULL,
  browser_binding_hash bytea NOT NULL,
  redirect_uri text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL DEFAULT now() + interval '10 minutes',
  consumed_at timestamptz NULL,
  CONSTRAINT auth_flows_state_hash_len CHECK (octet_length(state_hash) = 32),
  CONSTRAINT auth_flows_nonce_hash_len CHECK (octet_length(nonce_hash) = 32),
  CONSTRAINT auth_flows_binding_hash_len CHECK (octet_length(browser_binding_hash) = 32),
  CONSTRAINT auth_flows_state_hash_uidx UNIQUE (state_hash),
  CONSTRAINT auth_flows_verifier_len CHECK (char_length(code_verifier) <= 128),
  CONSTRAINT auth_flows_verifier_state CHECK (
    consumed_at IS NOT NULL OR char_length(code_verifier) BETWEEN 43 AND 128
  ),
  CONSTRAINT auth_flows_redirect_len CHECK (char_length(redirect_uri) BETWEEN 1 AND 4096),
  CONSTRAINT auth_flows_ttl CHECK (
    expires_at > created_at AND expires_at <= created_at + interval '10 minutes'
  )
);

CREATE INDEX auth_flows_expires_at_idx ON auth_flows (expires_at);

CREATE TABLE audit_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  occurred_at timestamptz NOT NULL DEFAULT now(),
  actor_id uuid NULL REFERENCES principals (id) ON DELETE RESTRICT,
  action text NOT NULL,
  resource_id text NOT NULL,
  reason text NOT NULL DEFAULT '',
  -- Device identity is retained even if the device is no longer present.
  target_device_id uuid NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT audit_events_details_object CHECK (jsonb_typeof(details) = 'object' AND octet_length(details::text) <= 8192),
  CONSTRAINT audit_events_action_len CHECK (char_length(action) BETWEEN 1 AND 128),
  CONSTRAINT audit_events_resource_len CHECK (char_length(resource_id) BETWEEN 1 AND 512),
  CONSTRAINT audit_events_reason_len CHECK (char_length(reason) <= 512)
);

CREATE INDEX audit_events_keyset ON audit_events (occurred_at DESC, id DESC);

CREATE INDEX audit_events_actor_id_idx ON audit_events (actor_id);

-- Local account UUID is also its immutable principal subject and actor ID.
CREATE TABLE local_accounts (
  id uuid PRIMARY KEY REFERENCES principals(id) ON DELETE RESTRICT,
  username text NOT NULL UNIQUE CHECK (username ~ '^[A-Za-z0-9._-]{1,64}$'),
  role text NOT NULL CHECK (role ~ '^[a-z][a-z0-9_.-]{0,63}$'),
  enabled boolean NOT NULL DEFAULT true,
  break_glass boolean NOT NULL DEFAULT false,
  scope_binding jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(scope_binding) = 'object'),
  password_hash text NOT NULL DEFAULT '' CHECK (octet_length(password_hash) <= 512),
  failed_attempts integer NOT NULL DEFAULT 0 CHECK (failed_attempts BETWEEN 0 AND 5),
  locked_until timestamptz,
  CHECK (NOT break_glass OR role = 'owner')
);

CREATE TABLE local_credentials (
  credential_id bytea PRIMARY KEY CHECK (octet_length(credential_id) BETWEEN 1 AND 1024),
  account_id uuid NOT NULL REFERENCES local_accounts(id) ON DELETE CASCADE,
  credential_json jsonb NOT NULL
);
CREATE INDEX local_credentials_account ON local_credentials(account_id);

CREATE TABLE local_enrollments (
  secret_hash bytea PRIMARY KEY CHECK (octet_length(secret_hash) = 32),
  account_id uuid NOT NULL UNIQUE REFERENCES local_accounts(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL DEFAULT now() + interval '1 hour'
);

CREATE TABLE local_ceremonies (
  token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
  account_id uuid NOT NULL REFERENCES local_accounts(id) ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('login', 'enroll')),
  challenge_hash bytea NOT NULL CHECK (octet_length(challenge_hash) = 32),
  session_data jsonb NOT NULL,
  password_hash text NOT NULL DEFAULT '',
  incident_reason text NOT NULL DEFAULT '' CHECK (char_length(incident_reason) <= 512),
  authorization_version bigint NOT NULL CHECK (authorization_version > 0),
  expires_at timestamptz NOT NULL DEFAULT now() + interval '5 minutes',
  CHECK (session_data->>'challenge' IS NULL OR session_data->>'challenge' = '')
);
CREATE INDEX local_ceremonies_expiry ON local_ceremonies(expires_at);
CREATE UNIQUE INDEX local_ceremonies_account ON local_ceremonies(account_id);

-- Immutable action/target/payload authority; only the decision state can advance.
CREATE TABLE approval_requests (
  id uuid PRIMARY KEY,
  requester_id uuid NOT NULL REFERENCES principals(id) ON DELETE RESTRICT,
  requester_version bigint NOT NULL CHECK (requester_version > 0),
  action text NOT NULL CHECK (action IN ('device.revoke', 'device.recover', 'enrollment.approve', 'resources.assign', 'resources.activate_preview', 'execution_trust.manage', 'device.action', 'recovery_key.reveal')),
  permission text NOT NULL CHECK (
    (action IN ('device.revoke', 'resources.assign', 'execution_trust.manage') AND permission = action)
    OR (action = 'device.action' AND permission IN ('encryption.manage', 'actions.lock', 'actions.release-lock', 'actions.quarantine', 'destructive.execute', 'remote_execution.run', 'inventory.manage'))
    OR (action = 'resources.activate_preview' AND permission = 'resources.assign')
    OR (action = 'recovery_key.reveal' AND permission = 'recovery_keys.read')
    OR (action = 'device.recover' AND permission = 'device.revoke')
    OR (action = 'enrollment.approve' AND permission = 'enrollment.manage')
  ),
  device_id uuid,
  mutation_id text NOT NULL CHECK (octet_length(mutation_id) BETWEEN 1 AND 128),
  payload bytea NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 1048576),
  payload_sha256 bytea NOT NULL CHECK (octet_length(payload_sha256) = 32),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'rejected', 'consumed')),
  approver_id uuid REFERENCES principals(id) ON DELETE RESTRICT,
  approver_version bigint NOT NULL DEFAULT 0,
  decision_reason text NOT NULL DEFAULT '' CHECK (char_length(decision_reason) <= 512),
  consumed_at timestamptz,
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '1 hour'),
  CHECK ((action = 'execution_trust.manage') = (device_id IS NULL)),
  CHECK (approver_id IS NULL OR approver_id <> requester_id),
  CHECK ((state = 'pending' AND approver_id IS NULL AND approver_version = 0)
    OR (state <> 'pending' AND approver_id IS NOT NULL AND approver_version > 0)),
  CHECK ((state = 'consumed') = (consumed_at IS NOT NULL))
);
CREATE INDEX approval_requests_requester ON approval_requests(requester_id, id);
CREATE UNIQUE INDEX approval_requests_mutation ON approval_requests(requester_id, action, mutation_id);

-- SCIM credentials are independent of login sessions and scoped to one connector.
-- Configuration fingerprints fence removed/remapped connectors on old replicas.
CREATE TABLE scim_connectors (
  id text PRIMARY KEY CHECK (id ~ '^[a-z][a-z0-9_-]{0,63}$'),
  config_digest bytea NOT NULL CHECK (octet_length(config_digest) = 32),
  credential_hash bytea UNIQUE CHECK (octet_length(credential_hash) = 32),
  enabled boolean NOT NULL DEFAULT true
);

-- Correlation is durable and immutable, even after resource deletion/config removal.
CREATE TABLE scim_correlations (
  connector_id text NOT NULL REFERENCES scim_connectors(id) ON DELETE RESTRICT,
  provider_id text NOT NULL CHECK (char_length(provider_id) BETWEEN 1 AND 256),
  issuer text NOT NULL CHECK (char_length(issuer) BETWEEN 1 AND 2048),
  subject text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 256),
  PRIMARY KEY (connector_id, provider_id),
  UNIQUE (issuer, subject)
);

CREATE TABLE scim_resources (
  id uuid PRIMARY KEY,
  connector_id text NOT NULL REFERENCES scim_connectors(id) ON DELETE RESTRICT,
  resource_type text NOT NULL CHECK (resource_type IN ('User', 'Group')),
  external_id text NOT NULL DEFAULT '' CHECK (char_length(external_id) <= 256),
  user_name text NOT NULL DEFAULT '' CHECK (char_length(user_name) <= 256),
  principal_id uuid UNIQUE REFERENCES principals(id) ON DELETE RESTRICT,
  document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object' AND octet_length(document::text) <= 131072),
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  modified_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  deleted boolean NOT NULL DEFAULT false,
  CHECK ((resource_type = 'User') = (principal_id IS NOT NULL)),
  UNIQUE (connector_id, id)
);
CREATE UNIQUE INDEX scim_resources_external ON scim_resources(connector_id, resource_type, external_id) WHERE external_id <> '';
CREATE UNIQUE INDEX scim_users_name ON scim_resources(connector_id, lower(user_name)) WHERE resource_type = 'User' AND NOT deleted;
CREATE INDEX scim_resources_page ON scim_resources(connector_id, resource_type, id) WHERE NOT deleted;

CREATE TABLE scim_group_members (
  connector_id text NOT NULL,
  group_id uuid NOT NULL,
  user_id uuid NOT NULL,
  PRIMARY KEY (group_id, user_id),
  FOREIGN KEY (connector_id, group_id) REFERENCES scim_resources(connector_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (connector_id, user_id) REFERENCES scim_resources(connector_id, id) ON DELETE RESTRICT
);

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
  DROP TABLE IF EXISTS scim_group_members;
  DROP TABLE IF EXISTS scim_resources;
  DROP TABLE IF EXISTS scim_correlations;
  DROP TABLE IF EXISTS scim_connectors;
  DROP TABLE IF EXISTS approval_requests;
  DROP TABLE IF EXISTS local_ceremonies;
  DROP TABLE IF EXISTS local_enrollments;
  DROP TABLE IF EXISTS local_credentials;
  DROP TABLE IF EXISTS local_accounts;
  DROP TABLE IF EXISTS audit_events;
  DROP TABLE IF EXISTS cli_auth_codes;
  DROP TABLE IF EXISTS cli_auth_requests;
  DROP TABLE IF EXISTS auth_flows;
  DROP TABLE IF EXISTS sessions;
  DROP TABLE IF EXISTS principal_groups;
  DROP TABLE IF EXISTS principal_lineage;
  DROP TABLE IF EXISTS deployment_identity;
  DROP TABLE IF EXISTS authorization_policy;
  DROP TABLE IF EXISTS principals;
END $$;
-- +goose StatementEnd
