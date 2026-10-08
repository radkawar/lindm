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
  CONSTRAINT principals_issuer_len CHECK (char_length(issuer) BETWEEN 1 AND 2048),
  CONSTRAINT principals_subject_len CHECK (char_length(subject) BETWEEN 1 AND 256),
  CONSTRAINT principals_display_name_len CHECK (char_length(display_name) <= 256),
  CONSTRAINT principals_pinned_role_chk CHECK (pinned_role IN ('', 'owner')),
  CONSTRAINT principals_deactivation_source_chk CHECK (deactivation_source IN ('', 'keycloak', 'scim')),
  CONSTRAINT principals_deactivation_pair CHECK (
    (deactivated_at IS NULL AND deactivation_source = '')
    OR (deactivated_at IS NOT NULL AND deactivation_source <> '')
  ),
  CONSTRAINT principals_issuer_subject_uidx UNIQUE (issuer, subject)
);

CREATE UNIQUE INDEX principals_one_owner ON principals (pinned_role) WHERE pinned_role = 'owner';

CREATE TABLE deployment_identity (
  id boolean PRIMARY KEY DEFAULT true CHECK (id),
  owner_principal_id uuid NULL REFERENCES principals (id) ON DELETE RESTRICT,
  initialized_at timestamptz NULL,
  CONSTRAINT deployment_identity_pair CHECK (
    (owner_principal_id IS NULL AND initialized_at IS NULL)
    OR (owner_principal_id IS NOT NULL AND initialized_at IS NOT NULL)
  )
);

INSERT INTO deployment_identity (id) VALUES (true);

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
  CONSTRAINT audit_events_action_len CHECK (char_length(action) BETWEEN 1 AND 128),
  CONSTRAINT audit_events_resource_len CHECK (char_length(resource_id) BETWEEN 1 AND 512),
  CONSTRAINT audit_events_reason_len CHECK (char_length(reason) <= 512)
);

CREATE INDEX audit_events_keyset ON audit_events (occurred_at DESC, id DESC);

CREATE INDEX audit_events_actor_id_idx ON audit_events (actor_id);

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
  DROP TABLE IF EXISTS audit_events;
  DROP TABLE IF EXISTS auth_flows;
  DROP TABLE IF EXISTS sessions;
  DROP TABLE IF EXISTS principal_groups;
  DROP TABLE IF EXISTS principal_lineage;
  DROP TABLE IF EXISTS deployment_identity;
  DROP TABLE IF EXISTS principals;
END $$;
-- +goose StatementEnd
