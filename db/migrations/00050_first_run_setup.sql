-- SPDX-License-Identifier: Apache-2.0

-- Hash-only first-run capability and bounded, durable request admission.
-- lindm:online-compatible minimum-runtime=49
-- +goose Up
CREATE TABLE first_run_setup (
  id boolean PRIMARY KEY DEFAULT true CHECK (id),
  code_hash bytea NOT NULL CHECK (octet_length(code_hash) = 32),
  expires_at timestamptz NOT NULL,
  account_id uuid REFERENCES local_accounts(id) ON DELETE RESTRICT,
  consumed_at timestamptz,
  CHECK (consumed_at IS NULL OR account_id IS NOT NULL)
);
CREATE TABLE first_run_attempts (
  bucket_hash bytea PRIMARY KEY CHECK (octet_length(bucket_hash) = 32),
  window_at timestamptz NOT NULL,
  attempts integer NOT NULL CHECK (attempts BETWEEN 1 AND 60)
);

-- Runtime may reserve/consume a capability, never issue/rotate its hash or expiry.
-- Preserve only the relevant subset of each inherited grant; never turn a
-- read-only grantee into a writer. The migration/table owner retains issuance.
-- +goose StatementBegin
DO $$
DECLARE grant_row record;
BEGIN
  REVOKE ALL ON first_run_setup FROM PUBLIC;
  FOR grant_row IN
    SELECT grantee,
      bool_or(privilege_type = 'SELECT') AS may_read,
      bool_or(privilege_type = 'UPDATE') AS may_update
    FROM information_schema.table_privileges
    WHERE table_schema = current_schema() AND table_name = 'first_run_setup'
      AND grantee <> (
        SELECT pg_get_userbyid(relowner) FROM pg_class
        WHERE oid = 'first_run_setup'::regclass
      )
    GROUP BY grantee
  LOOP
    EXECUTE format('REVOKE ALL ON first_run_setup FROM %I', grant_row.grantee);
    IF grant_row.may_read THEN
      EXECUTE format('GRANT SELECT ON first_run_setup TO %I', grant_row.grantee);
    END IF;
    IF grant_row.may_update THEN
      EXECUTE format('GRANT UPDATE (account_id, consumed_at) ON first_run_setup TO %I', grant_row.grantee);
    END IF;
  END LOOP;
END $$;
-- +goose StatementEnd


UPDATE lindm_schema_compatibility
SET migration_versions = (
  SELECT array_agg(version ORDER BY version)
  FROM (
    SELECT version FROM (
      SELECT DISTINCT ON (version_id) version_id AS version, is_applied
      FROM goose_db_version ORDER BY version_id, id DESC
    ) latest WHERE is_applied AND version > 0
    UNION SELECT 50::bigint
  ) versions
);
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
  DROP TABLE first_run_attempts;
  DROP TABLE first_run_setup;
END $$;
-- +goose StatementEnd
