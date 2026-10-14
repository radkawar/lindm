-- SPDX-License-Identifier: Apache-2.0

-- +goose Up
-- Recovery fencing is a runtime contract: older servers must not serve this schema.
CREATE TABLE server_recovery_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    hold boolean NOT NULL DEFAULT false,
    recovery_epoch numeric(20,0) NOT NULL DEFAULT 0 CHECK (recovery_epoch >= 0),
    checkpoint_sha256 bytea NOT NULL DEFAULT '' CHECK (octet_length(checkpoint_sha256) IN (0,32)),
    reconciled_at timestamptz
);
REVOKE ALL ON server_recovery_state FROM PUBLIC;
INSERT INTO server_recovery_state(singleton) VALUES (true);
-- Exclude every non-owner default-ACL grantee transactionally, without naming a
-- deployment-specific runtime role. Runtime consumers need only SELECT.
-- +goose StatementBegin
DO $$
DECLARE granted_role text;
BEGIN
    FOR granted_role IN
        SELECT DISTINCT pg_get_userbyid(privilege.grantee)
        FROM pg_class relation
        CROSS JOIN LATERAL aclexplode(coalesce(relation.relacl, acldefault('r', relation.relowner))) privilege
        WHERE relation.oid = 'server_recovery_state'::regclass
          AND privilege.grantee <> relation.relowner AND privilege.grantee <> 0
    LOOP
        EXECUTE format('REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON server_recovery_state FROM %I', granted_role);
    END LOOP;
END $$;
-- +goose StatementEnd
UPDATE lindm_schema_compatibility
SET minimum_runtime_version = 51,
    migration_versions = (
        SELECT array_agg(version ORDER BY version)
        FROM (
            SELECT version FROM (
                SELECT DISTINCT ON(version_id) version_id AS version, is_applied
                FROM goose_db_version ORDER BY version_id, id DESC
            ) latest WHERE is_applied AND version > 0
            UNION SELECT 51::bigint
        ) versions
    );

-- +goose Down
-- A recovery fence cannot safely be removed while restored state is retained.
-- +goose StatementBegin
DO $$
BEGIN
    RAISE EXCEPTION 'server recovery fencing is irreversible; restore a compatible release instead';
END $$;
-- +goose StatementEnd
