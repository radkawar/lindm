-- SPDX-License-Identifier: Apache-2.0

-- +goose Up
-- The initial compatibility-policy cutover requires fenced installation.
-- Future expand migrations must update this record in the same transaction as DDL.
CREATE TABLE lindm_schema_compatibility (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    minimum_runtime_version bigint NOT NULL CHECK (minimum_runtime_version > 0),
    migration_versions bigint[] NOT NULL CHECK (cardinality(migration_versions) > 0)
);
REVOKE ALL ON lindm_schema_compatibility FROM PUBLIC;
-- Default runtime table grants must not make the compatibility floor writable.
-- Revoke every non-owner grantee, without assuming a deployment role name.
-- +goose StatementBegin
DO $$
DECLARE granted_role text;
BEGIN
    FOR granted_role IN
        SELECT DISTINCT pg_get_userbyid(privilege.grantee)
        FROM pg_class relation
        CROSS JOIN LATERAL aclexplode(coalesce(relation.relacl, acldefault('r', relation.relowner))) privilege
        WHERE relation.oid = 'lindm_schema_compatibility'::regclass
          AND privilege.grantee <> relation.relowner AND privilege.grantee <> 0
    LOOP
        EXECUTE format('REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON lindm_schema_compatibility FROM %I', granted_role);
    END LOOP;
END $$;
-- +goose StatementEnd
INSERT INTO lindm_schema_compatibility(singleton, minimum_runtime_version, migration_versions)
SELECT true, 49, array_agg(version ORDER BY version)
FROM (
    SELECT version FROM (
        SELECT DISTINCT ON (version_id) version_id AS version, is_applied
        FROM goose_db_version ORDER BY version_id, id DESC
    ) latest WHERE is_applied AND version > 0
    UNION SELECT 49::bigint
) versions;

-- +goose Down
DROP TABLE lindm_schema_compatibility;
