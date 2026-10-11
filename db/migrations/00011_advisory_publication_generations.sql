-- +goose Up

-- Forward-only cutover: legacy readers keep the exact advisory_records columns,
-- but can see only the generation selected by the feed's committed revision.
-- Hold the feed lock before the record lock, matching publication lock order.
-- Backfill and view replacement commit together. DROP the original relation, not
-- merely rename it: pre-migration prepared statements must lose its old OID and
-- re-resolve advisory_records to the view, never bypass its generation filter.
LOCK TABLE advisory_feeds, advisory_records IN ACCESS EXCLUSIVE MODE;

ALTER TABLE advisory_feeds DROP CONSTRAINT advisory_feeds_advisory_count_check;
ALTER TABLE advisory_feeds ADD CONSTRAINT advisory_feeds_advisory_count_check
    CHECK (advisory_count BETWEEN 0 AND 20000000);

CREATE TABLE advisory_record_generations (
    generation uuid NOT NULL,
    id uuid NOT NULL,
    feed_id text NOT NULL REFERENCES advisory_feeds(id) ON DELETE CASCADE,
    advisory_id text NOT NULL,
    package_name text NOT NULL,
    source_package boolean NOT NULL,
    architecture text NOT NULL,
    record_bytes bytea NOT NULL CHECK (octet_length(record_bytes) BETWEEN 1 AND 65536),
    PRIMARY KEY (feed_id, generation, id)
);
CREATE INDEX advisory_record_generations_match_idx
    ON advisory_record_generations(feed_id, generation, package_name);
INSERT INTO advisory_record_generations(generation,id,feed_id,advisory_id,package_name,source_package,architecture,record_bytes)
SELECT f.revision,r.id,r.feed_id,r.advisory_id,r.package_name,r.source_package,r.architecture,r.record_bytes
FROM advisory_records r JOIN advisory_feeds f ON f.id=r.feed_id;

-- Scratch rows live only inside a single batch transaction: COPY, merge with
-- ON CONFLICT, then DELETE. Ordinals bound each publication's scratch batch to
-- 4096 even when every emitted claim is a duplicate. Distinct publication IDs
-- isolate concurrent writers. Runtime DDL and TEMPORARY privileges are not needed.
CREATE TABLE advisory_publication_batch (
    publication_id uuid NOT NULL,
    position smallint NOT NULL CHECK (position BETWEEN 0 AND 4095),
    id uuid NOT NULL,
    feed_id text NOT NULL REFERENCES advisory_feeds(id) ON DELETE CASCADE,
    advisory_id text NOT NULL,
    package_name text NOT NULL,
    source_package boolean NOT NULL,
    architecture text NOT NULL,
    record_bytes bytea NOT NULL CHECK (octet_length(record_bytes) BETWEEN 1 AND 65536),
    PRIMARY KEY (publication_id, position)
);

-- Preserve explicit legacy writer/reader ACLs as well as deployment defaults.
-- No role names or new database-level privileges are assumed by this migration.
-- +goose StatementBegin
DO $$
DECLARE
    permission record;
    recipient text;
BEGIN
    FOR permission IN
        SELECT a.grantee, a.privilege_type, a.is_grantable
        FROM pg_class c
        CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a
        WHERE c.oid = 'advisory_records'::regclass
          AND a.privilege_type IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
    LOOP
        recipient := CASE WHEN permission.grantee = 0 THEN 'PUBLIC'
                          ELSE quote_ident(pg_get_userbyid(permission.grantee)) END;
        EXECUTE format('GRANT %s ON TABLE advisory_record_generations, advisory_publication_batch TO %s%s',
                       permission.privilege_type, recipient,
                       CASE WHEN permission.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END);
    END LOOP;
END;
$$;
-- +goose StatementEnd

DROP TABLE advisory_records;
CREATE VIEW advisory_records AS
SELECT r.id, r.feed_id, r.advisory_id, r.package_name, r.source_package,
       r.architecture, r.record_bytes
FROM advisory_record_generations r
JOIN advisory_feeds f ON f.id = r.feed_id AND f.revision = r.generation;

-- The canonical active-record view is read-only. Publishers write to the
-- generation and batch tables explicitly, never through this projection.
-- +goose StatementBegin
DO $$
DECLARE
    permission record;
    recipient text;
BEGIN
    FOR permission IN
        SELECT a.grantee, a.is_grantable
        FROM pg_class c
        CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a
        WHERE c.oid = 'advisory_record_generations'::regclass
          AND a.privilege_type = 'SELECT'
    LOOP
        recipient := CASE WHEN permission.grantee = 0 THEN 'PUBLIC'
                          ELSE quote_ident(pg_get_userbyid(permission.grantee)) END;
        EXECUTE format('GRANT SELECT ON TABLE advisory_records TO %s%s', recipient,
                       CASE WHEN permission.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END);
    END LOOP;
END;
$$;
-- +goose StatementEnd
