-- +goose Up

-- Staging ownership and retired work share one durable key. A live writer renews
-- its lease inside each batch transaction; expired ownership cannot publish.
CREATE TABLE advisory_generation_cleanup (
    feed_id text NOT NULL REFERENCES advisory_feeds(id) ON DELETE CASCADE,
    generation uuid NOT NULL,
    cleanup_after timestamptz NOT NULL,
    PRIMARY KEY (feed_id, generation)
);
CREATE INDEX advisory_generation_cleanup_due_idx
    ON advisory_generation_cleanup(cleanup_after, feed_id, generation);
-- Pre-lease maintained import commands have a thirty-minute context. Give every
-- preexisting inactive generation thirty-five minutes before reclaiming it.
-- A publisher that wins during this grace is protected by the active fence.
INSERT INTO advisory_generation_cleanup(feed_id,generation,cleanup_after)
SELECT r.feed_id,r.generation,clock_timestamp()+interval '35 minutes'
FROM advisory_record_generations r
WHERE NOT EXISTS (SELECT 1 FROM advisory_feeds f WHERE f.id=r.feed_id AND f.revision=r.generation)
GROUP BY r.feed_id,r.generation;

-- Preserve explicit runtime grants where deployments do not use default ACLs.
-- +goose StatementBegin
DO $$
DECLARE
    permission record;
    recipient text;
BEGIN
    FOR permission IN
        SELECT a.grantee,a.privilege_type,a.is_grantable
        FROM pg_class c
        CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a
        WHERE c.oid='advisory_record_generations'::regclass
          AND a.privilege_type IN ('SELECT','INSERT','UPDATE','DELETE')
    LOOP
        recipient := CASE WHEN permission.grantee=0 THEN 'PUBLIC'
                          ELSE quote_ident(pg_get_userbyid(permission.grantee)) END;
        EXECUTE format('GRANT %s ON TABLE advisory_generation_cleanup TO %s%s',
                       permission.privilege_type,recipient,
                       CASE WHEN permission.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END);
    END LOOP;
END;
$$;
-- +goose StatementEnd
