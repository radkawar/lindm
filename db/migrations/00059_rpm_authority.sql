-- SPDX-License-Identifier: Apache-2.0

-- +goose Up
-- Evidence bytes are retained verbatim; signer/reason are computed by server
-- signature verification, never copied from an agent's asserted key identity.
ALTER TABLE snapshot_packages
 ADD COLUMN rpm_authority bytea NOT NULL DEFAULT '' CHECK (octet_length(rpm_authority) <= 1066000),
 ADD COLUMN rpm_signer text NOT NULL DEFAULT '' CHECK (rpm_signer IN ('', '567E347AD0044ADE55BA8A5F199E2F91FD431D51')),
 ADD COLUMN rpm_authority_reason text NOT NULL DEFAULT '',
 ADD COLUMN source_architecture text NOT NULL DEFAULT '' CHECK (source_architecture IN ('','src','nosrc')),
 ADD CONSTRAINT snapshot_packages_rpm_authority_verified
 CHECK (rpm_signer='' OR (octet_length(rpm_authority)>0 AND rpm_authority_reason=''));


-- UNKNOWN remains UNKNOWN when nothing is covered or source scope is lost;
-- retain its actual coverage-gap count instead of silently reporting zero.
ALTER TABLE advisory_evaluations
 DROP CONSTRAINT advisory_evaluations_partial_shape,
 ADD CONSTRAINT advisory_evaluations_partial_shape
 CHECK (state IN ('partial','unknown') OR uncovered_packages=0);

-- Unlike derivative origins, RHEL coverage also depends on the exact selected
-- feed generation's product declarations and scoped source rejections. Bind
-- its explicit uncovered projection to the same immutable finding set.
CREATE TABLE advisory_set_uncovered (
 set_id uuid NOT NULL REFERENCES advisory_finding_sets(id) ON DELETE CASCADE,
 position integer NOT NULL CHECK (position BETWEEN 0 AND 99999),
 name text NOT NULL,
 version text NOT NULL,
 architecture text NOT NULL,
 reason text NOT NULL CHECK (reason <> ''),
 PRIMARY KEY(set_id, position)
);

-- Every fleet read supplies the current runtime's cryptographic root validity.
-- Combine this fence with (never instead of) ordinary persisted freshness.
-- +goose StatementBegin
CREATE FUNCTION advisory_rpm_authority_current(os_id text, os_version text, authority_valid boolean)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
 SELECT coalesce(authority_valid,false) OR os_id<>'rhel'
  OR split_part(os_version,'.',1) NOT IN ('9','10')
$$;
-- +goose StatementEnd

-- Old complete RHEL evaluations predate both cryptographic authority and
-- bounded product membership. They must not survive the unchanged-input fast
-- path; the automatic evaluator rebuilds them using the new cache identity.
DELETE FROM advisory_evaluations e USING advisory_feeds f
WHERE e.feed_id=f.id AND f.distro='rhel' AND split_part(f.release,'.',1) IN ('9','10');

UPDATE lindm_schema_compatibility
SET minimum_runtime_version = 59,
 migration_versions = (
  SELECT array_agg(version ORDER BY version)
  FROM (
   SELECT version FROM (
    SELECT DISTINCT ON(version_id) version_id AS version, is_applied
    FROM goose_db_version ORDER BY version_id, id DESC
   ) latest WHERE is_applied AND version > 0
   UNION SELECT 59::bigint
  ) versions
 );

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 RAISE EXCEPTION 'RPM authority requires a fenced compatible backup restore';
END $$;
-- +goose StatementEnd
