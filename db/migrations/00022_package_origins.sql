-- +goose Up

-- APT origin evidence for each installed package: every index in
-- /var/lib/apt/lists that lists the exact installed name, version and
-- architecture, with its Release metadata and the agent's own signature
-- verification. origin_status is the lindm.inventory.v1.CollectionStatus of
-- the observation; 0 is historical evidence collected before origins existed.
ALTER TABLE snapshot_packages
    ADD COLUMN origin_status smallint NOT NULL DEFAULT 0,
    ADD CONSTRAINT snapshot_packages_origin_status CHECK (origin_status BETWEEN 0 AND 7);

-- signature is lindm.inventory.v1.AptReleaseSignature: 1 verified (signer is
-- the verifying primary-key fingerprint), 2 unsigned, 3 unverified.
CREATE TABLE snapshot_package_listings (
    snapshot_id uuid NOT NULL,
    position integer NOT NULL,
    ordinal smallint NOT NULL CHECK (ordinal BETWEEN 0 AND 15),
    origin text NOT NULL CHECK (char_length(origin) <= 256),
    label text NOT NULL CHECK (char_length(label) <= 256),
    suite text NOT NULL CHECK (char_length(suite) <= 256),
    codename text NOT NULL CHECK (char_length(codename) <= 256),
    signature smallint NOT NULL CHECK (signature BETWEEN 1 AND 3),
    signer text NOT NULL CHECK (signer ~ '^([0-9A-F]{40}|[0-9A-F]{64})?$'),
    PRIMARY KEY (snapshot_id, position, ordinal),
    FOREIGN KEY (snapshot_id, position) REFERENCES snapshot_packages (snapshot_id, position) ON DELETE CASCADE,
    CHECK ((signature = 1) = (signer <> ''))
);

-- Coverage of one package by a base release's feed on a derivative device.
-- '' means every listing is a verified base-archive index of a covered suite;
-- any other value is the package's UNKNOWN reason. The archive identity,
-- suites, signers and vendor origins are parameters from the platform
-- registry (internal/platform), never stored policy.
-- +goose StatementBegin
CREATE FUNCTION advisory_origin_reason(
    p_snapshot uuid, p_position integer, p_status smallint, p_origin text, p_codename text,
    p_suites text[], p_signers text[], p_vendor_origins text[])
RETURNS text LANGUAGE sql STABLE AS $$
    SELECT CASE
        WHEN p_status <> 1 THEN 'origin_unavailable'
        WHEN count(*) = 0 THEN 'origin_unlisted'
        WHEN bool_and(s.base) THEN ''
        WHEN bool_or(s.base) THEN 'origin_ambiguous'
        WHEN bool_or(s.vendor) THEN 'vendor_feed_unavailable'
        WHEN bool_or(s.base_archive) THEN 'base_pocket_uncovered'
        WHEN bool_or(s.verified) THEN 'origin_not_covered'
        ELSE 'origin_unverified' END
    FROM (
        SELECT l.signature = 1 AND l.origin = p_origin AND l.signer = ANY(p_signers)
                   AND l.codename = p_codename AND l.suite = ANY(p_suites) AS base,
               l.signature = 1 AND l.origin = ANY(p_vendor_origins) AS vendor,
               l.signature = 1 AND l.origin = p_origin AND l.signer = ANY(p_signers) AS base_archive,
               l.signature = 1 AS verified
        FROM snapshot_package_listings l
        WHERE l.snapshot_id = p_snapshot AND l.position = p_position
    ) s
$$;
-- +goose StatementEnd

-- A set matched under derivative coverage records how many packages it left
-- uncovered. Its package digest folds in the coverage policy and every
-- package's origin evidence, so it is never shared with a complete match.
ALTER TABLE advisory_finding_sets
    ADD COLUMN uncovered_packages integer NOT NULL DEFAULT 0 CHECK (uncovered_packages >= 0);

-- 'partial': a base feed applied to the verified base-archive packages of a
-- derivative device, which is never evaluated completely; uncovered_packages
-- counts every other installed package and is recorded only for 'partial'.
ALTER TABLE advisory_evaluations
    DROP CONSTRAINT advisory_evaluations_state_check,
    ADD CONSTRAINT advisory_evaluations_state_check CHECK (state IN ('evaluated', 'partial', 'unknown')),
    ADD COLUMN uncovered_packages integer NOT NULL DEFAULT 0 CHECK (uncovered_packages >= 0),
    ADD CONSTRAINT advisory_evaluations_partial_shape CHECK (state = 'partial' OR uncovered_packages = 0);

-- Findings of a partial evaluation are current exposure of covered packages:
-- the shared freshness predicate treats 'partial' like 'evaluated'.
CREATE OR REPLACE VIEW advisory_device_status AS
SELECT e.device_id, e.finding_set_id,
       COALESCE(d.state <> 'active' OR e.state NOT IN ('evaluated', 'partial')
                 OR e.expires_at <= CURRENT_TIMESTAMP
                 OR g.current_snapshot_id IS DISTINCT FROM e.snapshot_id
                 OR e.host_received_at IS DISTINCT FROM d.host_received_at
                 OR pa.status IS DISTINCT FROM 1::smallint
                 OR af.revision IS DISTINCT FROM e.feed_revision
                 OR NOT af.enabled OR af.expires_at IS NULL OR af.expires_at <= CURRENT_TIMESTAMP, false) AS unknown
FROM advisory_evaluations e
JOIN devices d ON d.id = e.device_id
LEFT JOIN enrollment_generations g ON g.id = d.current_generation_id
LEFT JOIN package_attempts pa ON pa.generation_id = g.id
LEFT JOIN advisory_feeds af ON af.id = e.feed_id;
