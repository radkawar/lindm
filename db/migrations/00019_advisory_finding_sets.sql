-- SPDX-License-Identifier: Apache-2.0

-- +goose Up

-- Content-addressed advisory finding sets. Matching depends only on the feed
-- generation and the exact published package rows, so devices with identical
-- package sets share one matched set instead of each materializing the same
-- tens of thousands of findings (a stock Ubuntu 24.04 image has ~28,800 against
-- the full OSV export). Devices bind a set through their persisted evaluation;
-- exceptions remain per-device overlays keyed by (device, finding key).
CREATE TABLE advisory_finding_sets (
    id uuid PRIMARY KEY,
    feed_id text NOT NULL,
    feed_revision uuid NOT NULL,
    package_digest bytea NOT NULL CHECK (octet_length(package_digest) = 32),
    state text NOT NULL CHECK (state IN ('evaluated', 'unknown')),
    reason text NOT NULL,
    finding_digest bytea NOT NULL CHECK (octet_length(finding_digest) = 32),
    finding_count integer NOT NULL CHECK (finding_count >= 0),
    critical_count integer NOT NULL CHECK (critical_count >= 0),
    high_count integer NOT NULL CHECK (high_count >= 0),
    medium_count integer NOT NULL CHECK (medium_count >= 0),
    low_count integer NOT NULL CHECK (low_count >= 0),
    other_count integer NOT NULL CHECK (other_count >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (feed_id, feed_revision, package_digest),
    CHECK (finding_count = critical_count + high_count + medium_count + low_count + other_count)
);
CREATE INDEX advisory_finding_sets_created_idx ON advisory_finding_sets(created_at);

-- finding_key is the first 16 bytes of SHA-256 over feed, advisory, package,
-- installed version and architecture joined by NUL; it is device-independent.
CREATE TABLE advisory_set_findings (
    set_id uuid NOT NULL REFERENCES advisory_finding_sets(id) ON DELETE CASCADE,
    finding_key uuid NOT NULL,
    advisory_id text NOT NULL,
    package_name text NOT NULL,
    installed_version text NOT NULL,
    fixed_version text NOT NULL,
    architecture text NOT NULL,
    severity text NOT NULL,
    published_at timestamptz,
    cves text[] NOT NULL,
    source_url text NOT NULL,
    PRIMARY KEY (set_id, finding_key)
);

-- Per-set advisory rollup: fleet summaries weight these rows by bound device
-- counts instead of scanning every device's findings.
CREATE TABLE advisory_set_advisories (
    set_id uuid NOT NULL REFERENCES advisory_finding_sets(id) ON DELETE CASCADE,
    advisory_id text NOT NULL,
    severity text NOT NULL,
    findings integer NOT NULL CHECK (findings > 0),
    PRIMARY KEY (set_id, advisory_id, severity)
);

ALTER TABLE advisory_evaluations
    ADD COLUMN finding_set_id uuid REFERENCES advisory_finding_sets(id) ON DELETE RESTRICT;
CREATE INDEX advisory_evaluations_finding_set_idx ON advisory_evaluations(finding_set_id);

DROP VIEW advisory_finding_status;

-- Exceptions move from device-namespaced finding IDs to (device, finding key).
-- Exceptions whose finding is still materialized are converted exactly; any
-- other (no current finding to derive the key from) is removed with an audit
-- record rather than silently retained in a form that can never match.
ALTER TABLE advisory_exceptions ADD COLUMN finding_key uuid;
UPDATE advisory_exceptions x SET finding_key = encode(substring(sha256(
        convert_to(f.feed_id, 'UTF8') || '\x00'::bytea || convert_to(f.advisory_id, 'UTF8') || '\x00'::bytea ||
        convert_to(f.package_name, 'UTF8') || '\x00'::bytea || convert_to(f.installed_version, 'UTF8') || '\x00'::bytea ||
        convert_to(f.architecture, 'UTF8')) FROM 1 FOR 16), 'hex')::uuid
    FROM advisory_findings f WHERE f.id = x.finding_id AND f.device_id = x.device_id;
INSERT INTO audit_events (id, actor_id, action, resource_id, details)
SELECT gen_random_uuid(), NULL, 'advisory.exception.migration_removed', x.device_id::text,
       jsonb_build_object('context', 'Advisory exception without a current finding could not be converted to a finding-set key')
FROM advisory_exceptions x WHERE x.finding_key IS NULL;
DELETE FROM advisory_exceptions WHERE finding_key IS NULL;
ALTER TABLE advisory_exceptions DROP CONSTRAINT advisory_exceptions_pkey;
ALTER TABLE advisory_exceptions DROP COLUMN finding_id;
ALTER TABLE advisory_exceptions RENAME COLUMN finding_key TO finding_id;
ALTER TABLE advisory_exceptions ALTER COLUMN finding_id SET NOT NULL;
ALTER TABLE advisory_exceptions ADD PRIMARY KEY (device_id, finding_id);

-- Per-device findings were caches of persisted evaluations; re-evaluation by
-- the background job rebuilds them as shared sets. Reads report
-- evaluation_pending until then, never a stale or fabricated result.
DROP TABLE advisory_findings;
DELETE FROM advisory_evaluations;

-- Device-level freshness, shared by the finding projection and set-weighted
-- aggregates so they cannot drift apart.
CREATE VIEW advisory_device_status AS
SELECT e.device_id, e.finding_set_id,
       COALESCE(d.state <> 'active' OR e.state <> 'evaluated'
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

CREATE VIEW advisory_findings AS
SELECT f.finding_key AS id, e.device_id, f.advisory_id, f.package_name, f.installed_version,
       f.fixed_version, f.architecture, f.severity, f.published_at, f.cves, s.feed_id, f.source_url
FROM advisory_evaluations e
JOIN advisory_finding_sets s ON s.id = e.finding_set_id
JOIN advisory_set_findings f ON f.set_id = s.id;

CREATE VIEW advisory_finding_status AS
SELECT f.*,
       e.evaluated_at, e.inventory_at,
       af.checked_at AS feed_checked_at, af.expires_at AS feed_expires_at,
       x.actor_id AS exception_actor_id, x.reason AS exception_reason,
       x.accepted_at, x.expires_at AS exception_expires_at,
       CASE WHEN s.unknown THEN 'unknown'
            WHEN x.expires_at > CURRENT_TIMESTAMP THEN 'accepted'
            ELSE 'affected' END::text AS state
FROM advisory_findings f
JOIN advisory_device_status s ON s.device_id = f.device_id
JOIN advisory_evaluations e ON e.device_id = f.device_id
LEFT JOIN advisory_feeds af ON af.id = e.feed_id
LEFT JOIN advisory_exceptions x ON x.device_id = f.device_id AND x.finding_id = f.id;
