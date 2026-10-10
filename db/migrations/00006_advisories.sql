-- +goose Up

-- Advisory feeds are published atomically. Evaluations refer to the exact feed
-- revision and published inventory snapshot; stale/mismatched evidence is unknown.
CREATE TABLE advisory_feeds (
    id text PRIMARY KEY CHECK (char_length(id) BETWEEN 1 AND 128),
    distro text NOT NULL,
    release text NOT NULL,
    platform_stream text NOT NULL DEFAULT '',
    source_url text NOT NULL,
    config_bytes bytea NOT NULL,
    revision uuid NOT NULL,
    source_sha256 bytea NOT NULL DEFAULT '' CHECK (octet_length(source_sha256) IN (0, 32)),
    source_manifest bytea NOT NULL DEFAULT '' CHECK (octet_length(source_manifest) <= 65536),
    snapshot_at timestamptz,
    checked_at timestamptz,
    expires_at timestamptz,
    attempted_at timestamptz,
    error text NOT NULL DEFAULT '',
    advisory_count bigint NOT NULL DEFAULT 0 CHECK (advisory_count BETWEEN 0 AND 1000000),
    enabled boolean NOT NULL DEFAULT true,
    complete_snapshot boolean NOT NULL DEFAULT false,
    UNIQUE (distro, release, platform_stream)
);

CREATE TABLE advisory_records (
    id uuid PRIMARY KEY,
    feed_id text NOT NULL REFERENCES advisory_feeds(id) ON DELETE CASCADE,
    advisory_id text NOT NULL,
    package_name text NOT NULL,
    source_package boolean NOT NULL,
    architecture text NOT NULL,
    record_bytes bytea NOT NULL CHECK (octet_length(record_bytes) BETWEEN 1 AND 65536)
);
CREATE INDEX advisory_records_match_idx ON advisory_records(feed_id, package_name);

CREATE TABLE advisory_evaluations (
    device_id uuid PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    id uuid NOT NULL,
    snapshot_id uuid,
    feed_id text NOT NULL DEFAULT '',
    feed_revision uuid,
    evaluated_at timestamptz NOT NULL,
    inventory_at timestamptz,
    host_received_at timestamptz,
    expires_at timestamptz NOT NULL,
    state text NOT NULL CHECK (state IN ('evaluated', 'unknown')),
    reason text NOT NULL,
    finding_digest bytea NOT NULL CHECK (octet_length(finding_digest) = 32)
);

CREATE TABLE advisory_findings (
    id uuid PRIMARY KEY,
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    advisory_id text NOT NULL,
    package_name text NOT NULL,
    installed_version text NOT NULL,
    fixed_version text NOT NULL,
    architecture text NOT NULL,
    severity text NOT NULL,
    published_at timestamptz,
    cves text[] NOT NULL,
    feed_id text NOT NULL,
    source_url text NOT NULL
);
CREATE INDEX advisory_findings_device_idx ON advisory_findings(device_id, id);
CREATE INDEX advisory_findings_advisory_idx ON advisory_findings(advisory_id, severity, device_id);

-- Retained independently of the current finding cache so a refresh does not
-- extend or erase an accepted risk. The ID binds package/advisory/version/device.
CREATE TABLE advisory_exceptions (
    finding_id uuid PRIMARY KEY,
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    actor_id uuid NOT NULL REFERENCES principals(id) ON DELETE RESTRICT,
    reason text NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 512 AND reason ~ '\S'),
    accepted_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > accepted_at AND expires_at <= accepted_at + interval '366 days')
);

CREATE TABLE advisory_exception_requests (
    actor_id uuid NOT NULL REFERENCES principals(id) ON DELETE RESTRICT,
    request_id uuid NOT NULL,
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    response_bytes bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(actor_id, request_id)
);
CREATE INDEX advisory_exception_requests_expiry ON advisory_exception_requests(created_at);
CREATE INDEX advisory_exceptions_expiry ON advisory_exceptions(expires_at);

-- Shared report/read projection. Exception expiry is evaluated at read time;
-- outdated snapshots/feeds cannot remain green until a worker happens to run.
CREATE VIEW advisory_finding_status AS
SELECT f.*,
       e.evaluated_at, e.inventory_at,
       af.checked_at AS feed_checked_at, af.expires_at AS feed_expires_at,
       x.actor_id AS exception_actor_id, x.reason AS exception_reason,
       x.accepted_at, x.expires_at AS exception_expires_at,
       CASE WHEN d.state <> 'active' OR e.state <> 'evaluated'
                 OR e.expires_at <= CURRENT_TIMESTAMP
                 OR g.current_snapshot_id IS DISTINCT FROM e.snapshot_id
                 OR e.host_received_at IS DISTINCT FROM d.host_received_at
                 OR pa.status IS DISTINCT FROM 1::smallint
                 OR af.revision IS DISTINCT FROM e.feed_revision
                 OR NOT af.enabled OR af.expires_at IS NULL OR af.expires_at <= CURRENT_TIMESTAMP
            THEN 'unknown'
            WHEN x.expires_at > CURRENT_TIMESTAMP THEN 'accepted'
            ELSE 'affected' END::text AS state
FROM advisory_findings f
JOIN devices d ON d.id = f.device_id
JOIN advisory_evaluations e ON e.device_id = f.device_id
LEFT JOIN enrollment_generations g ON g.id = d.current_generation_id
LEFT JOIN package_attempts pa ON pa.generation_id = g.id
LEFT JOIN advisory_feeds af ON af.id = e.feed_id
LEFT JOIN advisory_exceptions x ON x.finding_id = f.id;
