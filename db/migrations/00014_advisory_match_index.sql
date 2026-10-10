-- +goose Up

-- Matching probes binary and source identities separately. One OR join over both
-- name columns cannot use a single equality index and degraded to a scan of the
-- whole feed generation (millions of Ubuntu rows) per package batch. The leading
-- source_package column lets each branch resolve exact (feed, generation, kind,
-- name) keys; cleanup keeps using the primary key.
CREATE INDEX advisory_record_generations_identity_idx
    ON advisory_record_generations(feed_id, generation, source_package, package_name);
DROP INDEX advisory_record_generations_match_idx;

-- Feed selection depends only on enabled feed configuration. The background
-- evaluator rechecks devices evaluated without an applicable feed whenever any
-- process configures or re-enables a feed after that evaluation. Existing feeds
-- count as configured now, so such devices are rechecked once after upgrade.
ALTER TABLE advisory_feeds ADD COLUMN configured_at timestamptz NOT NULL DEFAULT clock_timestamp();
