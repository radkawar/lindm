-- +goose Up

-- Matching reads candidates in keyset pages over (package position, record id):
-- one installed Ubuntu kernel binary alone matches about 10,000 records, so a
-- fixed package window cannot bound a query. A trailing id returns each
-- package's records in page order without sorting the rest of the snapshot.
DROP INDEX advisory_record_generations_identity_idx;
CREATE INDEX advisory_record_generations_identity_idx
    ON advisory_record_generations(feed_id, generation, source_package, package_name, id);
