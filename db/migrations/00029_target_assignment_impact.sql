-- +goose Up
-- Short-lived review evidence, never an assignment or native execution head.
CREATE TABLE target_assignment_impact_reports (
    id uuid PRIMARY KEY,
    actor_id uuid NOT NULL REFERENCES principals(id),
    document bytea NOT NULL CHECK (octet_length(document) BETWEEN 1 AND 1048576),
    input_digest bytea NOT NULL CHECK (octet_length(input_digest) = 32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL
);
CREATE INDEX target_assignment_impact_actor ON target_assignment_impact_reports(actor_id, created_at, id);
CREATE INDEX target_assignment_impact_expiry ON target_assignment_impact_reports(expires_at, id);
CREATE TABLE target_assignment_impact_devices (
    report_id uuid NOT NULL REFERENCES target_assignment_impact_reports(id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    device_id uuid NOT NULL,
    document bytea NOT NULL CHECK (octet_length(document) BETWEEN 1 AND 1048576),
    PRIMARY KEY (report_id, device_id)
);
-- Reports may expire/evict, but live evidence cannot be rewritten.
CREATE TRIGGER immutable_impact_report BEFORE UPDATE ON target_assignment_impact_reports FOR EACH ROW EXECUTE FUNCTION reject_targeting_history_mutation();
CREATE TRIGGER immutable_impact_device BEFORE UPDATE ON target_assignment_impact_devices FOR EACH ROW EXECUTE FUNCTION reject_targeting_history_mutation();

-- +goose Down
DROP TABLE target_assignment_impact_devices, target_assignment_impact_reports;
