-- +goose Up
-- Keep the one-open-effect fence while an ungranted package staging unit is
-- being cancelled. closed_at, not the requested closure reason, is terminal.
-- The original closure check was unnamed; locate only its exact two-column key.
-- +goose StatementBegin
DO $$
DECLARE
    closure_check name;
BEGIN
    SELECT c.conname INTO STRICT closure_check
    FROM pg_constraint c
    JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attname = 'closed_at'
    JOIN pg_attribute r ON r.attrelid = c.conrelid AND r.attname = 'closed_reason'
    WHERE c.conrelid = 'resource_actions'::regclass AND c.contype = 'c'
      AND cardinality(c.conkey) = 2 AND c.conkey @> ARRAY[a.attnum, r.attnum];
    EXECUTE format('ALTER TABLE resource_actions DROP CONSTRAINT %I', closure_check);
END;
$$;
-- +goose StatementEnd
ALTER TABLE resource_actions ADD CONSTRAINT resource_actions_preparation_closure CHECK (
    (closed_at IS NULL) = (closed_reason = '') OR
    (closed_at IS NULL AND octet_length(start_grant_envelope) = 0 AND
     closed_reason IN ('assignment_changed', 'expired_unstarted', 'authority_changed', 'targeting_paused_or_changed'))
);

-- Persist the independently consumed approval, never a profile-supplied marker.
ALTER TABLE resource_assignments ADD COLUMN adoption_approval_id uuid REFERENCES approval_requests(id);
-- Release work retains the original resource FK and its separate current-head
-- authority fence in the signed intent. One open action per device still applies.
ALTER TABLE resource_actions ADD COLUMN release_id uuid REFERENCES resource_releases(id);
CREATE INDEX resource_actions_release ON resource_actions(release_id) WHERE release_id IS NOT NULL;
ALTER TABLE resource_releases ALTER COLUMN state SET DEFAULT 'pending';
ALTER TABLE resource_releases ALTER COLUMN reason SET DEFAULT '';

-- Managed file, sysctl, systemd definition and encryption compliance extend the
-- closed kind registry to 24. Each original column check is the default name.
ALTER TABLE profile_resources DROP CONSTRAINT profile_resources_resource_kind_check,
    ADD CONSTRAINT profile_resources_resource_kind_check CHECK (resource_kind BETWEEN 1 AND 24);
ALTER TABLE resource_sequences DROP CONSTRAINT resource_sequences_resource_kind_check,
    ADD CONSTRAINT resource_sequences_resource_kind_check CHECK (resource_kind BETWEEN 1 AND 24);
ALTER TABLE resource_assignment_resources DROP CONSTRAINT resource_assignment_resources_resource_kind_check,
    ADD CONSTRAINT resource_assignment_resources_resource_kind_check CHECK (resource_kind BETWEEN 1 AND 24);
ALTER TABLE resource_releases DROP CONSTRAINT resource_releases_resource_kind_check,
    ADD CONSTRAINT resource_releases_resource_kind_check CHECK (resource_kind BETWEEN 1 AND 24);

-- +goose Down
-- Downgrade refuses rows of the newer kinds rather than deleting them.
ALTER TABLE resource_releases DROP CONSTRAINT resource_releases_resource_kind_check,
    ADD CONSTRAINT resource_releases_resource_kind_check CHECK (resource_kind BETWEEN 1 AND 20);
ALTER TABLE resource_assignment_resources DROP CONSTRAINT resource_assignment_resources_resource_kind_check,
    ADD CONSTRAINT resource_assignment_resources_resource_kind_check CHECK (resource_kind BETWEEN 1 AND 20);
ALTER TABLE resource_sequences DROP CONSTRAINT resource_sequences_resource_kind_check,
    ADD CONSTRAINT resource_sequences_resource_kind_check CHECK (resource_kind BETWEEN 1 AND 20);
ALTER TABLE profile_resources DROP CONSTRAINT profile_resources_resource_kind_check,
    ADD CONSTRAINT profile_resources_resource_kind_check CHECK (resource_kind BETWEEN 1 AND 20);
ALTER TABLE resource_releases ALTER COLUMN reason SET DEFAULT 'ownership_baseline_unavailable';
ALTER TABLE resource_releases ALTER COLUMN state SET DEFAULT 'baseline_unknown';
DROP INDEX resource_actions_release;
ALTER TABLE resource_actions DROP COLUMN release_id;
ALTER TABLE resource_assignments DROP COLUMN adoption_approval_id;
-- Downgrade refuses pending cleanup rather than dropping its action fence.
ALTER TABLE resource_actions DROP CONSTRAINT resource_actions_preparation_closure;
ALTER TABLE resource_actions ADD CONSTRAINT resource_actions_closure CHECK ((closed_at IS NULL) = (closed_reason = ''));
