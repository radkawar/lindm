-- +goose Up
-- Root-local approvals each generation's latest accepted host observation
-- reports (lindm.agent.v1.ApprovedConfigurationObservation). Kinds: 1 approved
-- home root (reference_id = root ID, name = path), 2 approved package source
-- (reference_id = repository resource key, name = native repository name).
-- Every accepted observation replaces all rows of its generation; one without
-- the executor observation leaves none, never older reports presented as current.
CREATE TABLE host_approved_references (
    generation_id uuid NOT NULL REFERENCES enrollment_generations (id) ON DELETE CASCADE,
    kind smallint NOT NULL,
    reference_id text NOT NULL,
    name text NOT NULL,
    format text NOT NULL DEFAULT '',
    location text NOT NULL DEFAULT '',
    PRIMARY KEY (generation_id, kind, reference_id),
    CONSTRAINT host_approved_references_kind CHECK (kind BETWEEN 1 AND 2),
    CONSTRAINT host_approved_references_reference_len CHECK (char_length(reference_id) BETWEEN 1 AND 128),
    CONSTRAINT host_approved_references_name_len CHECK (char_length(name) BETWEEN 1 AND 1024),
    CONSTRAINT host_approved_references_format_len CHECK (char_length(format) <= 16),
    CONSTRAINT host_approved_references_location_len CHECK (char_length(location) <= 2048)
);
-- ListApprovedReferences walks one kind in output order from one exclusive start key.
CREATE INDEX host_approved_references_list_idx
    ON host_approved_references (kind, (lower(name COLLATE "C")), (name COLLATE "C"), (reference_id COLLATE "C"), generation_id);

-- +goose Down
DROP TABLE host_approved_references;
