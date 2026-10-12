-- +goose Up
-- Searchable values derived from each generation's latest accepted host
-- observation (host_observations.details is an opaque protobuf). Kinds: 1 local
-- account name, 2 login shell, 3 Flatpak application ID, 4 snap name. Every
-- accepted observation replaces all kinds; a failed collection leaves its kind
-- empty, as GetDevice shows the latest evidence rather than older successes.
CREATE TABLE host_inventory_values (
    generation_id uuid NOT NULL REFERENCES enrollment_generations (id) ON DELETE CASCADE,
    kind smallint NOT NULL,
    value text NOT NULL,
    PRIMARY KEY (generation_id, kind, value),
    CONSTRAINT host_inventory_values_kind CHECK (kind BETWEEN 1 AND 4),
    CONSTRAINT host_inventory_values_value_len CHECK (char_length(value) BETWEEN 1 AND 4096)
);
-- SuggestValues walks one kind in output order from one exclusive start key.
CREATE INDEX host_inventory_values_suggest_idx
    ON host_inventory_values (kind, (lower(value COLLATE "C")), (value COLLATE "C"), generation_id);

-- +goose Down
DROP TABLE host_inventory_values;
