-- SPDX-License-Identifier: Apache-2.0

-- +goose Up

-- Searchable names for dynamic groups and rollouts, whose definitions are
-- deterministic protobuf encodings. The store writes name with every definition:
-- a dynamic group's lindm.admin.v1.DynamicTargetGroup.name, and a rollout's ring
-- names (lindm.policy.v1.RolloutSpec.rings[].name) in order joined by ', ', the
-- name the console shows. Rollout definitions are immutable, so its name is too.

-- Backfill only: the length-delimited (wire type 2) values of one top-level
-- field of a protobuf message, in encoding order. Dropped below; the server
-- decodes definitions with the generated code, never with this.
-- +goose StatementBegin
CREATE FUNCTION migration_00045_proto_bytes(message bytea, wanted integer)
RETURNS SETOF bytea LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE
    pos integer := 0;
    size integer := length(message);
    tag bigint;
    len bigint;
    shift integer;
    b integer;
BEGIN
    WHILE pos < size LOOP
        tag := 0;
        shift := 0;
        LOOP
            b := get_byte(message, pos);
            pos := pos + 1;
            tag := tag | ((b & 127)::bigint << shift);
            shift := shift + 7;
            EXIT WHEN b < 128;
        END LOOP;
        CASE tag & 7
            WHEN 0 THEN
                LOOP
                    b := get_byte(message, pos);
                    pos := pos + 1;
                    EXIT WHEN b < 128;
                END LOOP;
            WHEN 1 THEN
                pos := pos + 8;
            WHEN 5 THEN
                pos := pos + 4;
            WHEN 2 THEN
                len := 0;
                shift := 0;
                LOOP
                    b := get_byte(message, pos);
                    pos := pos + 1;
                    len := len | ((b & 127)::bigint << shift);
                    shift := shift + 7;
                    EXIT WHEN b < 128;
                END LOOP;
                IF tag >> 3 = wanted THEN
                    RETURN NEXT substring(message FROM pos + 1 FOR len::integer);
                END IF;
                pos := pos + len;
            ELSE
                RAISE EXCEPTION 'unsupported protobuf wire type % in a targeting definition', tag & 7;
        END CASE;
    END LOOP;
    IF pos <> size THEN
        RAISE EXCEPTION 'truncated protobuf targeting definition';
    END IF;
END;
$$;
-- +goose StatementEnd

ALTER TABLE dynamic_target_groups ADD COLUMN name text;
UPDATE dynamic_target_groups g SET name = (
    SELECT convert_from(f.value, 'UTF8')
    FROM migration_00045_proto_bytes(g.definition, 2) WITH ORDINALITY AS f (value, ord)
    ORDER BY f.ord DESC
    LIMIT 1
);
ALTER TABLE dynamic_target_groups
    ALTER COLUMN name SET NOT NULL,
    ADD CONSTRAINT dynamic_target_groups_name_check CHECK (char_length(name) BETWEEN 1 AND 128);

-- A rollout has 1-16 rings named by at most 64 characters: at most 1,054 joined.
ALTER TABLE resource_rollouts ADD COLUMN name text;
UPDATE resource_rollouts r SET name = (
    SELECT string_agg(convert_from(n.value, 'UTF8'), ', ' ORDER BY ring.ord)
    FROM migration_00045_proto_bytes(r.definition, 3) WITH ORDINALITY AS ring (value, ord)
    CROSS JOIN LATERAL (
        SELECT f.value
        FROM migration_00045_proto_bytes(ring.value, 1) WITH ORDINALITY AS f (value, ord)
        ORDER BY f.ord DESC
        LIMIT 1
    ) AS n
);
ALTER TABLE resource_rollouts
    ALTER COLUMN name SET NOT NULL,
    ADD CONSTRAINT resource_rollouts_name_check CHECK (char_length(name) BETWEEN 1 AND 1054);

DROP FUNCTION migration_00045_proto_bytes(bytea, integer);

-- +goose Down
ALTER TABLE resource_rollouts DROP COLUMN name;
ALTER TABLE dynamic_target_groups DROP COLUMN name;
