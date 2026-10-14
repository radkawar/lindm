-- SPDX-License-Identifier: Apache-2.0

-- +goose Up
-- Fleet-wide package-name suggestions (SuggestValues PACKAGE_NAME) walk this
-- index in output order: an ASCII case-insensitive prefix is a key range and
-- snapshot_id answers the current-snapshot filter without a heap visit, so a
-- page reads only matching entries instead of every retained package row.
CREATE INDEX snapshot_packages_name_suggest_idx
    ON snapshot_packages ((lower(name COLLATE "C")), (name COLLATE "C"), snapshot_id);

-- +goose Down
DROP INDEX snapshot_packages_name_suggest_idx;
