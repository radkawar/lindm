-- +goose Up
-- Names identify declarative enrollment objects without exposing bearer material.
-- Expiry/consumption never renews a credential implicitly; explicit revocation
-- releases the label for a separately authorized replacement.
ALTER TABLE enrollment_grants ADD COLUMN name text NOT NULL DEFAULT '' CHECK (char_length(name) <= 257);
ALTER TABLE provisioning_tokens ADD COLUMN name text NOT NULL DEFAULT '' CHECK (char_length(name) <= 257);
CREATE UNIQUE INDEX enrollment_grants_name_live ON enrollment_grants (name) WHERE name <> '' AND revoked_at IS NULL;
CREATE UNIQUE INDEX provisioning_tokens_name_live ON provisioning_tokens (name) WHERE name <> '' AND revoked_at IS NULL;

-- +goose Down
DROP INDEX provisioning_tokens_name_live;
DROP INDEX enrollment_grants_name_live;
ALTER TABLE provisioning_tokens DROP COLUMN name;
ALTER TABLE enrollment_grants DROP COLUMN name;
