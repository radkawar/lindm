-- +goose Up

-- Deleting a managed secret erases every version's wrapped data key and
-- ciphertext. Metadata, version history and sealed delivery records remain
-- for audit; a deleted secret is never listed, revealed, rotated or delivered.
ALTER TABLE managed_secrets
    ADD COLUMN deleted_at timestamptz,
    ADD COLUMN deleted_by uuid REFERENCES principals(id),
    ADD CONSTRAINT managed_secrets_deleted_shape CHECK ((deleted_at IS NULL) = (deleted_by IS NULL));
ALTER TABLE managed_secret_versions
    DROP CONSTRAINT managed_secret_versions_wrapped_key_check,
    DROP CONSTRAINT managed_secret_versions_ciphertext_check,
    ADD CONSTRAINT managed_secret_versions_envelope CHECK (
        (octet_length(wrapped_key) BETWEEN 1 AND 1024 AND octet_length(ciphertext) BETWEEN 1 AND 8192)
        OR (octet_length(wrapped_key) = 0 AND octet_length(ciphertext) = 0)
    );
DROP INDEX managed_secrets_page;
CREATE INDEX managed_secrets_page ON managed_secrets(created_at, id) WHERE deleted_at IS NULL;

-- +goose Down
-- Erased material cannot be restored: the down migration fails while any
-- deleted secret exists rather than inventing envelopes.
DROP INDEX managed_secrets_page;
CREATE INDEX managed_secrets_page ON managed_secrets(created_at, id);
ALTER TABLE managed_secret_versions
    DROP CONSTRAINT managed_secret_versions_envelope,
    ADD CONSTRAINT managed_secret_versions_wrapped_key_check CHECK (octet_length(wrapped_key) BETWEEN 1 AND 1024),
    ADD CONSTRAINT managed_secret_versions_ciphertext_check CHECK (octet_length(ciphertext) BETWEEN 1 AND 8192);
ALTER TABLE managed_secrets
    DROP CONSTRAINT managed_secrets_deleted_shape,
    DROP COLUMN deleted_by,
    DROP COLUMN deleted_at;
