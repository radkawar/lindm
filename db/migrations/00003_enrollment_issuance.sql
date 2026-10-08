-- Bind a consumed enrollment grant to the certificate issued for that request.
-- Replay resolves this issuance. It must not substitute a later renewal.

-- +goose Up

ALTER TABLE enrollment_grants
    ADD COLUMN certificate_id uuid;

ALTER TABLE enrollment_grants
    ADD CONSTRAINT enrollment_grants_certificate_fk
    FOREIGN KEY (certificate_id) REFERENCES device_certificates (id) ON DELETE RESTRICT;

-- Same-key renewals share the enrollment public key. The issuance is the
-- certificate issued at or before consumption; later renewals are excluded.
-- A consumed grant with no match fails the shape check.
UPDATE enrollment_grants
SET certificate_id = (
    SELECT device_certificates.id
    FROM device_certificates
    WHERE device_certificates.device_id = enrollment_grants.device_id
      AND device_certificates.public_key_fingerprint = enrollment_grants.public_key_fingerprint
      AND device_certificates.issued_at <= enrollment_grants.consumed_at
    ORDER BY device_certificates.issued_at, device_certificates.id
    LIMIT 1
)
WHERE consumed_at IS NOT NULL;

ALTER TABLE enrollment_grants
    DROP CONSTRAINT enrollment_grants_consume_shape;

ALTER TABLE enrollment_grants
    ADD CONSTRAINT enrollment_grants_consume_shape CHECK (
        (
            consumed_at IS NULL
            AND device_id IS NULL
            AND transaction_id IS NULL
            AND public_key_fingerprint IS NULL
            AND certificate_id IS NULL
        )
        OR (
            consumed_at IS NOT NULL
            AND device_id IS NOT NULL
            AND transaction_id IS NOT NULL
            AND octet_length(public_key_fingerprint) = 32
            AND certificate_id IS NOT NULL
        )
    );

-- +goose Down

ALTER TABLE enrollment_grants DROP CONSTRAINT enrollment_grants_consume_shape;
ALTER TABLE enrollment_grants DROP CONSTRAINT enrollment_grants_certificate_fk;

ALTER TABLE enrollment_grants
    ADD CONSTRAINT enrollment_grants_consume_shape CHECK (
        (
            consumed_at IS NULL
            AND device_id IS NULL
            AND transaction_id IS NULL
            AND public_key_fingerprint IS NULL
        )
        OR (
            consumed_at IS NOT NULL
            AND device_id IS NOT NULL
            AND transaction_id IS NOT NULL
            AND octet_length(public_key_fingerprint) = 32
        )
    );

ALTER TABLE enrollment_grants DROP COLUMN certificate_id;
