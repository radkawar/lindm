-- Durable actor fences for privileged approvals and dispatch. Existing actors
-- establish their current effective role on the next authoritative observation.
-- Freshness/display-only changes must not consume an authorization version.

-- +goose Up
ALTER TABLE principals
  ADD COLUMN authorization_version bigint NOT NULL DEFAULT 1,
  ADD COLUMN authorization_role text NOT NULL DEFAULT '',
  ADD CONSTRAINT principals_authorization_version_positive CHECK (authorization_version > 0),
  ADD CONSTRAINT principals_authorization_role_known CHECK (authorization_role IN ('', 'owner', 'admin'));

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
  ALTER TABLE principals
    DROP CONSTRAINT principals_authorization_version_positive,
    DROP CONSTRAINT principals_authorization_role_known,
    DROP COLUMN authorization_role,
    DROP COLUMN authorization_version;
END $$;
-- +goose StatementEnd
