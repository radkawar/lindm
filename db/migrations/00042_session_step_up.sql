-- +goose Up
-- In-page step-up: a signed-in local administrator re-verifies with password
-- and passkey without starting a new session. The session records when, and
-- the ceremony is bound to the exact session that asked for it.
ALTER TABLE sessions ADD COLUMN stepped_up_at timestamptz,
  ADD CONSTRAINT sessions_stepped_up_after_creation CHECK (stepped_up_at IS NULL OR stepped_up_at >= created_at);
ALTER TABLE local_ceremonies DROP CONSTRAINT local_ceremonies_kind_check,
  ADD CONSTRAINT local_ceremonies_kind_check CHECK (kind IN ('login', 'enroll', 'step_up')),
  ADD COLUMN session_hash bytea CHECK (session_hash IS NULL OR octet_length(session_hash) = 32),
  ADD CONSTRAINT local_ceremonies_step_up_session CHECK ((kind = 'step_up') = (session_hash IS NOT NULL));

-- +goose Down
DELETE FROM local_ceremonies WHERE kind = 'step_up';
ALTER TABLE local_ceremonies DROP CONSTRAINT local_ceremonies_step_up_session,
  DROP COLUMN session_hash,
  DROP CONSTRAINT local_ceremonies_kind_check,
  ADD CONSTRAINT local_ceremonies_kind_check CHECK (kind IN ('login', 'enroll'));
ALTER TABLE sessions DROP CONSTRAINT sessions_stepped_up_after_creation,
  DROP COLUMN stepped_up_at;
