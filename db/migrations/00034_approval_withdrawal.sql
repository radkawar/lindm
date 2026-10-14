-- SPDX-License-Identifier: Apache-2.0

-- +goose Up
-- A requester may withdraw their own pending request. Withdrawal is not a
-- decision: no approver is recorded and the withdrawal reason is kept in
-- decision_reason.
-- +goose StatementBegin
DO $$
DECLARE c record;
BEGIN
  FOR c IN
    SELECT conname FROM pg_constraint
    WHERE conrelid = 'approval_requests'::regclass AND contype = 'c'
      AND (pg_get_constraintdef(oid) LIKE '%approver_version = 0%'
        OR (pg_get_constraintdef(oid) LIKE '%''consumed''%' AND pg_get_constraintdef(oid) NOT LIKE '%consumed_at%'))
  LOOP
    EXECUTE format('ALTER TABLE approval_requests DROP CONSTRAINT %I', c.conname);
  END LOOP;
END $$;
-- +goose StatementEnd
ALTER TABLE approval_requests ADD CONSTRAINT approval_requests_state_known
    CHECK (state IN ('pending', 'approved', 'rejected', 'consumed', 'withdrawn'));
ALTER TABLE approval_requests ADD CONSTRAINT approval_requests_decider CHECK (
    (state IN ('pending', 'withdrawn') AND approver_id IS NULL AND approver_version = 0)
    OR (state NOT IN ('pending', 'withdrawn') AND approver_id IS NOT NULL AND approver_version > 0)
);

-- +goose Down
-- Retained approvals are audit evidence; refuse downgrade while any is withdrawn.
ALTER TABLE approval_requests DROP CONSTRAINT approval_requests_decider;
ALTER TABLE approval_requests DROP CONSTRAINT approval_requests_state_known;
ALTER TABLE approval_requests ADD CHECK (state IN ('pending', 'approved', 'rejected', 'consumed'));
ALTER TABLE approval_requests ADD CHECK ((state = 'pending' AND approver_id IS NULL AND approver_version = 0)
    OR (state <> 'pending' AND approver_id IS NOT NULL AND approver_version > 0));
