-- +goose Up
-- One reviewed StartRollout request: the exact request bytes (the single
-- approval's payload), the assignment it saves when started and its status.
CREATE TABLE resource_rollout_plans (
    rollout_id uuid PRIMARY KEY REFERENCES resource_rollouts(id),
    assignment_id uuid NOT NULL,
    expected_revision bigint NOT NULL CHECK (expected_revision >= 0),
    request_id uuid NOT NULL,
    request bytea NOT NULL CHECK (octet_length(request) BETWEEN 1 AND 1048576),
    approval_required boolean NOT NULL,
    -- 1 awaiting approval, 2 active, 3 rejected, 4 approval expired,
    -- 5 assignment changed, 6 superseded.
    status smallint NOT NULL CHECK (status BETWEEN 1 AND 6),
    status_reason text NOT NULL DEFAULT '' CHECK (char_length(status_reason) <= 128),
    approval_id uuid REFERENCES approval_requests(id),
    reason text NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 512),
    -- Encoded RolloutState carrying only the reviewed distinct adopted settings.
    adopted bytea NOT NULL CHECK (octet_length(adopted) <= 262144),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    started_at timestamptz,
    CHECK (status <> 2 OR started_at IS NOT NULL),
    CHECK (status <> 2 OR NOT approval_required OR approval_id IS NOT NULL)
);
CREATE INDEX resource_rollout_plans_status ON resource_rollout_plans(status, rollout_id);
CREATE INDEX resource_rollout_plans_assignment ON resource_rollout_plans(assignment_id);

-- Every reviewed device's exact proposed change. The promoter activates a fresh
-- creator-bound preview only when its resolution digest equals this one.
CREATE TABLE resource_rollout_device_plans (
    rollout_id uuid NOT NULL REFERENCES resource_rollout_plans(rollout_id),
    device_id uuid NOT NULL REFERENCES devices(id),
    generation_id uuid NOT NULL REFERENCES enrollment_generations(id),
    resolution_sha256 bytea NOT NULL CHECK (octet_length(resolution_sha256) = 32),
    adopts_existing boolean NOT NULL,
    -- False: the proposal stops applying to this device (a removal). Removals
    -- are not staged by cohort; they activate once the rollout starts.
    included boolean NOT NULL,
    -- The resource head the review saw. A direct assignment made on the device
    -- after the review is never silently replaced.
    reviewed_head uuid,
    -- 1 pending, 2 activated, 3 needs review.
    state smallint NOT NULL DEFAULT 1 CHECK (state BETWEEN 1 AND 3),
    reason text NOT NULL DEFAULT '' CHECK (char_length(reason) <= 128),
    preview_id uuid REFERENCES target_previews(id),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (rollout_id, device_id),
    CHECK (state <> 2 OR preview_id IS NOT NULL)
);
CREATE INDEX resource_rollout_device_plans_pending ON resource_rollout_device_plans(rollout_id, device_id) WHERE state = 1;
CREATE TRIGGER immutable_rollout_device_plan BEFORE UPDATE OF rollout_id, device_id, generation_id, resolution_sha256, adopts_existing, included, reviewed_head OR DELETE ON resource_rollout_device_plans FOR EACH ROW EXECUTE FUNCTION reject_targeting_history_mutation();
CREATE TRIGGER immutable_rollout_plan BEFORE UPDATE OF rollout_id, assignment_id, expected_revision, request_id, request, approval_required, reason, adopted OR DELETE ON resource_rollout_plans FOR EACH ROW EXECUTE FUNCTION reject_targeting_history_mutation();

ALTER TABLE approval_requests DROP CONSTRAINT approval_requests_action_known;
ALTER TABLE approval_requests DROP CONSTRAINT approval_requests_action_permission;
ALTER TABLE approval_requests DROP CONSTRAINT approval_requests_device_target;
-- A rollout approval covers a whole reviewed plan, not one device.
ALTER TABLE approval_requests ADD CONSTRAINT approval_requests_device_target CHECK ((action IN ('execution_trust.manage', 'secret.reveal', 'resources.rollout')) = (device_id IS NULL));
ALTER TABLE approval_requests ADD CONSTRAINT approval_requests_action_known CHECK (action IN ('device.revoke', 'device.recover', 'enrollment.approve', 'resources.assign', 'resources.activate_preview', 'resources.rollout', 'execution_trust.manage', 'device.action', 'recovery_key.reveal', 'secret.reveal', 'local_admin.reveal', 'advisory_exception.accept'));
ALTER TABLE approval_requests ADD CONSTRAINT approval_requests_action_permission CHECK (
    (action IN ('device.revoke', 'resources.assign', 'execution_trust.manage') AND permission = action)
    OR (action = 'device.action' AND permission IN ('encryption.manage', 'actions.lock', 'actions.release-lock', 'actions.quarantine', 'destructive.execute', 'remote_execution.run', 'inventory.manage'))
    OR (action = 'resources.activate_preview' AND permission = 'resources.assign')
    OR (action = 'resources.rollout' AND permission = 'resources.assign' AND device_id IS NULL)
    OR (action = 'recovery_key.reveal' AND permission = 'recovery_keys.read')
    OR (action = 'device.recover' AND permission = 'device.revoke')
    OR (action = 'enrollment.approve' AND permission = 'enrollment.manage')
    OR (action IN ('secret.reveal', 'local_admin.reveal') AND permission = 'secrets.reveal')
    OR (action = 'advisory_exception.accept' AND permission = 'advisory_exceptions.manage')
);

-- +goose Down
-- Retained approvals are audit evidence; refuse downgrade until none use this action.
ALTER TABLE approval_requests DROP CONSTRAINT approval_requests_device_target;
ALTER TABLE approval_requests ADD CONSTRAINT approval_requests_device_target CHECK ((action IN ('execution_trust.manage', 'secret.reveal')) = (device_id IS NULL));
ALTER TABLE approval_requests DROP CONSTRAINT approval_requests_action_known;
ALTER TABLE approval_requests DROP CONSTRAINT approval_requests_action_permission;
ALTER TABLE approval_requests ADD CONSTRAINT approval_requests_action_known CHECK (action IN ('device.revoke', 'device.recover', 'enrollment.approve', 'resources.assign', 'resources.activate_preview', 'execution_trust.manage', 'device.action', 'recovery_key.reveal', 'secret.reveal', 'local_admin.reveal', 'advisory_exception.accept'));
ALTER TABLE approval_requests ADD CONSTRAINT approval_requests_action_permission CHECK (
    (action IN ('device.revoke', 'resources.assign', 'execution_trust.manage') AND permission = action)
    OR (action = 'device.action' AND permission IN ('encryption.manage', 'actions.lock', 'actions.release-lock', 'actions.quarantine', 'destructive.execute', 'remote_execution.run', 'inventory.manage'))
    OR (action = 'resources.activate_preview' AND permission = 'resources.assign')
    OR (action = 'recovery_key.reveal' AND permission = 'recovery_keys.read')
    OR (action = 'device.recover' AND permission = 'device.revoke')
    OR (action = 'enrollment.approve' AND permission = 'enrollment.manage')
    OR (action IN ('secret.reveal', 'local_admin.reveal') AND permission = 'secrets.reveal')
    OR (action = 'advisory_exception.accept' AND permission = 'advisory_exceptions.manage')
);
DROP TABLE resource_rollout_device_plans;
DROP TABLE resource_rollout_plans;
