-- SPDX-License-Identifier: Apache-2.0

-- +goose Up
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

-- +goose Down
-- Retained approvals are audit evidence; refuse downgrade until none use this action.
ALTER TABLE approval_requests DROP CONSTRAINT approval_requests_action_known;
ALTER TABLE approval_requests DROP CONSTRAINT approval_requests_action_permission;
ALTER TABLE approval_requests ADD CONSTRAINT approval_requests_action_known CHECK (action IN ('device.revoke', 'device.recover', 'enrollment.approve', 'resources.assign', 'resources.activate_preview', 'execution_trust.manage', 'device.action', 'recovery_key.reveal', 'secret.reveal', 'local_admin.reveal'));
ALTER TABLE approval_requests ADD CONSTRAINT approval_requests_action_permission CHECK (
    (action IN ('device.revoke', 'resources.assign', 'execution_trust.manage') AND permission = action)
    OR (action = 'device.action' AND permission IN ('encryption.manage', 'actions.lock', 'actions.release-lock', 'actions.quarantine', 'destructive.execute', 'remote_execution.run', 'inventory.manage'))
    OR (action = 'resources.activate_preview' AND permission = 'resources.assign')
    OR (action = 'recovery_key.reveal' AND permission = 'recovery_keys.read')
    OR (action = 'device.recover' AND permission = 'device.revoke')
    OR (action = 'enrollment.approve' AND permission = 'enrollment.manage')
    OR (action IN ('secret.reveal', 'local_admin.reveal') AND permission = 'secrets.reveal')
);
