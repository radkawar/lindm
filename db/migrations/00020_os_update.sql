-- +goose Up
-- Patch now starts one native update run outside the maintenance window.
ALTER TABLE device_actions DROP CONSTRAINT device_actions_capability_check;
ALTER TABLE device_actions ADD CONSTRAINT device_actions_capability_check CHECK (capability IN ('device.escrow-rotate.v1', 'device.tpm2-bind.v1', 'device.lock-sessions.v1', 'device.release-lock.v1', 'device.quarantine.v1', 'device.release-quarantine.v1', 'device.crypto-erase.v1', 'device.sanitize.v1', 'device.restart.v1', 'device.shutdown.v1', 'device.refresh-inventory.v1', 'device.local-admin-rotate.v1', 'device.patch-now.v1'));

-- Queryable projection of the latest published lindm.agent.v1.PatchStatusObservation
-- of a generation, written in the host-observation transaction. Untrusted device
-- telemetry for fleet compliance, never native success authority. last_run_result
-- uses lindm.agent.v1.PatchRunResult numbers (0 when no run is recorded).
CREATE TABLE host_patch_status (
    generation_id uuid PRIMARY KEY REFERENCES host_observations (generation_id) ON DELETE CASCADE,
    observed_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL,
    available boolean NOT NULL,
    reason text NOT NULL CHECK (char_length(reason) <= 256),
    backend smallint NOT NULL CHECK (backend BETWEEN 0 AND 3),
    pending_security_updates integer NOT NULL CHECK (pending_security_updates BETWEEN 0 AND 100000),
    pending_updates integer NOT NULL CHECK (pending_updates BETWEEN pending_security_updates AND 100000),
    deferred_updates integer NOT NULL CHECK (deferred_updates BETWEEN 0 AND pending_updates),
    reboot_required boolean NOT NULL,
    metadata_refreshed_at timestamptz,
    last_successful_update timestamptz,
    last_run_finished_at timestamptz,
    last_run_result smallint NOT NULL CHECK (last_run_result BETWEEN 0 AND 5),
    reboot_scheduled_for timestamptz,
    policy_installed boolean NOT NULL,
    CONSTRAINT host_patch_status_availability CHECK (available = (reason = '') AND (available OR (pending_updates = 0 AND NOT reboot_required))),
    CONSTRAINT host_patch_status_run CHECK ((last_run_result = 0) = (last_run_finished_at IS NULL))
);

-- +goose Down
DROP TABLE host_patch_status;
DELETE FROM device_actions WHERE capability = 'device.patch-now.v1';
ALTER TABLE device_actions DROP CONSTRAINT device_actions_capability_check;
ALTER TABLE device_actions ADD CONSTRAINT device_actions_capability_check CHECK (capability IN ('device.escrow-rotate.v1', 'device.tpm2-bind.v1', 'device.lock-sessions.v1', 'device.release-lock.v1', 'device.quarantine.v1', 'device.release-quarantine.v1', 'device.crypto-erase.v1', 'device.sanitize.v1', 'device.restart.v1', 'device.shutdown.v1', 'device.refresh-inventory.v1', 'device.local-admin-rotate.v1'));
