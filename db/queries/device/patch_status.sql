-- SPDX-License-Identifier: Apache-2.0

-- name: UpsertHostPatchStatus :exec
-- Projection of the validated NativeDetails.patch_status of the generation's
-- latest admitted host observation, written in the same transaction.
INSERT INTO host_patch_status (
    generation_id,
    observed_at,
    received_at,
    available,
    reason,
    backend,
    pending_security_updates,
    pending_updates,
    deferred_updates,
    reboot_required,
    metadata_refreshed_at,
    last_successful_update,
    last_run_finished_at,
    last_run_result,
    reboot_scheduled_for,
    policy_installed
) VALUES (
    sqlc.arg('generation_id'),
    sqlc.arg('observed_at'),
    sqlc.arg('received_at'),
    sqlc.arg('available'),
    sqlc.arg('reason'),
    sqlc.arg('backend'),
    sqlc.arg('pending_security_updates'),
    sqlc.arg('pending_updates'),
    sqlc.arg('deferred_updates'),
    sqlc.arg('reboot_required'),
    sqlc.narg('metadata_refreshed_at'),
    sqlc.narg('last_successful_update'),
    sqlc.narg('last_run_finished_at'),
    sqlc.arg('last_run_result'),
    sqlc.narg('reboot_scheduled_for'),
    sqlc.arg('policy_installed')
)
ON CONFLICT (generation_id) DO UPDATE SET
    observed_at = EXCLUDED.observed_at,
    received_at = EXCLUDED.received_at,
    available = EXCLUDED.available,
    reason = EXCLUDED.reason,
    backend = EXCLUDED.backend,
    pending_security_updates = EXCLUDED.pending_security_updates,
    pending_updates = EXCLUDED.pending_updates,
    deferred_updates = EXCLUDED.deferred_updates,
    reboot_required = EXCLUDED.reboot_required,
    metadata_refreshed_at = EXCLUDED.metadata_refreshed_at,
    last_successful_update = EXCLUDED.last_successful_update,
    last_run_finished_at = EXCLUDED.last_run_finished_at,
    last_run_result = EXCLUDED.last_run_result,
    reboot_scheduled_for = EXCLUDED.reboot_scheduled_for,
    policy_installed = EXCLUDED.policy_installed;

-- name: DeleteHostPatchStatus :exec
-- A host observation without patch status (historical agents, direct
-- collection) never keeps an older generation-local projection.
DELETE FROM host_patch_status WHERE generation_id = sqlc.arg('generation_id');

-- name: GetHostPatchStatus :one
SELECT * FROM host_patch_status WHERE generation_id = sqlc.arg('generation_id');
