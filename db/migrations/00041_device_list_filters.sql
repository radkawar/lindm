-- +goose Up

-- One definition each for a device's worst profile-item state and its patch
-- bucket, shared by the device list's filters and projections and by the fleet
-- summary, so a dashboard count and the list it links to cannot disagree.

-- Worst rank across the device's assigned items, independent of protobuf enum
-- numbering: 5 attention > 4 unknown (never verified) > 3 stale > 2 drift
-- remediated > 1 compliant; 0 when nothing is assigned.
CREATE FUNCTION device_compliance_rank(target uuid)
RETURNS integer LANGUAGE sql STABLE AS $$
    SELECT coalesce(max(CASE
        WHEN p.blocked_reason <> '' OR p.disposition IN (4, 5, 6, 7) OR p.applying OR p.dependency_attention THEN 5
        WHEN p.last_verified_at IS NULL THEN 4
        WHEN p.last_verified_at + make_interval(secs => LEAST(2 * p.reconcile_interval_seconds, p.verification_max_age_seconds)) <= CURRENT_TIMESTAMP THEN 3
        WHEN p.drift_remediated THEN 2
        ELSE 1
    END), 0)::integer
    FROM integration_compliance_projection p
    WHERE p.device_id = target
$$;

-- Latest published patch status of a generation: unknown (none or unavailable),
-- stale (older than stale_after_seconds by server receipt, never the device
-- clock alone), security_pending, reboot_required or patched.
CREATE FUNCTION device_patch_bucket(generation uuid, stale_after_seconds integer)
RETURNS text LANGUAGE sql STABLE AS $$
    SELECT coalesce((
        SELECT CASE
            WHEN NOT p.available THEN 'unknown'
            WHEN LEAST(p.observed_at, p.received_at) < CURRENT_TIMESTAMP - make_interval(secs => stale_after_seconds) THEN 'stale'
            WHEN p.pending_security_updates > 0 THEN 'security_pending'
            WHEN p.reboot_required THEN 'reboot_required'
            ELSE 'patched'
        END
        FROM host_patch_status p WHERE p.generation_id = generation
    ), 'unknown')
$$;

-- +goose Down
DROP FUNCTION device_patch_bucket(uuid, integer);
DROP FUNCTION device_compliance_rank(uuid);
