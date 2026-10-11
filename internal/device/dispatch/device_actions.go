package dispatch

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"lindm/internal/device/inventory"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

func DeviceActionPermission(spec *agentv1.DeviceActionSpec) identity.Permission {
	return identity.DeviceActionPermission(spec)
}
func DestructiveDeviceAction(spec *agentv1.DeviceActionSpec) bool {
	return spec.GetCryptoErase() != nil || spec.GetSanitize() != nil
}

// A policy-minted rotation has no human request to approve: its authority is
// the policy actor's, freshly re-authorized at minting and again at start.
func policyMintedAction(spec *agentv1.DeviceActionSpec) bool {
	return spec.GetLocalAdminPasswordRotate() != nil
}
func actionRequest(row devicedb.DeviceAction) (*adminv1.CreateDeviceActionRequest, error) {
	request := new(adminv1.CreateDeviceActionRequest)
	if err := proto.Unmarshal(row.RequestDocument, request); err != nil {
		return nil, core.ErrInternalState
	}
	return request, nil
}
func actionMessage(row devicedb.DeviceAction) (*adminv1.DeviceAction, error) {
	intent, err := core.ActionIntent(row)
	if err != nil {
		return nil, err
	}
	result := &adminv1.DeviceAction{ActionId: row.ID.String(), DeviceId: row.DeviceID.String(), EnrollmentGeneration: row.GenerationID.String(), Spec: intent.GetSpec(), ActorId: row.ActorID.String(), CreatedAt: timestamppb.New(row.IssuedAt.Time), ExpiresAt: timestamppb.New(row.ExpiresAt.Time), ClosedReason: row.ClosedReason}
	if len(row.StatusDocument) > 0 {
		result.Status = new(agentv1.DeviceActionStatus)
		if err := proto.Unmarshal(row.StatusDocument, result.Status); err != nil {
			return nil, core.ErrInternalState
		}
	}
	if row.ActionRevision.Valid && row.ActionRevision.Int != nil && row.ActionRevision.Int.IsUint64() {
		result.ActionRevision = row.ActionRevision.Int.Uint64()
	}
	// Start authority is evidence of a possible effect, never evidence of success.
	if row.OutcomeUnknown && (result.Status == nil || result.Status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING || result.Status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_QUEUED) {
		digest := sha256.Sum256(row.IntentEnvelope)
		before := result.Status.GetBefore()
		if before == nil {
			before = &agentv1.DeviceActionObservation{ObservedAt: timestamppb.New(row.IssuedAt.Time), Reason: "result_not_received"}
		}
		started := row.StartAuthorizedAt.Time
		if !row.StartAuthorizedAt.Valid {
			started = row.IssuedAt.Time
		}
		result.Status = &agentv1.DeviceActionStatus{ActionId: row.ID.String(), IntentSha256: digest[:], State: agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN, Failure: agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_INTERRUPTED, AcceptedAt: timestamppb.New(row.IssuedAt.Time), StartedAt: timestamppb.New(started), CompletedAt: timestamppb.New(started), Before: before}
	}
	return result, nil
}

// Inventory gates freshness and exact observed selection, not destructive
// authority. Root-owned signed preflight independently qualifies native effects.
func requireActionInventory(ctx context.Context, q *devicedb.Queries, generation uuid.UUID, spec *agentv1.DeviceActionSpec, now time.Time) error {
	// Refresh repairs missing or stale inventory; its signed start is still online.
	// Local-admin rotation selects no inventory object: the root executor
	// observes the allowlisted account itself before each phase.
	if spec.GetRefreshInventory() != nil || spec.GetLocalAdminPasswordRotate() != nil {
		return nil
	}
	host, err := q.GetHostObservation(ctx, generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return rpcreason.Error(connect.CodeFailedPrecondition, "device_action_inventory_unavailable")
	}
	if err != nil {
		return err
	}
	if !inventory.ActionInventoryFresh(host, now) {
		return rpcreason.Error(connect.CodeFailedPrecondition, "device_action_inventory_stale")
	}
	details := new(inventoryv1.NativeDetails)
	if len(host.Details) == 0 || proto.Unmarshal(host.Details, details) != nil {
		return rpcreason.Error(connect.CodeFailedPrecondition, "device_action_inventory_unavailable")
	}
	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	if spec.GetTpm2Bind() != nil && !core.TPM2Available(details.GetTpm()) {
		return rpcreason.Error(connect.CodeFailedPrecondition, "device_action_tpm2_unavailable")
	}
	if spec.GetTpm2Bind() != nil && !core.TPM2BindSupported(host) {
		return rpcreason.Error(connect.CodeFailedPrecondition, "device_action_tpm2_binding_unsupported")
	}
	if err := inventory.RequireObservedStorageTargets(details, spec); err != nil {
		return err
	}
	if spec.GetLockSessions() != nil && details.GetSessions().GetSessions().GetStatus() != success {
		return rpcreason.Error(connect.CodeFailedPrecondition, "device_action_sessions_unavailable")
	}
	if core.SessionLockOnlyUnsupported(host, spec.GetLockSessions()) {
		return rpcreason.Error(connect.CodeFailedPrecondition, "device_action_session_lock_unsupported")
	}
	return nil
}

func ActionTerminal(state agentv1.DeviceActionState) bool {
	switch state {
	case agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, agentv1.DeviceActionState_DEVICE_ACTION_STATE_FAILED, agentv1.DeviceActionState_DEVICE_ACTION_STATE_EXPIRED:
		return true
	}
	return false
}

// The device row is locked by callers. Keep lock ownership independent of a
// later quarantine and forbid overlapping locks that could orphan owned accounts.
func requireLockActionRestriction(ctx context.Context, q *devicedb.Queries, deviceID, generationID uuid.UUID, spec *agentv1.DeviceActionSpec) error {
	if spec.GetLockSessions() == nil && spec.GetReleaseLock() == nil {
		return nil
	}
	restriction, err := q.GetDeviceActionRestriction(ctx, deviceID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if spec.GetLockSessions() != nil {
		if restriction.LockActionID != nil || restriction.SessionsLocked {
			return rpcreason.Error(connect.CodeFailedPrecondition, "device_lock_release_required")
		}
		return nil
	}
	release := spec.GetReleaseLock()
	if restriction.LockActionID == nil || restriction.LockActionID.String() != release.GetLockActionId() || !restriction.SessionsLocked {
		return rpcreason.Error(connect.CodeFailedPrecondition, "device_action_lock_changed")
	}
	original, err := q.GetDeviceAction(ctx, *restriction.LockActionID)
	if err != nil {
		return err
	}
	if original.DeviceID != deviceID || original.GenerationID != generationID || len(original.StartGrantEnvelope) == 0 {
		return rpcreason.Error(connect.CodeFailedPrecondition, "device_action_lock_binding_rejected")
	}
	intent, err := core.ActionIntent(original)
	if err != nil {
		return err
	}
	if intent.GetSpec().GetLockSessions() == nil {
		return rpcreason.Error(connect.CodeFailedPrecondition, "device_action_lock_binding_rejected")
	}
	return nil
}

// An explicit, separately authorized inverse may reconcile an interrupted lock.
// Grant issuance alone is not an interrupted result: only a signed UNKNOWN
// status admits this exception, never queued/running work or another operation.
func releaseSupersedesUnknownLock(open devicedb.DeviceAction, generationID uuid.UUID, spec *agentv1.DeviceActionSpec) (bool, error) {
	release := spec.GetReleaseLock()
	if release == nil || open.GenerationID != generationID || !open.OutcomeUnknown || len(open.StartGrantEnvelope) == 0 {
		return false, nil
	}
	if len(open.StatusDocument) == 0 {
		return false, nil
	}
	status := new(agentv1.DeviceActionStatus)
	if err := proto.Unmarshal(open.StatusDocument, status); err != nil {
		return false, core.ErrInternalState
	}
	if status.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN {
		return false, nil
	}
	intent, err := core.ActionIntent(open)
	if err != nil {
		return false, err
	}
	if intent.GetSpec().GetLockSessions() != nil {
		return open.ID.String() == release.GetLockActionId(), nil
	}
	prior := intent.GetSpec().GetReleaseLock()
	return prior != nil && prior.GetLockActionId() == release.GetLockActionId(), nil
}
