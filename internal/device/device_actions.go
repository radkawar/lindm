package device

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

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
)

func deviceActionPermission(spec *agentv1.DeviceActionSpec) identity.Permission {
	if destructiveDeviceAction(spec) {
		return identity.PermissionExecuteDestructive
	}
	if spec.GetEscrowRotate() != nil || spec.GetTpm2Bind() != nil {
		return identity.PermissionManageEncryption
	}
	if spec.GetLockSessions() != nil {
		return identity.PermissionLockDevice
	}
	if spec.GetReleaseLock() != nil {
		return identity.PermissionReleaseLockDevice
	}
	if spec.GetQuarantine() != nil || spec.GetReleaseQuarantine() != nil {
		return identity.PermissionQuarantineDevice
	}
	return identity.PermissionRunRemoteExecution
}
func destructiveDeviceAction(spec *agentv1.DeviceActionSpec) bool {
	return spec.GetCryptoErase() != nil || spec.GetSanitize() != nil
}
func actionDigest(message proto.Message) ([]byte, error) {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	return digest[:], nil
}
func actionRequest(row devicedb.DeviceAction) (*adminv1.CreateDeviceActionRequest, error) {
	request := new(adminv1.CreateDeviceActionRequest)
	if err := proto.Unmarshal(row.RequestDocument, request); err != nil {
		return nil, errInternalState
	}
	return request, nil
}
func actionIntent(row devicedb.DeviceAction) (*agentv1.DeviceActionIntent, error) {
	intent := new(agentv1.DeviceActionIntent)
	if err := proto.Unmarshal(row.IntentDocument, intent); err != nil {
		return nil, errInternalState
	}
	return intent, nil
}
func actionMessage(row devicedb.DeviceAction) (*adminv1.DeviceAction, error) {
	intent, err := actionIntent(row)
	if err != nil {
		return nil, err
	}
	result := &adminv1.DeviceAction{ActionId: row.ID.String(), DeviceId: row.DeviceID.String(), EnrollmentGeneration: row.GenerationID.String(), Spec: intent.GetSpec(), ActorId: row.ActorID.String(), CreatedAt: timestamppb.New(row.IssuedAt.Time), ExpiresAt: timestamppb.New(row.ExpiresAt.Time), ClosedReason: row.ClosedReason}
	if len(row.StatusDocument) > 0 {
		result.Status = new(agentv1.DeviceActionStatus)
		if err := proto.Unmarshal(row.StatusDocument, result.Status); err != nil {
			return nil, errInternalState
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

// Inventory gates availability, not destructive authority. Exact target and native
// capabilities are independently established by the root-owned signed preflight.
func requireActionInventory(ctx context.Context, q *devicedb.Queries, generation uuid.UUID, spec *agentv1.DeviceActionSpec, now time.Time) error {
	host, err := q.GetHostObservation(ctx, generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return rpcError(connect.CodeFailedPrecondition, "device_action_inventory_unavailable")
	}
	if err != nil {
		return err
	}
	if !host.ReceivedAt.Valid || now.Sub(host.ReceivedAt.Time) > 5*time.Minute || host.ReceivedAt.Time.After(now) {
		return rpcError(connect.CodeFailedPrecondition, "device_action_inventory_stale")
	}
	details := new(inventoryv1.NativeDetails)
	if len(host.Details) == 0 || proto.Unmarshal(host.Details, details) != nil {
		return rpcError(connect.CodeFailedPrecondition, "device_action_inventory_unavailable")
	}
	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	if spec.GetTpm2Bind() != nil && !tpm2Available(details.GetTpm()) {
		return rpcError(connect.CodeFailedPrecondition, "device_action_tpm2_unavailable")
	}
	if spec.GetEscrowRotate() != nil || spec.GetTpm2Bind() != nil || destructiveDeviceAction(spec) {
		if details.GetStorage().GetStatus() != success || len(details.GetStorage().GetDevices()) == 0 {
			return rpcError(connect.CodeFailedPrecondition, "device_action_storage_unavailable")
		}
	}
	if spec.GetLockSessions() != nil && details.GetSessions().GetSessions().GetStatus() != success {
		return rpcError(connect.CodeFailedPrecondition, "device_action_sessions_unavailable")
	}
	return nil
}

func actionTerminal(state agentv1.DeviceActionState) bool {
	switch state {
	case agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, agentv1.DeviceActionState_DEVICE_ACTION_STATE_FAILED, agentv1.DeviceActionState_DEVICE_ACTION_STATE_EXPIRED:
		return true
	}
	return false
}

func requireActionRestriction(ctx context.Context, q *devicedb.Queries, id uuid.UUID, spec *agentv1.DeviceActionSpec) error {
	if err := q.ExpireDeviceActionQuarantine(ctx, id); err != nil {
		return err
	}
	restriction, err := q.GetDeviceActionRestriction(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !restriction.Quarantined {
		return nil
	}
	if release := spec.GetReleaseQuarantine(); release != nil && release.GetQuarantineActionId() == restriction.ActionID.String() {
		return nil
	}
	return rpcError(connect.CodeFailedPrecondition, "device_quarantined")
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
			return rpcError(connect.CodeFailedPrecondition, "device_lock_release_required")
		}
		return nil
	}
	release := spec.GetReleaseLock()
	if restriction.LockActionID == nil || restriction.LockActionID.String() != release.GetLockActionId() || !restriction.SessionsLocked {
		return rpcError(connect.CodeFailedPrecondition, "device_action_lock_changed")
	}
	original, err := q.GetDeviceAction(ctx, *restriction.LockActionID)
	if err != nil {
		return err
	}
	if original.DeviceID != deviceID || original.GenerationID != generationID || len(original.StartGrantEnvelope) == 0 {
		return rpcError(connect.CodeFailedPrecondition, "device_action_lock_binding_rejected")
	}
	intent, err := actionIntent(original)
	if err != nil {
		return err
	}
	if intent.GetSpec().GetLockSessions() == nil {
		return rpcError(connect.CodeFailedPrecondition, "device_action_lock_binding_rejected")
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
		return false, errInternalState
	}
	if status.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN {
		return false, nil
	}
	intent, err := actionIntent(open)
	if err != nil {
		return false, err
	}
	if intent.GetSpec().GetLockSessions() != nil {
		return open.ID.String() == release.GetLockActionId(), nil
	}
	prior := intent.GetSpec().GetReleaseLock()
	return prior != nil && prior.GetLockActionId() == release.GetLockActionId(), nil
}

// tpm2Available reports whether inventory positively observed a TPM 2.0 device.
// The collector reports sysfs tpm_version_major ("2"), not a marketing string.
func tpm2Available(tpm *inventoryv1.TpmDetails) bool {
	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	return tpm.GetPresent().GetStatus() == success && tpm.GetPresent().GetValue() &&
		tpm.GetVersion().GetStatus() == success && tpm.GetVersion().GetValue() == "2"
}
