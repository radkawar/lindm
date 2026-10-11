package device

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"slices"
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
	"lindm/internal/rpcreason"
	"lindm/internal/trust"
)

func deviceActionPermission(spec *agentv1.DeviceActionSpec) identity.Permission {
	return identity.DeviceActionPermission(spec)
}
func destructiveDeviceAction(spec *agentv1.DeviceActionSpec) bool {
	return spec.GetCryptoErase() != nil || spec.GetSanitize() != nil
}

// A policy-minted rotation has no human request to approve: its authority is
// the policy actor's, freshly re-authorized at minting and again at start.
func policyMintedAction(spec *agentv1.DeviceActionSpec) bool {
	return spec.GetLocalAdminPasswordRotate() != nil
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
	if !actionInventoryFresh(host, now) {
		return rpcreason.Error(connect.CodeFailedPrecondition, "device_action_inventory_stale")
	}
	details := new(inventoryv1.NativeDetails)
	if len(host.Details) == 0 || proto.Unmarshal(host.Details, details) != nil {
		return rpcreason.Error(connect.CodeFailedPrecondition, "device_action_inventory_unavailable")
	}
	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	if spec.GetTpm2Bind() != nil && !tpm2Available(details.GetTpm()) {
		return rpcreason.Error(connect.CodeFailedPrecondition, "device_action_tpm2_unavailable")
	}
	if err := requireObservedStorageTargets(details, spec); err != nil {
		return err
	}
	if spec.GetLockSessions() != nil && details.GetSessions().GetSessions().GetStatus() != success {
		return rpcreason.Error(connect.CodeFailedPrecondition, "device_action_sessions_unavailable")
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
	return rpcreason.Error(connect.CodeFailedPrecondition, "device_quarantined")
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
	intent, err := actionIntent(original)
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

type refreshInventoryAdmission struct {
	challengeIssuedAt time.Time
	startAuthorizedAt time.Time
}

// The caller holds the device lock and claims only a new, validated collection.
// Binding in the ingestion transaction preserves the allowance across stale
// routine admissions and rolls it back if any later admission step fails.
func claimRefreshInventoryAdmission(ctx context.Context, q *devicedb.Queries, deviceID, generationID uuid.UUID, sequence int64, started, received time.Time, packageSnapshot bool) (refreshInventoryAdmission, error) {
	action, err := q.GetOpenDeviceAction(ctx, deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return refreshInventoryAdmission{}, nil
	}
	if err != nil {
		return refreshInventoryAdmission{}, err
	}
	if action.GenerationID != generationID || action.Capability != "device.refresh-inventory.v1" || !action.StartAuthorizedAt.Valid || len(action.StartGrantEnvelope) == 0 {
		return refreshInventoryAdmission{}, nil
	}
	if (packageSnapshot && action.InventoryPackageSequence != 0) || (!packageSnapshot && action.InventoryHostSequence != 0) {
		return refreshInventoryAdmission{}, nil
	}
	challenge := new(agentv1.DeviceActionChallenge)
	if proto.Unmarshal(action.ChallengeDocument, challenge) != nil || challenge.GetIssuedAt() == nil {
		return refreshInventoryAdmission{}, errInternalState
	}
	issued := challenge.GetIssuedAt().AsTime()
	if started.Before(issued) {
		return refreshInventoryAdmission{}, nil
	}
	var claimed int64
	if packageSnapshot {
		claimed, err = q.ClaimDeviceActionPackageAdmission(ctx, devicedb.ClaimDeviceActionPackageAdmissionParams{ID: action.ID, Sequence: sequence})
	} else {
		claimed, err = q.ClaimDeviceActionHostAdmission(ctx, devicedb.ClaimDeviceActionHostAdmissionParams{ID: action.ID, Sequence: sequence, ReceivedAt: timestamptz(received)})
	}
	if err != nil {
		return refreshInventoryAdmission{}, err
	}
	if claimed != 1 {
		return refreshInventoryAdmission{}, errInternalState
	}
	return refreshInventoryAdmission{challengeIssuedAt: issued, startAuthorizedAt: action.StartAuthorizedAt.Time}, nil
}

// A configured online key is not authority for capabilities absent from the
// operator-approved delegation. Detect that prerequisite before signing work.
func deviceActionSignerDelegated(delegation *agentv1.ExecutionDelegation, key ed25519.PrivateKey, role agentv1.ExecutionSignerRole, capability string) bool {
	if len(key) != ed25519.PrivateKeySize {
		return false
	}
	public := key[ed25519.SeedSize:]
	for _, delegate := range delegation.GetDelegates() {
		if delegate.GetRole() == role && slices.Contains(delegate.GetCapabilities(), capability) && bytes.Equal(delegate.GetKey().GetPublicKey(), public) {
			return true
		}
	}
	return false
}

// deviceActionNotBefore backdates an intent by the device clock tolerance but
// never before its signing delegation becomes valid: VerifyDeviceActionIntent
// requires the intent window inside the delegation's. Without the clamp every
// action created within MaxDeviceClockSkew of a newly valid delegation failed
// as an internal error. Resource intents apply the same bound.
func deviceActionNotBefore(now time.Time, delegation *agentv1.ExecutionDelegation) time.Time {
	notBefore := now.Add(-trust.MaxDeviceClockSkew)
	if valid := delegation.GetNotBefore().AsTime(); valid.After(notBefore) {
		return valid
	}
	return notBefore
}

func deviceActionCapabilityError(capability, role string) error {
	failure := rpcreason.Error(connect.CodeFailedPrecondition, "device_action_capability_not_delegated")
	failure.Meta().Set("Lindm-Action-Capability", capability)
	failure.Meta().Set("Lindm-Signer-Role", role)
	return failure
}
