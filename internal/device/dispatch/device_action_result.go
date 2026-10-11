package dispatch

import (
	"bytes"
	"context"
	"errors"

	"lindm/internal/device/secrets"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/rpcreason"
	"lindm/internal/trust"
)

func (s *Service) ReportDeviceActionResult(ctx context.Context, req *connect.Request[devicev1.ReportDeviceActionResultRequest]) (*connect.Response[devicev1.ReportDeviceActionResultResponse], error) {
	st, err := reportSignedResult(ctx, s, core.Message(req), &deviceActionResult{})
	if err != nil {
		return nil, err
	}
	// A receipt is signed only in a subsequent transaction, after custody committed.
	receipt, err := s.secrets.DeviceActionReceipt(ctx, st.principal, st.epoch, st.id)
	if err != nil {
		return nil, err
	}
	return core.NoStore(&devicev1.ReportDeviceActionResultResponse{Closed: st.closed, EscrowReceiptEnvelope: receipt}), nil
}

type deviceActionResultState = resultState[*agentv1.DeviceActionStatus, *agentv1.DeviceActionAttestation]

// deviceActionResult is the device-action half of result admission: one
// result per action, verified native evidence per action type, escrow custody
// and restriction release.
type deviceActionResult struct {
	action devicedb.DeviceAction
	intent *agentv1.DeviceActionIntent
}

var _ resultKind[*agentv1.DeviceActionStatus, *agentv1.DeviceActionAttestation] = (*deviceActionResult)(nil)

func (*deviceActionResult) reasons() signedReasons { return deviceActionReasons }

func (*deviceActionResult) newAttestation() *agentv1.DeviceActionAttestation {
	return new(agentv1.DeviceActionAttestation)
}

func (k *deviceActionResult) lockAction(ctx context.Context, _ *Service, st *deviceActionResultState) (signedRow, error) {
	var err error
	if k.action, err = st.q.LockDeviceAction(ctx, st.id); err != nil {
		return signedRow{}, core.MapErr(err)
	}
	return deviceActionRow(k.action), nil
}

func (*deviceActionResult) verifyAttestation(ctx context.Context, s *Service, st *deviceActionResultState, binding *trust.ResourceAttestationBinding) (*agentv1.DeviceActionAttestation, error) {
	expected := trust.DeviceActionAttestationBinding(*binding)
	return s.Authority.VerifyDeviceActionAttestation(ctx, st.envelope, st.certificate, s.CA, &expected, st.now, trust.MaxDeviceClockSkew)
}

func (k *deviceActionResult) admit(ctx context.Context, s *Service, st *deviceActionResultState) error {
	status := st.attestation.GetStatus()
	var err error
	if k.intent, err = core.ActionIntent(k.action); err != nil {
		return core.MapErr(err)
	}
	spec, granted := k.intent.GetSpec(), len(k.action.StartGrantEnvelope) != 0
	if k.action.ClosedAt.Valid {
		return rpcreason.Error(connect.CodeAlreadyExists, "device_action_result_closed")
	}
	if status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED && !granted {
		return deviceActionReasons.ungranted.err()
	}
	if spec.GetSanitize().GetRecovery() != nil && (status.GetStartedAt() != nil || k.action.OutcomeUnknown) {
		return rpcreason.Error(connect.CodePermissionDenied, "recovery_result_endpoint_required")
	}
	challenge := new(agentv1.DeviceActionChallenge)
	if len(k.action.ChallengeDocument) > 0 && proto.Unmarshal(k.action.ChallengeDocument, challenge) != nil {
		return core.MapErr(core.ErrInternalState)
	}
	if err := validateLiveRootResult(spec, challenge, status); err != nil {
		return err
	}
	if err := ValidatePowerActionResult(spec, challenge, status); err != nil {
		return err
	}
	if err := ValidatePatchNowResult(spec, status); err != nil {
		return err
	}
	if err := k.requireInventoryReceipt(st, challenge); err != nil {
		return err
	}
	if err := s.admitActionEscrow(ctx, st.q, k.action, k.intent, challenge, status); err != nil {
		return err
	}
	if (spec.GetEscrowRotate() != nil || spec.GetLocalAdminPasswordRotate() != nil) && status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED && len(k.action.EscrowReceiptEnvelope) == 0 {
		return rpcreason.Error(connect.CodeFailedPrecondition, "device_action_escrow_receipt_required")
	}
	return nil
}

// requireInventoryReceipt binds a successful refresh to the exact package
// sequence admitted under the verified server-signed receipt. The committed
// receipt document is not reverified with a possibly rotated current key, and
// the mutable latest host row need not retain the admitted sequence.
func (k *deviceActionResult) requireInventoryReceipt(st *deviceActionResultState, challenge *agentv1.DeviceActionChallenge) error {
	status := st.attestation.GetStatus()
	if k.intent.GetSpec().GetRefreshInventory() == nil || status.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED {
		return nil
	}
	sequence := status.GetVerification().GetInventorySequence()
	if sequence == 0 || !status.GetVerification().GetVerified() || !status.GetVerification().GetAfter().GetSupported() || challenge.GetIssuedAt() == nil {
		return rpcreason.Error(connect.CodePermissionDenied, "device_action_inventory_unverified")
	}
	if k.action.InventoryPackageSequence != int64(sequence) {
		return rpcreason.Error(connect.CodePermissionDenied, "device_action_inventory_receipt_mismatch")
	}
	if len(k.action.InventoryReceiptEnvelope) == 0 {
		return rpcreason.Error(connect.CodeFailedPrecondition, "device_action_inventory_receipt_required")
	}
	receipt := new(agentv1.DeviceActionInventoryReceipt)
	if proto.Unmarshal(k.action.InventoryReceiptDocument, receipt) != nil || receipt.GetActionId() != st.id.String() || receipt.GetDeviceId() != st.principal.DeviceID.String() || receipt.GetEnrollmentGeneration() != st.principal.GenerationID.String() {
		return core.MapErr(core.ErrInternalState)
	}
	if receipt.GetPackageSequence() != sequence || receipt.GetHostSequence() != uint64(k.action.InventoryHostSequence) {
		return rpcreason.Error(connect.CodePermissionDenied, "device_action_inventory_receipt_mismatch")
	}
	return nil
}

// admitActionEscrow takes custody of escrowed secrets exactly once: a
// local-admin password, or a LUKS recovery key bound to the planned slot.
func (s *Service) admitActionEscrow(ctx context.Context, q *devicedb.Queries, action devicedb.DeviceAction, intent *agentv1.DeviceActionIntent, challenge *agentv1.DeviceActionChallenge, status *agentv1.DeviceActionStatus) error {
	escrow := status.GetVerification().GetEscrow()
	if escrow == nil {
		return nil
	}
	if intent.GetSpec().GetLocalAdminPasswordRotate() != nil {
		if err := s.secrets.IngestLocalAdminEscrow(ctx, q, action, intent, escrow); err != nil {
			return core.MapErr(err)
		}
	} else if err := s.ingestRecoveryEscrow(ctx, q, action, intent, challenge, escrow); err != nil {
		return err
	}
	if len(action.StatusDocument) > 0 {
		previous := new(agentv1.DeviceActionStatus)
		if proto.Unmarshal(action.StatusDocument, previous) != nil {
			return core.MapErr(core.ErrInternalState)
		}
		if earlier := previous.GetVerification().GetEscrow(); earlier != nil && !proto.Equal(earlier, escrow) {
			return rpcreason.Error(connect.CodeAlreadyExists, "device_action_escrow_conflict")
		}
	}
	return nil
}

func (s *Service) ingestRecoveryEscrow(ctx context.Context, q *devicedb.Queries, action devicedb.DeviceAction, intent *agentv1.DeviceActionIntent, challenge *agentv1.DeviceActionChallenge, escrow *agentv1.DeviceActionEscrow) error {
	rotate := intent.GetSpec().GetEscrowRotate()
	if rotate == nil || len(action.StartGrantEnvelope) == 0 || s.Escrow == nil || escrow.GetEscrowKeyId() != s.Escrow.KeyID() || escrow.GetLocalAdmin() != nil || escrow.GetLuksUuid() != rotate.GetTarget().GetLuksUuid() {
		return rpcreason.Error(connect.CodePermissionDenied, "device_action_escrow_binding_rejected")
	}
	recovery := challenge.GetNativePlan().GetRecoveryBinding()
	if recovery.GetDeviceId() != intent.GetDeviceId() || recovery.GetEnrollmentGeneration() != intent.GetEnrollmentGeneration() || recovery.GetActionId() != intent.GetActionId() || recovery.GetLuksUuid() != escrow.GetLuksUuid() || recovery.GetNewKeyslot() != escrow.GetNewKeyslot() {
		return rpcreason.Error(connect.CodePermissionDenied, "device_action_escrow_binding_rejected")
	}
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(recovery)
	if err != nil {
		return core.MapErr(err)
	}
	retained, err := q.GetDeviceActionEscrow(ctx, action.ID)
	if err == nil {
		if !bytes.Equal(retained.BindingDocument, canonical) || !bytes.Equal(retained.SecretSha256, escrow.GetRecoveryKeySha256()) {
			return rpcreason.Error(connect.CodeAlreadyExists, "device_action_escrow_conflict")
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return core.MapErr(err)
	}
	sealed, err := s.Escrow.OpenAndSeal(canonical, escrow.GetCiphertext())
	if err != nil {
		return rpcreason.Error(connect.CodePermissionDenied, "device_action_escrow_rejected")
	}
	if !bytes.Equal(sealed.SecretSHA256, escrow.GetRecoveryKeySha256()) {
		return rpcreason.Error(connect.CodePermissionDenied, "device_action_escrow_digest_rejected")
	}
	if _, err := q.InsertDeviceActionEscrow(ctx, devicedb.InsertDeviceActionEscrowParams{ActionID: action.ID, BindingDocument: canonical, KeyID: sealed.KeyID, WrappedKey: sealed.WrappedKey, Ciphertext: sealed.Ciphertext, SecretSha256: sealed.SecretSHA256}); err != nil {
		return core.MapErr(err)
	}
	return core.MapErr(core.DispatchSystemAudit(ctx, q, nil, "device_action.escrow_store", action.ID, "proof", "verified_encrypted_recovery"))
}

func (k *deviceActionResult) persist(ctx context.Context, _ *Service, st *deviceActionResultState, document []byte) error {
	status, now, q := st.attestation.GetStatus(), st.now, st.q
	terminal := ActionTerminal(status.GetState())
	unknown := len(k.action.StartGrantEnvelope) > 0 && !terminal
	if err := q.SetDeviceActionResult(ctx, devicedb.SetDeviceActionResultParams{ID: st.id, ActionRevision: actionRevision(st.attestation.GetActionRevision()), AttestationEnvelope: st.envelope, AttestationCertificate: st.certificate, StatusDocument: document, ReceivedAt: core.Timestamptz(now), OutcomeUnknown: unknown}); err != nil {
		return core.MapErr(err)
	}
	st.closed = terminal
	if terminal {
		if err := q.CloseDeviceAction(ctx, devicedb.CloseDeviceActionParams{ID: st.id, ClosedAt: core.Timestamptz(now), ClosedReason: "result"}); err != nil {
			return core.MapErr(err)
		}
	}
	spec, succeeded := k.intent.GetSpec(), status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED
	if spec.GetLocalAdminPasswordRotate() != nil {
		if err := secrets.SettleLocalAdminPassword(ctx, q, k.action, status, now); err != nil {
			return core.MapErr(err)
		}
	}
	if release := spec.GetReleaseQuarantine(); release != nil && succeeded {
		restriction, err := q.GetDeviceActionRestriction(ctx, st.principal.DeviceID)
		if err != nil {
			return core.MapErr(err)
		}
		if restriction.ActionID.String() != release.GetQuarantineActionId() {
			return rpcreason.Error(connect.CodeAborted, "device_action_quarantine_changed")
		}
		if err := q.SetDeviceActionRestriction(ctx, devicedb.SetDeviceActionRestrictionParams{DeviceID: st.principal.DeviceID, ActionID: st.id, SetQuarantine: true, Quarantined: false, UpdatedAt: core.Timestamptz(now)}); err != nil {
			return core.MapErr(err)
		}
	}
	if release := spec.GetReleaseLock(); release != nil && succeeded {
		if !status.GetVerification().GetVerified() || !status.GetVerification().GetAfter().GetSupported() {
			return rpcreason.Error(connect.CodePermissionDenied, "device_action_lock_release_unverified")
		}
		lockID, _ := uuid.Parse(release.GetLockActionId())
		if err := q.ReleaseDeviceActionLock(ctx, devicedb.ReleaseDeviceActionLockParams{DeviceID: st.principal.DeviceID, LockActionID: &lockID, UpdatedAt: core.Timestamptz(now)}); err != nil {
			return core.MapErr(err)
		}
	}
	return nil
}

func ValidatePowerActionResult(spec *agentv1.DeviceActionSpec, challenge *agentv1.DeviceActionChallenge, status *agentv1.DeviceActionStatus) error {
	verification := status.GetVerification()
	if spec.GetShutdown() != nil {
		// An accepted request or later contact proves neither power-off nor its
		// duration. Preserve the signed evidence, never convert it to success.
		if status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED || verification.GetVerified() {
			return rpcreason.Error(connect.CodePermissionDenied, "device_action_shutdown_unverifiable")
		}
		if verification.GetPowerRequestAccepted() && (status.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN || verification.GetEvidence() != "outcome_unknown_until_contact") {
			return rpcreason.Error(connect.CodePermissionDenied, "device_action_shutdown_outcome_unknown")
		}
	}
	if spec.GetRestart() != nil && status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED {
		boot := verification.GetBootId()
		if challenge.GetBootId() == "" || boot == "" || boot == challenge.GetBootId() || boot != verification.GetAfter().GetBootId() || !verification.GetVerified() || !verification.GetAfter().GetSupported() {
			return rpcreason.Error(connect.CodePermissionDenied, "device_action_restart_unverified")
		}
	}
	return nil
}

// Patch now succeeds when the native run unit was started; installation
// outcome is reported separately through patch status, never by this action.
func ValidatePatchNowResult(spec *agentv1.DeviceActionSpec, status *agentv1.DeviceActionStatus) error {
	verification := status.GetVerification()
	if spec.GetPatchNow() == nil {
		if verification.GetPatchRunStarted() {
			return rpcreason.Error(connect.CodePermissionDenied, "device_action_patch_run_unexpected")
		}
		return nil
	}
	if verification.GetPowerRequestAccepted() {
		return rpcreason.Error(connect.CodePermissionDenied, "device_action_patch_now_power_claimed")
	}
	if status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED && (!verification.GetVerified() || !verification.GetPatchRunStarted() || verification.GetEvidence() != "native_patch_run_started") {
		return rpcreason.Error(connect.CodePermissionDenied, "device_action_patch_now_unverified")
	}
	return nil
}
