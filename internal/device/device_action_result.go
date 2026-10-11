package device

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/rpcreason"
	"lindm/internal/trust"
)

func (s *Service) ReportDeviceActionResult(ctx context.Context, req *connect.Request[devicev1.ReportDeviceActionResultRequest]) (*connect.Response[devicev1.ReportDeviceActionResultResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	principal, ok := devicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_device_action_result")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := devicedb.New(tx)
	device, err := s.lockAuthority(ctx, q, principal)
	if err != nil {
		return nil, mapErr(err)
	}
	if uint64(device.generation.SessionEpoch) != req.Msg.GetSessionEpoch() {
		return nil, mapErr(errSessionFenced)
	}
	id, _ := uuid.Parse(req.Msg.GetActionId())
	action, err := q.LockDeviceAction(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	if action.DeviceID != principal.DeviceID || action.GenerationID != principal.GenerationID {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "device_action_binding_rejected")
	}
	now, err := dispatchClock(ctx, q)
	if err != nil {
		return nil, mapErr(err)
	}
	if !enrollmentIssuanceResumable(device.certificate, now) {
		return nil, mapErr(errCertificateRejected)
	}
	block, rest := pem.Decode(req.Msg.GetCertificatePem())
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, mapErr(errCertificateRejected)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, mapErr(errCertificateRejected)
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	certificate, err := q.GetCertificateByFingerprint(ctx, fingerprint[:])
	if err != nil {
		return nil, mapErr(errCertificateRejected)
	}
	if certificate.DeviceID != principal.DeviceID || certificate.GenerationID != principal.GenerationID || now.Before(certificate.NotBefore.Time) || !now.Before(certificate.NotAfter.Time) || (certificate.Status != "active" && (certificate.Status != "overlapping" || !certificate.OverlapUntil.Valid || !now.Before(certificate.OverlapUntil.Time))) {
		return nil, mapErr(errCertificateRejected)
	}
	if bytes.Equal(action.AttestationEnvelope, req.Msg.GetAttestationEnvelope()) && bytes.Equal(action.AttestationCertificate, req.Msg.GetCertificatePem()) {
		public, ok := leaf.PublicKey.(ed25519.PublicKey)
		if !ok {
			return nil, mapErr(errCertificateRejected)
		}
		accepted := new(agentv1.DeviceActionAttestation)
		if err := s.authority.Verify(ctx, action.AttestationEnvelope, accepted, 1, public); err != nil || accepted.GetSessionEpoch() != req.Msg.GetSessionEpoch() {
			return nil, rpcreason.Error(connect.CodePermissionDenied, "device_action_result_rejected")
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, mapErr(err)
		}
		receipt, err := s.deviceActionReceipt(ctx, principal, req.Msg.GetSessionEpoch(), id)
		if err != nil {
			return nil, err
		}
		return noStore(&devicev1.ReportDeviceActionResultResponse{Closed: action.ClosedAt.Valid, EscrowReceiptEnvelope: receipt}), nil
	}
	if len(action.ResultNonce) != 32 || !action.NonceExpiresAt.Valid || !now.Before(action.NonceExpiresAt.Time) {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "device_action_result_nonce_rejected")
	}
	binding := &trust.DeviceActionAttestationBinding{DeploymentID: s.deploymentID, DeviceID: principal.DeviceID, EnrollmentGeneration: principal.GenerationID, SessionEpoch: req.Msg.GetSessionEpoch(), ActionID: id, IntentSHA256: sha256.Sum256(action.IntentEnvelope)}
	copy(binding.Nonce[:], action.ResultNonce)
	attestation, err := s.authority.VerifyDeviceActionAttestation(ctx, req.Msg.GetAttestationEnvelope(), req.Msg.GetCertificatePem(), s.ca, binding, now, trust.MaxDeviceClockSkew)
	if err != nil {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "device_action_result_rejected")
	}
	previous := action.ActionRevision
	if !previous.Valid || previous.Int == nil || !previous.Int.IsUint64() || attestation.GetActionRevision() <= previous.Int.Uint64() {
		return nil, rpcreason.Error(connect.CodeAlreadyExists, "device_action_result_conflict")
	}
	status := attestation.GetStatus()
	intent, err := actionIntent(action)
	if err != nil {
		return nil, mapErr(err)
	}
	if action.ClosedAt.Valid {
		return nil, rpcreason.Error(connect.CodeAlreadyExists, "device_action_result_closed")
	}
	if status.GetStartedAt() != nil && len(action.StartGrantEnvelope) == 0 {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "device_action_ungranted_result")
	}
	if status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED && len(action.StartGrantEnvelope) == 0 {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "device_action_ungranted_result")
	}
	if intent.GetSpec().GetSanitize().GetRecovery() != nil && (status.GetStartedAt() != nil || action.OutcomeUnknown) {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "recovery_result_endpoint_required")
	}
	admittedChallenge := new(agentv1.DeviceActionChallenge)
	if len(action.ChallengeDocument) > 0 && proto.Unmarshal(action.ChallengeDocument, admittedChallenge) != nil {
		return nil, mapErr(errInternalState)
	}
	if err := validateLiveRootResult(intent.GetSpec(), admittedChallenge, status); err != nil {
		return nil, err
	}
	if err := validatePowerActionResult(intent.GetSpec(), admittedChallenge, status); err != nil {
		return nil, err
	}
	if err := validatePatchNowResult(intent.GetSpec(), status); err != nil {
		return nil, err
	}
	if intent.GetSpec().GetRefreshInventory() != nil && status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED {
		sequence := status.GetVerification().GetInventorySequence()
		if sequence == 0 || !status.GetVerification().GetVerified() || !status.GetVerification().GetAfter().GetSupported() || admittedChallenge.GetIssuedAt() == nil {
			return nil, rpcreason.Error(connect.CodePermissionDenied, "device_action_inventory_unverified")
		}
		if action.InventoryPackageSequence != int64(sequence) {
			return nil, rpcreason.Error(connect.CodePermissionDenied, "device_action_inventory_receipt_mismatch")
		}
		if len(action.InventoryReceiptEnvelope) == 0 {
			return nil, rpcreason.Error(connect.CodeFailedPrecondition, "device_action_inventory_receipt_required")
		}
		// This document was committed with the verified server-signed receipt.
		// Do not reverify historical custody with a possibly rotated current key
		// or require the mutable latest host row to retain the admitted sequence.
		receipt := new(agentv1.DeviceActionInventoryReceipt)
		if proto.Unmarshal(action.InventoryReceiptDocument, receipt) != nil || receipt.GetActionId() != id.String() || receipt.GetDeviceId() != principal.DeviceID.String() || receipt.GetEnrollmentGeneration() != principal.GenerationID.String() {
			return nil, mapErr(errInternalState)
		}
		if receipt.GetPackageSequence() != sequence || receipt.GetHostSequence() != uint64(action.InventoryHostSequence) {
			return nil, rpcreason.Error(connect.CodePermissionDenied, "device_action_inventory_receipt_mismatch")
		}
	}
	incoming := status.GetVerification().GetEscrow()
	if incoming != nil && intent.GetSpec().GetLocalAdminPasswordRotate() != nil {
		if err := s.ingestLocalAdminEscrow(ctx, q, action, intent, incoming); err != nil {
			return nil, mapErr(err)
		}
	} else if incoming != nil {
		if intent.GetSpec().GetEscrowRotate() == nil || len(action.StartGrantEnvelope) == 0 || s.escrow == nil || incoming.GetEscrowKeyId() != s.escrow.KeyID() || incoming.GetLocalAdmin() != nil || incoming.GetLuksUuid() != intent.GetSpec().GetEscrowRotate().GetTarget().GetLuksUuid() {
			return nil, rpcreason.Error(connect.CodePermissionDenied, "device_action_escrow_binding_rejected")
		}
		challenge := new(agentv1.DeviceActionChallenge)
		if err := proto.Unmarshal(action.ChallengeDocument, challenge); err != nil {
			return nil, mapErr(errInternalState)
		}
		recovery := challenge.GetNativePlan().GetRecoveryBinding()
		if recovery.GetDeviceId() != intent.GetDeviceId() || recovery.GetEnrollmentGeneration() != intent.GetEnrollmentGeneration() || recovery.GetActionId() != intent.GetActionId() || recovery.GetLuksUuid() != incoming.GetLuksUuid() || recovery.GetNewKeyslot() != incoming.GetNewKeyslot() {
			return nil, rpcreason.Error(connect.CodePermissionDenied, "device_action_escrow_binding_rejected")
		}
		canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(recovery)
		if err != nil {
			return nil, mapErr(err)
		}
		retained, err := q.GetDeviceActionEscrow(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			sealed, err := s.escrow.OpenAndSeal(canonical, incoming.GetCiphertext())
			if err != nil {
				return nil, rpcreason.Error(connect.CodePermissionDenied, "device_action_escrow_rejected")
			}
			if !bytes.Equal(sealed.SecretSHA256, incoming.GetRecoveryKeySha256()) {
				return nil, rpcreason.Error(connect.CodePermissionDenied, "device_action_escrow_digest_rejected")
			}
			if _, err := q.InsertDeviceActionEscrow(ctx, devicedb.InsertDeviceActionEscrowParams{ActionID: id, BindingDocument: canonical, KeyID: sealed.KeyID, WrappedKey: sealed.WrappedKey, Ciphertext: sealed.Ciphertext, SecretSha256: sealed.SecretSHA256}); err != nil {
				return nil, mapErr(err)
			}
			if err := dispatchAudit(ctx, q, nil, "device_action.escrow_store", id, "verified_encrypted_recovery"); err != nil {
				return nil, mapErr(err)
			}
		} else if err != nil {
			return nil, mapErr(err)
		} else if !bytes.Equal(retained.BindingDocument, canonical) || !bytes.Equal(retained.SecretSha256, incoming.GetRecoveryKeySha256()) {
			return nil, rpcreason.Error(connect.CodeAlreadyExists, "device_action_escrow_conflict")
		}
	}
	if incoming != nil {
		if len(action.StatusDocument) > 0 {
			previousStatus := new(agentv1.DeviceActionStatus)
			if proto.Unmarshal(action.StatusDocument, previousStatus) != nil {
				return nil, mapErr(errInternalState)
			}
			if previousEscrow := previousStatus.GetVerification().GetEscrow(); previousEscrow != nil && !proto.Equal(previousEscrow, incoming) {
				return nil, rpcreason.Error(connect.CodeAlreadyExists, "device_action_escrow_conflict")
			}
		}
	}
	if (intent.GetSpec().GetEscrowRotate() != nil || intent.GetSpec().GetLocalAdminPasswordRotate() != nil) && status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED && len(action.EscrowReceiptEnvelope) == 0 {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "device_action_escrow_receipt_required")
	}
	encoded, err := proto.Marshal(status)
	if err != nil {
		return nil, mapErr(err)
	}
	unknown := len(action.StartGrantEnvelope) > 0 && !actionTerminal(status.GetState())
	if err := q.SetDeviceActionResult(ctx, devicedb.SetDeviceActionResultParams{ID: id, ActionRevision: pgtype.Numeric{Int: new(big.Int).SetUint64(attestation.GetActionRevision()), Valid: true}, AttestationEnvelope: req.Msg.GetAttestationEnvelope(), AttestationCertificate: req.Msg.GetCertificatePem(), StatusDocument: encoded, ReceivedAt: timestamptz(now), OutcomeUnknown: unknown}); err != nil {
		return nil, mapErr(err)
	}
	terminal := actionTerminal(status.GetState())
	if terminal {
		if err := q.CloseDeviceAction(ctx, devicedb.CloseDeviceActionParams{ID: id, ClosedAt: timestamptz(now), ClosedReason: "result"}); err != nil {
			return nil, mapErr(err)
		}
	}
	if intent.GetSpec().GetLocalAdminPasswordRotate() != nil {
		if err := settleLocalAdminPassword(ctx, q, action, status, now); err != nil {
			return nil, mapErr(err)
		}
	}
	if release := intent.GetSpec().GetReleaseQuarantine(); release != nil && status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED {
		restriction, err := q.GetDeviceActionRestriction(ctx, principal.DeviceID)
		if err != nil {
			return nil, mapErr(err)
		}
		if restriction.ActionID.String() != release.GetQuarantineActionId() {
			return nil, rpcreason.Error(connect.CodeAborted, "device_action_quarantine_changed")
		}
		if err := q.SetDeviceActionRestriction(ctx, devicedb.SetDeviceActionRestrictionParams{DeviceID: principal.DeviceID, ActionID: id, SetQuarantine: true, Quarantined: false, UpdatedAt: timestamptz(now)}); err != nil {
			return nil, mapErr(err)
		}
	}
	if release := intent.GetSpec().GetReleaseLock(); release != nil && status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED {
		if !status.GetVerification().GetVerified() || !status.GetVerification().GetAfter().GetSupported() {
			return nil, rpcreason.Error(connect.CodePermissionDenied, "device_action_lock_release_unverified")
		}
		lockID, _ := uuid.Parse(release.GetLockActionId())
		if err := q.ReleaseDeviceActionLock(ctx, devicedb.ReleaseDeviceActionLockParams{DeviceID: principal.DeviceID, LockActionID: &lockID, UpdatedAt: timestamptz(now)}); err != nil {
			return nil, mapErr(err)
		}
	}
	if err := dispatchAudit(ctx, q, nil, "device_action.result", id, "verified_device_attestation"); err != nil {
		return nil, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	// A receipt is signed only in a subsequent transaction, after custody committed.
	receipt, err := s.deviceActionReceipt(ctx, principal, req.Msg.GetSessionEpoch(), id)
	if err != nil {
		return nil, err
	}
	return noStore(&devicev1.ReportDeviceActionResultResponse{Closed: terminal, EscrowReceiptEnvelope: receipt}), nil
}

func validatePowerActionResult(spec *agentv1.DeviceActionSpec, challenge *agentv1.DeviceActionChallenge, status *agentv1.DeviceActionStatus) error {
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
func validatePatchNowResult(spec *agentv1.DeviceActionSpec, status *agentv1.DeviceActionStatus) error {
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
