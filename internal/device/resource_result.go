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
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/resource"
	"lindm/internal/rpcreason"
	"lindm/internal/trust"
)

func (s *Service) ReportResourceResult(ctx context.Context, req *connect.Request[devicev1.ReportResourceResultRequest]) (*connect.Response[devicev1.ReportResourceResultResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	principal, ok := devicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_service_result_request")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.targeting.Lock(ctx, tx); err != nil {
		return nil, mapErr(err)
	}
	q := devicedb.New(tx)
	device, err := s.lockAuthority(ctx, q, principal)
	if err != nil {
		return nil, mapErr(err)
	}
	if uint64(device.generation.SessionEpoch) != req.Msg.GetSessionEpoch() {
		return nil, mapErr(errSessionFenced)
	}
	if _, err := q.LockResourceAssignment(ctx, principal.GenerationID); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, mapErr(err)
	}
	id, _ := uuid.Parse(req.Msg.GetActionId())
	action, err := q.LockResourceAction(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	now, err := dispatchClock(ctx, q)
	if err != nil {
		return nil, mapErr(err)
	}
	if !enrollmentIssuanceResumable(device.certificate, now) {
		return nil, mapErr(errCertificateRejected)
	}
	if err := q.TouchDeviceLastSeen(ctx, devicedb.TouchDeviceLastSeenParams{ID: principal.DeviceID, LastSeenAt: timestamptz(now)}); err != nil {
		return nil, mapErr(err)
	}
	if action.DeviceID != principal.DeviceID || action.GenerationID != principal.GenerationID {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "resource_action_binding_rejected")
	}
	if cancellation := req.Msg.GetNeverPrepared(); cancellation != nil {
		return s.reportNeverPreparedResource(ctx, tx, q, action, cancellation, now)
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
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, mapErr(errCertificateRejected)
		}
		return nil, mapErr(err)
	}
	// The CA signature alone is insufficient: only a registered, non-revoked
	// certificate for this generation can attest, including during renewal overlap.
	if certificate.DeviceID != principal.DeviceID || certificate.GenerationID != principal.GenerationID || now.Before(certificate.NotBefore.Time) || !now.Before(certificate.NotAfter.Time) || (certificate.Status != "active" && (certificate.Status != "overlapping" || !certificate.OverlapUntil.Valid || !now.Before(certificate.OverlapUntil.Time))) {
		return nil, mapErr(errCertificateRejected)
	}
	if bytes.Equal(action.AttestationEnvelope, req.Msg.GetAttestationEnvelope()) && bytes.Equal(action.AttestationCertificate, req.Msg.GetCertificatePem()) {
		// This exact evidence was already cryptographically admitted. Consumed nonce
		// and subsequent wall-clock expiry cannot make a lost response non-idempotent.
		public, ok := leaf.PublicKey.(ed25519.PublicKey)
		if !ok {
			return nil, mapErr(errCertificateRejected)
		}
		accepted := new(agentv1.ResourceExecutionAttestation)
		if err := s.authority.Verify(ctx, action.AttestationEnvelope, accepted, 1, public); err != nil || accepted.GetSessionEpoch() != req.Msg.GetSessionEpoch() {
			return nil, rpcreason.Error(connect.CodePermissionDenied, "resource_result_rejected")
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, mapErr(err)
		}
		return noStore(&devicev1.ReportResourceResultResponse{Closed: action.ClosedAt.Valid}), nil
	}
	if len(action.ResultNonce) != 32 || !action.NonceExpiresAt.Valid || !now.Before(action.NonceExpiresAt.Time) {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "resource_result_nonce_rejected")
	}
	binding := &trust.ResourceAttestationBinding{DeploymentID: s.deploymentID, DeviceID: principal.DeviceID, EnrollmentGeneration: principal.GenerationID, SessionEpoch: req.Msg.GetSessionEpoch(), ActionID: id, IntentSHA256: sha256.Sum256(action.IntentEnvelope)}
	copy(binding.Nonce[:], action.ResultNonce)
	attestation, err := s.authority.VerifyResourceAttestation(ctx, req.Msg.GetAttestationEnvelope(), req.Msg.GetCertificatePem(), s.ca, binding, now, trust.MaxDeviceClockSkew)
	if errors.Is(err, trust.ErrDeviceClockSkew) {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "device_clock_skew")
	}
	if err != nil {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "resource_result_rejected")
	}
	previous, err := resourceActionRevision(action)
	if err != nil {
		return nil, mapErr(err)
	}
	status := attestation.GetStatus()
	var priorPreparation *agentv1.ResourceExecutionStatus
	if status.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING && len(action.StatusDocument) != 0 {
		priorPreparation = new(agentv1.ResourceExecutionStatus)
		if err := proto.Unmarshal(action.StatusDocument, priorPreparation); err != nil {
			return nil, mapErr(errInternalState)
		}
	}
	// Independent staging need not mutate the journal every cycle. A fresh
	// nonce may authenticate the identical pending revision, never changed
	// history or refreshed native proof. All other states remain increasing.
	if attestation.GetActionRevision() < previous ||
		(attestation.GetActionRevision() == previous && (priorPreparation == nil || !proto.Equal(priorPreparation, status))) {
		return nil, rpcreason.Error(connect.CodeAlreadyExists, "resource_result_conflict")
	}
	intent := new(agentv1.ResourceExecutionIntent)
	if err := proto.Unmarshal(action.IntentDocument, intent); err != nil {
		return nil, mapErr(errInternalState)
	}
	if err := resourceResultBinding(intent, status); err != nil {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "resource_result_binding_rejected")
	}
	if _, err := resourceActionHead(action, intent); err != nil {
		return nil, mapErr(err)
	}
	if action.ReleaseID != nil {
		release, err := q.GetResourceRelease(ctx, *action.ReleaseID)
		if err != nil {
			return nil, mapErr(err)
		}
		if err := validateReleaseAction(release, action, intent); err != nil {
			return nil, rpcreason.Error(connect.CodePermissionDenied, "resource_release_binding_rejected")
		}
	}
	if (status.GetReadOnly() || status.GetAdmissionRefusal() != nil) && len(action.StartGrantEnvelope) != 0 {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "resource_result_binding_rejected")
	}
	terminal := resourceExecutionTerminal(status.GetState())
	if status.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING || status.GetPreparationOutcome() != nil {
		if len(action.StartGrantEnvelope) != 0 {
			return nil, rpcreason.Error(connect.CodePermissionDenied, "resource_result_binding_rejected")
		}
		if priorPreparation != nil && priorPreparation.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING {
			return nil, rpcreason.Error(connect.CodeAlreadyExists, "resource_result_conflict")
		}
	}
	if action.ClosedAt.Valid && !terminal {
		return nil, rpcreason.Error(connect.CodeAlreadyExists, "resource_result_conflict")
	}
	encoded, err := proto.Marshal(status)
	if err != nil {
		return nil, mapErr(err)
	}
	if err := q.SetResourceResult(ctx, devicedb.SetResourceResultParams{ID: id, ActionRevision: pgtype.Numeric{Int: new(big.Int).SetUint64(attestation.GetActionRevision()), Valid: true}, AttestationEnvelope: req.Msg.GetAttestationEnvelope(), AttestationCertificate: req.Msg.GetCertificatePem(), StatusDocument: encoded, AttestedAt: timestamptz(attestation.GetIssuedAt().AsTime()), ReceivedAt: timestamptz(now)}); err != nil {
		return nil, mapErr(err)
	}
	disposition, reason := int16(2), action.ClosedReason
	if terminal {
		closedReason := action.ClosedReason
		if closedReason == "" {
			closedReason = "result"
		}
		if err := q.CloseResourceAction(ctx, devicedb.CloseResourceActionParams{ID: id, ClosedAt: timestamptz(now), ClosedReason: closedReason}); err != nil {
			return nil, mapErr(err)
		}
		switch {
		case status.GetAdmissionRefusal() != nil:
			disposition, reason = 6, "native_unsupported"
			if status.GetAdmissionRefusal().GetReason() == agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_PRECONDITION {
				disposition, reason = 5, "admission_precondition"
			}
		case status.GetReadOnly() && status.GetVerification().GetDisposition() == resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_NOT_APPLICABLE:
			// A successful release acknowledgment is not proof of the active
			// desired state, including when old converged evidence still exists.
			disposition, reason = 5, "not_applicable"
		case status.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED:
			disposition, reason = 3, ""
		case (status.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED || status.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUPERSEDED) && status.GetStartedAt() == nil:
			disposition, reason = 1, "no_effect"
		case status.GetReadOnly():
			disposition, reason = 4, "verification_drifted"
			if status.GetVerification().GetDisposition() == resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_UNKNOWN {
				reason = "verification_unknown"
			}
		default:
			disposition, reason = 4, "execution_failed"
			if status.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_OUTCOME_UNKNOWN {
				reason = "outcome_unknown"
			}
		}
	}
	if action.ReleaseID != nil {
		latest, err := q.LatestResourceReleaseAction(ctx, action.ReleaseID)
		if err != nil {
			return nil, mapErr(err)
		}
		if terminal && latest.ID == action.ID {
			state, reason := releaseResultState(status)
			completed := pgtype.Timestamptz{}
			if state == "released" {
				completed = timestamptz(now)
			}
			if err := q.SetResourceReleaseState(ctx, devicedb.SetResourceReleaseStateParams{ID: *action.ReleaseID, State: state, Reason: reason, CompletedAt: completed}); err != nil {
				return nil, mapErr(err)
			}
		}
	} else {
		// A late report for an older action must not overwrite a newer lease's
		// disposition, even though the signed evidence remains retained and audited.
		latest, err := q.LatestResourceAction(ctx, devicedb.LatestResourceActionParams{AssignmentID: action.AssignmentID, ResourceID: action.ResourceID})
		if err != nil {
			return nil, mapErr(err)
		}
		if latest.ID == action.ID {
			if err := q.SetAssignmentResourceDisposition(ctx, devicedb.SetAssignmentResourceDispositionParams{AssignmentID: action.AssignmentID, ResourceID: action.ResourceID, Disposition: disposition, Reason: reason}); err != nil {
				return nil, mapErr(err)
			}
			if disposition == 3 {
				if err := q.SetAssignmentResourceVerification(ctx, devicedb.SetAssignmentResourceVerificationParams{AssignmentID: action.AssignmentID, ResourceID: action.ResourceID, LastVerifiedAt: timestamptz(now), ObservedAt: timestamptz(status.GetVerification().GetAfter().GetMetadata().GetObservedAt().AsTime()), DriftRemediated: len(action.StartGrantEnvelope) != 0}); err != nil {
					return nil, mapErr(err)
				}
			}
		}
		if err := s.targeting.RecordExecutionHealth(ctx, tx, principal.DeviceID, principal.GenerationID, action.AssignmentID); err != nil {
			return nil, mapErr(err)
		}
		if disposition == 3 && len(action.StartGrantEnvelope) == 0 && status.GetStartedAt() == nil {
			if err := q.MarkResourceReadOnlySuccess(ctx, id); err != nil {
				return nil, mapErr(err)
			}
			if err := q.PruneResourceReadOnlySuccesses(ctx, principal.GenerationID); err != nil {
				return nil, mapErr(err)
			}
		}
	}
	if err := dispatchAudit(ctx, q, nil, "resource_action.result", id, "verified_device_attestation"); err != nil {
		return nil, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return noStore(&devicev1.ReportResourceResultResponse{Closed: terminal || action.ClosedAt.Valid}), nil
}

// The signed history authenticates the executor, but compliance must additionally
// describe the exact canonical desired resource admitted by this action.
func resourceResultBinding(intent *agentv1.ResourceExecutionIntent, status *agentv1.ResourceExecutionStatus) error {
	if refusal := status.GetAdmissionRefusal(); refusal != nil {
		if !proto.Equal(refusal.GetRef(), intent.GetDesired().GetRef()) || refusal.GetOperation() != intent.GetOperation() ||
			status.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED ||
			status.GetBefore() != nil || status.GetVerification() != nil || status.GetStartedAt() != nil || status.GetReadOnly() || status.GetPreparationOutcome() != nil ||
			!refusal.GetNativeEvidenceUnavailable() {
			return errors.New("resource_admission_refusal_binding_rejected")
		}
		switch refusal.GetReason() {
		case agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_BASELINE_UNKNOWN:
			if intent.GetOperation() != resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE || status.GetFailure() != agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_UNSUPPORTED {
				return errors.New("resource_admission_refusal_binding_rejected")
			}
		case agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_UNSUPPORTED_NATIVE:
			if status.GetFailure() != agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_UNSUPPORTED {
				return errors.New("resource_admission_refusal_binding_rejected")
			}
		case agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_PRECONDITION:
			if status.GetFailure() != agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION {
				return errors.New("resource_admission_refusal_binding_rejected")
			}
		default:
			return errors.New("resource_admission_refusal_binding_rejected")
		}
		return nil
	}
	if intent.GetDesired().GetEncryptionCompliance() != nil && (status.GetStartedAt() != nil || !status.GetReadOnly()) {
		return errors.New("resource_result_read_only_mismatch")
	}
	// The attestation binding already authenticates the exact intent digest.
	// Staging has no native evidence; only its immutable signed limits can be
	// compared until a real plan and before observation exist.
	if status.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING || status.GetPreparationOutcome() != nil {
		if intent.GetDesired().GetNativePackage() == nil || intent.GetPreparation() == nil {
			return errors.New("resource_result_preparation_mismatch")
		}
		if outcome := status.GetPreparationOutcome(); outcome != nil && !proto.Equal(outcome.GetPreparation(), intent.GetPreparation()) {
			return errors.New("resource_result_preparation_mismatch")
		}
		return nil
	}
	if !proto.Equal(status.GetBefore().GetRef(), intent.GetDesired().GetRef()) {
		return errors.New("resource_result_ref_mismatch")
	}
	if err := resource.ValidateObservation(status.GetBefore()); err != nil {
		return err
	}
	if verification := status.GetVerification(); verification != nil {
		if err := resource.ValidateVerification(verification); err != nil {
			return err
		}
		if verification.GetDisposition() == resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_NOT_APPLICABLE &&
			(!status.GetReadOnly() || intent.GetOperation() != resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE) {
			return errors.New("resource_result_release_mismatch")
		}
		digest, err := resource.DesiredDigest(intent.GetDesired())
		if err != nil {
			return err
		}
		if !proto.Equal(verification.GetRef(), intent.GetDesired().GetRef()) || !bytes.Equal(verification.GetDesiredSha256(), digest[:]) {
			return errors.New("resource_result_desired_mismatch")
		}
	}
	return nil
}

func resourceExecutionTerminal(state agentv1.ResourceExecutionState) bool {
	switch state {
	case agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED,
		agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED,
		agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_OUTCOME_UNKNOWN,
		agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED,
		agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUPERSEDED:
		return true
	default:
		return false
	}
}

// A generation-authenticated cancellation acknowledgment is not a native result.
// The protected executor has durably tombstoned this exact action/intent before
// returning never_prepared. Retain the nonce for exact lost-response retries,
// without writing a fabricated status, observation, revision or verification.
func (s *Service) reportNeverPreparedResource(ctx context.Context, tx pgx.Tx, q *devicedb.Queries, action devicedb.ResourceAction, cancellation *devicev1.ResourcePreparationCancellation, now time.Time) (*connect.Response[devicev1.ReportResourceResultResponse], error) {
	digest := sha256.Sum256(action.IntentEnvelope)
	if len(action.StartGrantEnvelope) != 0 || !bytes.Equal(cancellation.GetIntentSha256(), digest[:]) || !bytes.Equal(cancellation.GetResultNonce(), action.ResultNonce) {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "resource_cancellation_binding_rejected")
	}
	intent := new(agentv1.ResourceExecutionIntent)
	if err := proto.Unmarshal(action.IntentDocument, intent); err != nil {
		return nil, mapErr(errInternalState)
	}
	if intent.GetPreparation() == nil || intent.GetDesired().GetNativePackage() == nil {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "resource_cancellation_binding_rejected")
	}
	if _, err := resourceActionHead(action, intent); err != nil {
		return nil, mapErr(err)
	}
	if action.ClosedAt.Valid {
		if !strings.HasSuffix(action.ClosedReason, "_never_prepared") {
			return nil, rpcreason.Error(connect.CodeAlreadyExists, "resource_result_conflict")
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, mapErr(err)
		}
		return noStore(&devicev1.ReportResourceResultResponse{Closed: true}), nil
	}
	if action.ClosedReason == "" || len(action.StatusDocument) != 0 {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "resource_cancellation_not_requested")
	}
	if !action.NonceExpiresAt.Valid || !now.Before(action.NonceExpiresAt.Time) {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "resource_result_nonce_rejected")
	}
	if err := q.CloseResourceAction(ctx, devicedb.CloseResourceActionParams{ID: action.ID, ClosedAt: timestamptz(now), ClosedReason: action.ClosedReason + "_never_prepared"}); err != nil {
		return nil, mapErr(err)
	}
	if action.ReleaseID != nil {
		release, err := q.GetResourceRelease(ctx, *action.ReleaseID)
		if err != nil {
			return nil, mapErr(err)
		}
		if err := validateReleaseAction(release, action, intent); err != nil {
			return nil, rpcreason.Error(connect.CodePermissionDenied, "resource_release_binding_rejected")
		}
		if err := q.SetResourceReleaseState(ctx, devicedb.SetResourceReleaseStateParams{ID: release.ID, State: "release_conflict", Reason: "cancelled_no_effect"}); err != nil {
			return nil, mapErr(err)
		}
	} else {
		if err := q.SetAssignmentResourceDisposition(ctx, devicedb.SetAssignmentResourceDispositionParams{AssignmentID: action.AssignmentID, ResourceID: action.ResourceID, Disposition: 1, Reason: "no_effect"}); err != nil {
			return nil, mapErr(err)
		}
		if err := s.targeting.RecordExecutionHealth(ctx, tx, action.DeviceID, action.GenerationID, action.AssignmentID); err != nil {
			return nil, mapErr(err)
		}
	}
	if err := dispatchAudit(ctx, q, nil, "resource_action.preparation_cancel", action.ID, "executor_never_prepared"); err != nil {
		return nil, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return noStore(&devicev1.ReportResourceResultResponse{Closed: true}), nil
}
