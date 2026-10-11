package device

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"time"

	"connectrpc.com/connect"
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
	k := &resourceResult{}
	if req != nil && req.Msg != nil {
		k.cancellation = req.Msg.GetNeverPrepared()
	}
	st, err := reportSignedResult(ctx, s, message(req), k)
	if err != nil {
		return nil, err
	}
	return noStore(&devicev1.ReportResourceResultResponse{Closed: st.closed}), nil
}

type resourceResultState = resultState[*agentv1.ResourceExecutionStatus, *agentv1.ResourceExecutionAttestation]

// resourceResult is the resource half of result admission: the exact desired
// resource binding, staged preparation, release and disposition bookkeeping.
// A late report for an older action retains its evidence without overwriting
// a newer lease's disposition.
type resourceResult struct {
	cancellation *devicev1.ResourcePreparationCancellation
	action       devicedb.ResourceAction
	intent       *agentv1.ResourceExecutionIntent
	prior        *agentv1.ResourceExecutionStatus
}

var (
	_ resultKind[*agentv1.ResourceExecutionStatus, *agentv1.ResourceExecutionAttestation]      = (*resourceResult)(nil)
	_ resultLocker[*agentv1.ResourceExecutionStatus, *agentv1.ResourceExecutionAttestation]    = (*resourceResult)(nil)
	_ resultPreflight[*agentv1.ResourceExecutionStatus, *agentv1.ResourceExecutionAttestation] = (*resourceResult)(nil)
	_ resultRepeat[*agentv1.ResourceExecutionStatus, *agentv1.ResourceExecutionAttestation]    = (*resourceResult)(nil)
)

func (*resourceResult) reasons() signedReasons { return resourceReasons }

func (*resourceResult) newAttestation() *agentv1.ResourceExecutionAttestation {
	return new(agentv1.ResourceExecutionAttestation)
}

func (*resourceResult) lock(ctx context.Context, s *Service, st *resourceResultState) error {
	return mapErr(s.targeting.Lock(ctx, st.tx))
}

func (k *resourceResult) lockAction(ctx context.Context, _ *Service, st *resourceResultState) (signedRow, error) {
	if _, err := st.q.LockResourceAssignment(ctx, st.principal.GenerationID); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return signedRow{}, mapErr(err)
	}
	var err error
	if k.action, err = st.q.LockResourceAction(ctx, st.id); err != nil {
		return signedRow{}, mapErr(err)
	}
	if err := st.q.TouchDeviceLastSeen(ctx, devicedb.TouchDeviceLastSeenParams{ID: st.principal.DeviceID, LastSeenAt: timestamptz(st.now)}); err != nil {
		return signedRow{}, mapErr(err)
	}
	return resourceRow(k.action), nil
}

func (k *resourceResult) preflight(ctx context.Context, s *Service, st *resourceResultState) (bool, error) {
	if k.cancellation == nil {
		return false, nil
	}
	if _, err := s.reportNeverPreparedResource(ctx, st.tx, st.q, k.action, k.cancellation, st.now); err != nil {
		return true, err
	}
	st.closed = true
	return true, nil
}

func (*resourceResult) verifyAttestation(ctx context.Context, s *Service, st *resourceResultState, binding *trust.ResourceAttestationBinding) (*agentv1.ResourceExecutionAttestation, error) {
	return s.authority.VerifyResourceAttestation(ctx, st.envelope, st.certificate, s.ca, binding, st.now, trust.MaxDeviceClockSkew)
}

// sameRevision lets independent staging authenticate the identical pending
// revision with a fresh nonce, never changed history or refreshed native proof.
func (k *resourceResult) sameRevision(st *resourceResultState) (bool, error) {
	if err := k.decodePrior(st); err != nil {
		return false, err
	}
	return k.prior != nil && proto.Equal(k.prior, st.attestation.GetStatus()), nil
}

func (k *resourceResult) decodePrior(st *resourceResultState) error {
	if k.prior != nil || st.attestation.GetStatus().GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING || len(k.action.StatusDocument) == 0 {
		return nil
	}
	k.prior = new(agentv1.ResourceExecutionStatus)
	if err := proto.Unmarshal(k.action.StatusDocument, k.prior); err != nil {
		return mapErr(errInternalState)
	}
	return nil
}

func (k *resourceResult) admit(ctx context.Context, _ *Service, st *resourceResultState) error {
	if err := k.decodePrior(st); err != nil {
		return err
	}
	status := st.attestation.GetStatus()
	k.intent = new(agentv1.ResourceExecutionIntent)
	if err := proto.Unmarshal(k.action.IntentDocument, k.intent); err != nil {
		return mapErr(errInternalState)
	}
	if err := resourceResultBinding(k.intent, status); err != nil {
		return rpcreason.Error(connect.CodePermissionDenied, "resource_result_binding_rejected")
	}
	if _, err := resourceActionHead(k.action, k.intent); err != nil {
		return mapErr(err)
	}
	if err := requireReleaseBinding(ctx, st.q, k.action, k.intent); err != nil {
		return err
	}
	granted := len(k.action.StartGrantEnvelope) != 0
	preparing := status.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING || status.GetPreparationOutcome() != nil
	if granted && (status.GetReadOnly() || status.GetAdmissionRefusal() != nil || preparing) {
		return rpcreason.Error(connect.CodePermissionDenied, "resource_result_binding_rejected")
	}
	if preparing && k.prior != nil && k.prior.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING {
		return resourceReasons.resultConflict.err()
	}
	if k.action.ClosedAt.Valid && !resourceExecutionTerminal(status.GetState()) {
		return resourceReasons.resultConflict.err()
	}
	return nil
}

func (k *resourceResult) persist(ctx context.Context, s *Service, st *resourceResultState, document []byte) error {
	status, now := st.attestation.GetStatus(), st.now
	if err := st.q.SetResourceResult(ctx, devicedb.SetResourceResultParams{ID: st.id, ActionRevision: actionRevision(st.attestation.GetActionRevision()), AttestationEnvelope: st.envelope, AttestationCertificate: st.certificate, StatusDocument: document, AttestedAt: timestamptz(st.attestation.GetIssuedAt().AsTime()), ReceivedAt: timestamptz(now)}); err != nil {
		return mapErr(err)
	}
	terminal := resourceExecutionTerminal(status.GetState())
	st.closed = terminal || k.action.ClosedAt.Valid
	disposition, reason := int16(2), k.action.ClosedReason
	if terminal {
		closedReason := k.action.ClosedReason
		if closedReason == "" {
			closedReason = "result"
		}
		if err := st.q.CloseResourceAction(ctx, devicedb.CloseResourceActionParams{ID: st.id, ClosedAt: timestamptz(now), ClosedReason: closedReason}); err != nil {
			return mapErr(err)
		}
		disposition, reason = resourceResultDisposition(status)
	}
	if k.action.ReleaseID != nil {
		return k.settleRelease(ctx, st, terminal)
	}
	return k.settleAssignment(ctx, s, st, disposition, reason)
}

// resourceResultDisposition classifies terminal evidence for the assignment.
func resourceResultDisposition(status *agentv1.ResourceExecutionStatus) (int16, string) {
	switch {
	case status.GetAdmissionRefusal() != nil:
		if status.GetAdmissionRefusal().GetReason() == agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_PRECONDITION {
			return 5, "admission_precondition"
		}
		return 6, "native_unsupported"
	case status.GetReadOnly() && status.GetVerification().GetDisposition() == resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_NOT_APPLICABLE:
		// A successful release acknowledgment is not proof of the active
		// desired state, including when old converged evidence still exists.
		return 5, "not_applicable"
	case status.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED:
		return 3, ""
	case (status.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED || status.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUPERSEDED) && status.GetStartedAt() == nil:
		return 1, "no_effect"
	case status.GetReadOnly():
		if status.GetVerification().GetDisposition() == resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_UNKNOWN {
			return 4, "verification_unknown"
		}
		return 4, "verification_drifted"
	case status.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED && status.GetFailure() == agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NATIVE_BUSY && status.GetStartedAt() == nil:
		// Another native frontend owned the package database; nothing
		// changed. The hold is retried after the reconcile interval.
		return 5, resourceReasonNativeBusy
	case status.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_OUTCOME_UNKNOWN:
		return 4, "outcome_unknown"
	default:
		return 4, "execution_failed"
	}
}

func (k *resourceResult) settleRelease(ctx context.Context, st *resourceResultState, terminal bool) error {
	latest, err := st.q.LatestResourceReleaseAction(ctx, k.action.ReleaseID)
	if err != nil {
		return mapErr(err)
	}
	if !terminal || latest.ID != k.action.ID {
		return nil
	}
	state, reason := releaseResultState(st.attestation.GetStatus())
	completed := pgtype.Timestamptz{}
	if state == "released" {
		completed = timestamptz(st.now)
	}
	return mapErr(st.q.SetResourceReleaseState(ctx, devicedb.SetResourceReleaseStateParams{ID: *k.action.ReleaseID, State: state, Reason: reason, CompletedAt: completed}))
}

// settleAssignment records the disposition only for the latest action of the
// assigned resource, then execution health and read-only success retention.
func (k *resourceResult) settleAssignment(ctx context.Context, s *Service, st *resourceResultState, disposition int16, reason string) error {
	status, action := st.attestation.GetStatus(), k.action
	latest, err := st.q.LatestResourceAction(ctx, devicedb.LatestResourceActionParams{AssignmentID: action.AssignmentID, ResourceID: action.ResourceID})
	if err != nil {
		return mapErr(err)
	}
	if latest.ID == action.ID {
		if reason == resourceReasonNativeBusy {
			if err := st.q.HoldResource(ctx, devicedb.HoldResourceParams{AssignmentID: action.AssignmentID, ResourceID: action.ResourceID, Reason: reason, ObservedAt: timestamptz(st.now)}); err != nil {
				return mapErr(err)
			}
		} else if err := st.q.SetAssignmentResourceDisposition(ctx, devicedb.SetAssignmentResourceDispositionParams{AssignmentID: action.AssignmentID, ResourceID: action.ResourceID, Disposition: disposition, Reason: reason}); err != nil {
			return mapErr(err)
		}
		if disposition == 3 {
			if err := st.q.SetAssignmentResourceVerification(ctx, devicedb.SetAssignmentResourceVerificationParams{AssignmentID: action.AssignmentID, ResourceID: action.ResourceID, LastVerifiedAt: timestamptz(st.now), ObservedAt: timestamptz(status.GetVerification().GetAfter().GetMetadata().GetObservedAt().AsTime()), DriftRemediated: len(action.StartGrantEnvelope) != 0}); err != nil {
				return mapErr(err)
			}
		}
	}
	if err := s.targeting.RecordExecutionHealth(ctx, st.tx, st.principal.DeviceID, st.principal.GenerationID, action.AssignmentID); err != nil {
		return mapErr(err)
	}
	if disposition == 3 && len(action.StartGrantEnvelope) == 0 && status.GetStartedAt() == nil {
		if err := st.q.MarkResourceReadOnlySuccess(ctx, st.id); err != nil {
			return mapErr(err)
		}
		if err := st.q.PruneResourceReadOnlySuccesses(ctx, st.principal.GenerationID); err != nil {
			return mapErr(err)
		}
	}
	return nil
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
	if err := dispatchSystemAudit(ctx, q, nil, "resource_action.preparation_cancel", action.ID, "status", "executor_never_prepared"); err != nil {
		return nil, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return noStore(&devicev1.ReportResourceResultResponse{Closed: true}), nil
}
