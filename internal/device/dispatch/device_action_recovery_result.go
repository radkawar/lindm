package dispatch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"math/big"
	"time"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	recoveryv1 "lindm/gen/lindm/recovery/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/executionauthority"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
	"lindm/internal/trust"
)

func (s *Service) CheckpointRecoveryAction(ctx context.Context, req *connect.Request[recoveryv1.CheckpointRecoveryActionRequest]) (*connect.Response[recoveryv1.CheckpointRecoveryActionResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_recovery_checkpoint")
	}
	if s.Execution == nil || s.Signing == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "execution_signing_unconfigured")
	}
	admission, err := s.authenticateRecovery(ctx, req.Msg.GetCredentialEnvelope(), req.Msg.GetRequestProof(), agentv1.RecoveryOperation_RECOVERY_OPERATION_CHECKPOINT, RecoveryCheckpointPayload(req.Msg))
	if err != nil {
		return nil, err
	}
	checkpoint := req.Msg.GetCheckpoint()
	effect := checkpoint.GetPhase() == agentv1.RecoveryPhase_RECOVERY_PHASE_EFFECT_COMMITTED
	if checkpoint.GetCredentialId() != admission.row.CredentialID.String() || checkpoint.GetActionId() != admission.row.ActionID.String() || checkpoint.GetBootId() != admission.proof.GetBootId() || checkpoint.GetExecutorIncarnation() != admission.proof.GetExecutorIncarnation() {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "recovery_checkpoint_binding_rejected")
	}
	// The durable effect gate rechecks both humans again, even if a granted
	// challenge was revoked during its short network round trip.
	var authorization *identity.Authorization
	var pair *identity.ApprovalConsumption
	if effect && !admission.row.EffectCommittedAt.Valid {
		authorization, pair, err = s.recoveryApproval(ctx, admission.action)
		if err != nil {
			return nil, err
		}
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if pair != nil {
		if err := s.Identity.LockAndConsumeApproval(ctx, tx, pair, s.recoveryApprovalScope); err != nil {
			return nil, core.ApprovalError(err)
		}
	}
	snapshot, verifier, err := s.Execution.CurrentInTransaction(ctx, tx)
	if err != nil {
		return nil, core.ExecutionError(err)
	}
	q := devicedb.New(tx)
	action, row, now, err := lockRecovery(ctx, q, admission, checkpoint.GetPhase() == agentv1.RecoveryPhase_RECOVERY_PHASE_TERMINAL || admission.row.EffectCommittedAt.Valid)
	if err != nil {
		return nil, core.MapErr(err)
	}
	response := &recoveryv1.CheckpointRecoveryActionResponse{}
	replay, err := recoveryRequestReplay(ctx, q, admission, response)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if replay {
		if err := tx.Commit(ctx); err != nil {
			return nil, core.MapErr(err)
		}
		return core.NoStore(response), nil
	}
	digest, err := core.ActionDigest(checkpoint)
	if err != nil {
		return nil, core.MapErr(err)
	}
	journalDocument, err := recoveryJournalDocument(req.Msg.GetJournal(), checkpoint, action, row, admission.credential, snapshot.Root, snapshot.DelegationEnvelope)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if bytes.Equal(digest, row.CheckpointSha256) && int64(checkpoint.GetSequence()) == row.CheckpointSequence {
		if !bytes.Equal(journalDocument, row.JournalDocument) {
			return nil, rpcreason.Error(connect.CodeAlreadyExists, "recovery_journal_conflict")
		}
		response = &recoveryv1.CheckpointRecoveryActionResponse{CheckpointSha256: digest, Sequence: checkpoint.GetSequence(), ReceiptEnvelope: row.CheckpointReceiptEnvelope}
	} else {
		if err := validateRecoveryCheckpoint(ctx, checkpoint, action, row, admission, authorization, pair, snapshot, verifier, now); err != nil {
			return nil, err
		}
		receipt := &agentv1.RecoveryCheckpointReceipt{CredentialId: row.CredentialID.String(), ActionId: row.ActionID.String(), Sequence: checkpoint.GetSequence(), CheckpointSha256: digest, StoredAt: timestamppb.New(now), RootVersion: snapshot.Root.GetVersion(), DelegationVersion: snapshot.Delegation.GetVersion()}
		envelope, err := s.Authority.Sign(ctx, receipt, s.Signing.StartKey)
		if err != nil {
			return nil, core.ExecutionError(err)
		}
		if _, err := verifier.VerifyRecoveryCheckpointReceipt(ctx, snapshot.Root, snapshot.Delegation, envelope, checkpoint, now); err != nil {
			return nil, core.ExecutionError(err)
		}
		document, err := proto.Marshal(checkpoint)
		if err != nil {
			return nil, core.MapErr(err)
		}
		if err := q.SetRecoveryCheckpoint(ctx, devicedb.SetRecoveryCheckpointParams{ActionID: row.ActionID, CheckpointDocument: document, CheckpointSha256: digest, CheckpointSequence: int64(checkpoint.GetSequence()), CheckpointReceiptEnvelope: envelope, JournalDocument: journalDocument, EffectCommitted: effect, StoredAt: core.Timestamptz(now)}); err != nil {
			return nil, core.MapErr(err)
		}
		if err := core.DispatchSystemAudit(ctx, q, nil, "device_action.recovery_checkpoint", row.ActionID, "phase", checkpoint.GetPhase().String()); err != nil {
			return nil, core.MapErr(err)
		}
		response = &recoveryv1.CheckpointRecoveryActionResponse{CheckpointSha256: digest, Sequence: checkpoint.GetSequence(), ReceiptEnvelope: envelope}
		if pair != nil {
			if err := s.Identity.LockAndConsumeApproval(ctx, tx, pair, s.recoveryApprovalScope); err != nil {
				return nil, core.ApprovalError(err)
			}
		}
		if authorization != nil {
			if err := s.Identity.LockAuthorization(ctx, tx, authorization, identity.PermissionExecuteDestructive); err != nil {
				return nil, core.ExecutionError(err)
			}
		}
	}
	if err := storeRecoveryRequest(ctx, q, admission, response); err != nil {
		return nil, core.MapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	return core.NoStore(response), nil
}

func validateRecoveryCheckpoint(ctx context.Context, checkpoint *agentv1.RecoveryCheckpoint, action devicedb.DeviceAction, row devicedb.DeviceActionRecovery, admission *recoveryAdmission, authorization *identity.Authorization, pair *identity.ApprovalConsumption, snapshot *executionauthority.Snapshot, verifier *trust.ExecutionVerifier, now time.Time) error {
	previous, err := recoveryCheckpoint(row)
	if err != nil {
		return core.MapErr(err)
	}
	if action.ClosedAt.Valid || int64(checkpoint.GetSequence()) != row.CheckpointSequence+1 || !bytes.Equal(checkpoint.GetPreviousSha256(), row.CheckpointSha256) || checkpoint.GetAt().AsTime().After(now.Add(time.Minute)) {
		return rpcreason.Error(connect.CodeAlreadyExists, "recovery_checkpoint_conflict")
	}
	switch checkpoint.GetPhase() {
	case agentv1.RecoveryPhase_RECOVERY_PHASE_BOOTED:
		if previous != nil || len(row.StartGrantEnvelope) > 0 || row.EffectCommittedAt.Valid || len(checkpoint.GetGrantSha256()) != 0 {
			return rpcreason.Error(connect.CodeFailedPrecondition, "recovery_boot_already_consumed")
		}
	case agentv1.RecoveryPhase_RECOVERY_PHASE_EFFECT_COMMITTED:
		if pair == nil || authorization == nil || previous.GetPhase() != agentv1.RecoveryPhase_RECOVERY_PHASE_BOOTED || row.EffectCommittedAt.Valid || len(row.StartGrantEnvelope) == 0 {
			return rpcreason.Error(connect.CodeFailedPrecondition, "recovery_effect_already_consumed")
		}
		challenge := new(agentv1.DeviceActionChallenge)
		if proto.Unmarshal(row.ChallengeDocument, challenge) != nil {
			return core.MapErr(core.ErrInternalState)
		}
		grantDigest := sha256.Sum256(row.StartGrantEnvelope)
		if !bytes.Equal(grantDigest[:], checkpoint.GetGrantSha256()) || challenge.GetBootId() != checkpoint.GetBootId() || challenge.GetExecutorIncarnation() != checkpoint.GetExecutorIncarnation() || previous.GetBootId() != checkpoint.GetBootId() || previous.GetExecutorIncarnation() != checkpoint.GetExecutorIncarnation() {
			return rpcreason.Error(connect.CodePermissionDenied, "recovery_effect_binding_rejected")
		}
		// New effect authority is evaluated on server time, not the request's clock.
		if _, err := verifier.VerifyRecoveryStart(ctx, snapshot.Root, snapshot.Delegation, row.StartGrantEnvelope, admission.credential.GetHandoff().GetIntent(), challenge, admission.credential, now); err != nil {
			return core.ExecutionError(err)
		}
	case agentv1.RecoveryPhase_RECOVERY_PHASE_TERMINAL:
		if previous == nil || previous.GetPhase() == agentv1.RecoveryPhase_RECOVERY_PHASE_TERMINAL {
			return rpcreason.Error(connect.CodeAlreadyExists, "recovery_terminal_conflict")
		}
		if len(row.StartGrantEnvelope) > 0 {
			grantDigest := sha256.Sum256(row.StartGrantEnvelope)
			if !bytes.Equal(grantDigest[:], checkpoint.GetGrantSha256()) {
				return rpcreason.Error(connect.CodePermissionDenied, "recovery_terminal_grant_rejected")
			}
		} else if len(checkpoint.GetGrantSha256()) != 0 {
			return rpcreason.Error(connect.CodePermissionDenied, "recovery_terminal_grant_rejected")
		}
	default:
		return core.Invalid("invalid_recovery_checkpoint")
	}
	return nil
}

func (s *Service) ReportRecoveryResult(ctx context.Context, req *connect.Request[recoveryv1.ReportRecoveryResultRequest]) (*connect.Response[recoveryv1.ReportRecoveryResultResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_recovery_result")
	}
	admission, err := s.authenticateRecovery(ctx, req.Msg.GetCredentialEnvelope(), req.Msg.GetRequestProof(), agentv1.RecoveryOperation_RECOVERY_OPERATION_REPORT_RESULT, RecoveryResultPayload(req.Msg))
	if err != nil {
		return nil, err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := devicedb.New(tx)
	action, row, now, err := lockRecovery(ctx, q, admission, true)
	if err != nil {
		return nil, core.MapErr(err)
	}
	response := &recoveryv1.ReportRecoveryResultResponse{}
	replay, err := recoveryRequestReplay(ctx, q, admission, response)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if replay {
		if err := tx.Commit(ctx); err != nil {
			return nil, core.MapErr(err)
		}
		return core.NoStore(response), nil
	}
	status := req.Msg.GetStatus()
	intent := admission.credential.GetHandoff().GetIntent()
	digest := sha256.Sum256(action.IntentEnvelope)
	if status.GetActionId() != action.ID.String() || !bytes.Equal(status.GetIntentSha256(), digest[:]) || status.GetVolatileResult() {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "recovery_result_binding_rejected")
	}
	if len(row.ResultNonce) != 32 || !bytes.Equal(row.ResultNonce, req.Msg.GetResultNonce()) || !row.NonceExpiresAt.Valid || !now.Before(row.NonceExpiresAt.Time) {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "recovery_result_nonce_rejected")
	}
	checkpoint, err := recoveryCheckpoint(row)
	if err != nil {
		return nil, core.MapErr(err)
	}
	succeeded := status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED
	unknown := status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN
	if !ActionTerminal(status.GetState()) && !unknown {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "recovery_terminal_result_required")
	}
	if action.ClosedAt.Valid {
		return nil, rpcreason.Error(connect.CodeAlreadyExists, "recovery_result_closed")
	}
	if succeeded && (!row.EffectCommittedAt.Valid || checkpoint.GetPhase() != agentv1.RecoveryPhase_RECOVERY_PHASE_TERMINAL || status.GetStartedAt() == nil || !status.GetVerification().GetVerified() || !proto.Equal(status.GetVerification().GetAfter().GetTarget(), intent.GetSpec().GetSanitize().GetTarget()) || status.GetVerification().GetAfter().GetEncrypted()) {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "recovery_effect_proof_required")
	}
	if !succeeded && !unknown && checkpoint.GetPhase() != agentv1.RecoveryPhase_RECOVERY_PHASE_TERMINAL {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "recovery_terminal_checkpoint_required")
	}
	if checkpoint.GetPhase() == agentv1.RecoveryPhase_RECOVERY_PHASE_TERMINAL && !unknown {
		journal, err := recoveryJournal(row)
		if err != nil {
			return nil, core.MapErr(err)
		}
		before := journal.GetHandoff().GetChallenge().GetNativePlan().GetBefore()
		if journal.GetChallenge() != nil {
			before = journal.GetChallenge().GetNativePlan().GetBefore()
		}
		if !proto.Equal(before, status.GetBefore()) {
			return nil, rpcreason.Error(connect.CodePermissionDenied, "recovery_terminal_observation_rejected")
		}
		if journal.GetState() != status.GetState() || journal.GetFailure() != status.GetFailure() || !proto.Equal(journal.GetVerification(), status.GetVerification()) || !proto.Equal(journal.GetStartedAt(), status.GetStartedAt()) || !proto.Equal(journal.GetCompletedAt(), status.GetCompletedAt()) || !proto.Equal(journal.GetAcceptedAt(), status.GetAcceptedAt()) {
			return nil, rpcreason.Error(connect.CodePermissionDenied, "recovery_terminal_snapshot_rejected")
		}
	}
	// If a previous process consumed an effect but only a restarted key holder is
	// available, lack of positive verification remains durable UNKNOWN.
	if row.EffectCommittedAt.Valid && !succeeded && status.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_FAILED && !unknown {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "recovery_effect_outcome_unknown")
	}
	document, err := proto.Marshal(status)
	if err != nil {
		return nil, core.MapErr(err)
	}
	requestID, _ := uuid.Parse(admission.proof.GetRequestId())
	if err := q.SetRecoveryResult(ctx, devicedb.SetRecoveryResultParams{ActionID: row.ActionID, ResultRequestID: &requestID, ResultProof: req.Msg.GetRequestProof(), ResultDocument: document}); err != nil {
		return nil, core.MapErr(err)
	}
	revision := action.ActionRevision
	if !revision.Valid || revision.Int == nil || !revision.Int.IsUint64() || revision.Int.Uint64() == ^uint64(0) {
		return nil, core.MapErr(core.ErrInternalState)
	}
	next := new(big.Int).Add(revision.Int, big.NewInt(1))
	if err := q.SetDeviceActionResult(ctx, devicedb.SetDeviceActionResultParams{ID: row.ActionID, ActionRevision: pgtype.Numeric{Int: next, Valid: true}, AttestationEnvelope: req.Msg.GetRequestProof(), AttestationCertificate: []byte{}, StatusDocument: document, ReceivedAt: core.Timestamptz(now), OutcomeUnknown: unknown}); err != nil {
		return nil, core.MapErr(err)
	}
	if !unknown {
		if err := q.CloseDeviceAction(ctx, devicedb.CloseDeviceActionParams{ID: row.ActionID, ClosedAt: core.Timestamptz(now), ClosedReason: "recovery_result"}); err != nil {
			return nil, core.MapErr(err)
		}
	}
	if err := core.DispatchSystemAudit(ctx, q, nil, "device_action.recovery_result", row.ActionID, "proof", "verified_action_scoped_proof"); err != nil {
		return nil, core.MapErr(err)
	}
	response.Closed = !unknown
	if err := storeRecoveryRequest(ctx, q, admission, response); err != nil {
		return nil, core.MapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	return core.NoStore(response), nil
}
