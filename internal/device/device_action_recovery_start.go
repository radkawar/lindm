package device

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	recoveryv1 "lindm/gen/lindm/recovery/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/trust"
)

func (s *Service) AcquireRecoveryWork(ctx context.Context, req *connect.Request[recoveryv1.AcquireRecoveryWorkRequest]) (*connect.Response[recoveryv1.AcquireRecoveryWorkResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_recovery_work")
	}
	admission, err := s.authenticateRecovery(ctx, req.Msg.GetCredentialEnvelope(), req.Msg.GetRequestProof(), agentv1.RecoveryOperation_RECOVERY_OPERATION_ACQUIRE_WORK, recoveryAcquirePayload(req.Msg))
	if err != nil {
		return nil, err
	}
	if s.execution == nil {
		return nil, rpcError(connect.CodeFailedPrecondition, "execution_authority_unconfigured")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	root := new(agentv1.ExecutionRoot)
	if protojson.Unmarshal(admission.row.RootJson, root) != nil {
		return nil, mapErr(errInternalState)
	}
	rootDigest, err := trust.ExecutionRootDigest(root)
	if err != nil {
		return nil, mapErr(err)
	}
	delegationDigest := sha256.Sum256(admission.row.DelegationEnvelope)
	_, update, err := s.execution.ForDevice(ctx, tx, admission.credential.GetRootVersion(), admission.credential.GetDelegationVersion(), admission.credential.GetHandoff().GetIntent().GetRecoveryEpoch(), rootDigest[:], delegationDigest[:])
	if err != nil {
		return nil, executionError(err)
	}
	q := devicedb.New(tx)
	action, row, now, err := lockRecovery(ctx, q, admission, true)
	if err != nil {
		return nil, mapErr(err)
	}
	response := &recoveryv1.AcquireRecoveryWorkResponse{}
	replay, err := recoveryRequestReplay(ctx, q, admission, response)
	if err != nil {
		return nil, mapErr(err)
	}
	if !replay {
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return nil, mapErr(err)
		}
		if err := q.SetRecoveryNonce(ctx, devicedb.SetRecoveryNonceParams{ActionID: row.ActionID, ResultNonce: nonce, NonceExpiresAt: timestamptz(now.Add(time.Minute))}); err != nil {
			return nil, mapErr(err)
		}
		checkpoint, err := recoveryCheckpoint(row)
		if err != nil {
			return nil, mapErr(err)
		}
		journal, err := recoveryJournal(row)
		if err != nil {
			return nil, mapErr(err)
		}
		response = &recoveryv1.AcquireRecoveryWorkResponse{IntentEnvelope: action.IntentEnvelope, ResultNonce: nonce, StartGrantEnvelope: row.StartGrantEnvelope, Checkpoint: checkpoint, TrustUpdate: update, Closed: action.ClosedAt.Valid, Journal: journal}
		if err := storeRecoveryRequest(ctx, q, admission, response); err != nil {
			return nil, mapErr(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return noStore(response), nil
}

func (s *Service) AuthorizeRecoveryStart(ctx context.Context, req *connect.Request[recoveryv1.AuthorizeRecoveryStartRequest]) (*connect.Response[recoveryv1.AuthorizeRecoveryStartResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_recovery_start")
	}
	if s.signing == nil || s.execution == nil || s.identity == nil {
		return nil, rpcError(connect.CodeFailedPrecondition, "execution_signing_unconfigured")
	}
	admission, err := s.authenticateRecovery(ctx, req.Msg.GetCredentialEnvelope(), req.Msg.GetRequestProof(), agentv1.RecoveryOperation_RECOVERY_OPERATION_AUTHORIZE_START, recoveryStartPayload(req.Msg))
	if err != nil {
		return nil, err
	}
	challenge := req.Msg.GetChallenge()
	handoff := admission.credential.GetHandoff()
	if challenge.GetBootId() != admission.proof.GetBootId() || challenge.GetExecutorIncarnation() != admission.proof.GetExecutorIncarnation() || !bytes.Equal(req.Msg.GetRecoveryImageSha256(), handoff.GetRecoveryImageSha256()) {
		return nil, rpcError(connect.CodePermissionDenied, "recovery_boot_binding_rejected")
	}
	var authorization *identity.Authorization
	var pair *identity.ApprovalConsumption
	if len(admission.row.StartGrantEnvelope) == 0 {
		authorization, pair, err = s.recoveryApproval(ctx, admission.action)
		if err != nil {
			return nil, err
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if pair != nil {
		if err := s.identity.LockAndConsumeApproval(ctx, tx, pair, s.recoveryApprovalScope); err != nil {
			return nil, approvalError(err)
		}
	}
	snapshot, verifier, err := s.execution.CurrentInTransaction(ctx, tx)
	if err != nil {
		return nil, executionError(err)
	}
	q := devicedb.New(tx)
	action, row, now, err := lockRecovery(ctx, q, admission, false)
	if err != nil {
		return nil, mapErr(err)
	}
	if action.ClosedAt.Valid || row.EffectCommittedAt.Valid {
		return nil, rpcError(connect.CodeFailedPrecondition, "recovery_effect_already_consumed")
	}
	response := &recoveryv1.AuthorizeRecoveryStartResponse{}
	replay, err := recoveryRequestReplay(ctx, q, admission, response)
	if err != nil {
		return nil, mapErr(err)
	}
	if replay {
		if err := tx.Commit(ctx); err != nil {
			return nil, mapErr(err)
		}
		return noStore(response), nil
	}
	challengeDocument, err := proto.Marshal(challenge)
	if err != nil {
		return nil, mapErr(err)
	}
	if len(row.StartGrantEnvelope) > 0 {
		if !bytes.Equal(row.ChallengeDocument, challengeDocument) {
			return nil, rpcError(connect.CodeAlreadyExists, "recovery_start_conflict")
		}
		response.StartGrantEnvelope = row.StartGrantEnvelope
	} else {
		checkpoint, err := recoveryCheckpoint(row)
		if err != nil {
			return nil, mapErr(err)
		}
		if checkpoint.GetPhase() != agentv1.RecoveryPhase_RECOVERY_PHASE_BOOTED || checkpoint.GetBootId() != challenge.GetBootId() || checkpoint.GetExecutorIncarnation() != challenge.GetExecutorIncarnation() {
			return nil, rpcError(connect.CodeFailedPrecondition, "recovery_boot_checkpoint_required")
		}
		if pair == nil || authorization == nil || !now.Before(action.ExpiresAt.Time) {
			return nil, rpcError(connect.CodePermissionDenied, "recovery_authority_expired")
		}
		if err := requireActionRestriction(ctx, q, action.DeviceID, handoff.GetIntent().GetSpec()); err != nil {
			return nil, mapErr(err)
		}
		if _, err := verifier.VerifyDeviceActionRecoveryCredential(ctx, snapshot.Root, snapshot.Delegation, row.CredentialEnvelope, handoff, now); err != nil {
			return nil, executionError(err)
		}
		if _, err := verifier.VerifyDeviceActionIntent(ctx, snapshot.Root, snapshot.Delegation, action.IntentEnvelope, now); err != nil {
			return nil, executionError(err)
		}
		issued, expires := challenge.GetIssuedAt().AsTime(), challenge.GetExpiresAt().AsTime()
		if issued.After(now.Add(trust.MaxDeviceClockSkew)) || !now.Add(-trust.MaxDeviceClockSkew).Before(expires) {
			return nil, rpcError(connect.CodeFailedPrecondition, "device_clock_skew")
		}
		for _, limit := range []time.Time{issued.Add(30 * time.Second), issued.Add(authorization.ExpiresAt().Sub(now)), row.ExpiresAt.Time, action.ExpiresAt.Time, snapshot.Delegation.GetExpiresAt().AsTime()} {
			if limit.Before(expires) {
				expires = limit
			}
		}
		if !expires.After(issued) {
			return nil, rpcError(connect.CodePermissionDenied, "recovery_start_window_empty")
		}
		grant := &agentv1.DeviceActionStartGrant{Challenge: challenge, ActorId: action.ActorID.String(), AuthorizationVersion: authorization.Version(), RootVersion: snapshot.Root.GetVersion(), DelegationVersion: snapshot.Delegation.GetVersion(), NotBefore: challenge.GetIssuedAt(), ExpiresAt: timestamppb.New(expires), Approvals: recoveryHumanApprovals(handoff.GetIntent(), pair)}
		envelope, err := s.authority.Sign(ctx, grant, s.signing.StartKey)
		if err != nil {
			return nil, executionError(err)
		}
		if _, err := verifier.VerifyRecoveryStart(ctx, snapshot.Root, snapshot.Delegation, envelope, handoff.GetIntent(), challenge, admission.credential, issued); err != nil {
			return nil, executionError(err)
		}
		if err := q.SetRecoveryStartGrant(ctx, devicedb.SetRecoveryStartGrantParams{ActionID: row.ActionID, ChallengeDocument: challengeDocument, StartGrantEnvelope: envelope, StartAuthorizedAt: timestamptz(now)}); err != nil {
			return nil, mapErr(err)
		}
		if err := q.SetDeviceActionGrant(ctx, devicedb.SetDeviceActionGrantParams{ID: row.ActionID, ChallengeProof: req.Msg.GetRequestProof(), ChallengeDocument: challengeDocument, StartGrantEnvelope: envelope, StartAuthorizedAt: timestamptz(now)}); err != nil {
			return nil, mapErr(err)
		}
		if err := dispatchAudit(ctx, q, &action.ActorID, "device_action.recovery_start", action.ID, "fresh_two_human_recovery_authority"); err != nil {
			return nil, mapErr(err)
		}
		if err := s.identity.LockAndConsumeApproval(ctx, tx, pair, s.recoveryApprovalScope); err != nil {
			return nil, approvalError(err)
		}
		if err := s.identity.LockAuthorization(ctx, tx, authorization, identity.PermissionExecuteDestructive); err != nil {
			return nil, executionError(err)
		}
		response.StartGrantEnvelope = envelope
	}
	if err := storeRecoveryRequest(ctx, q, admission, response); err != nil {
		return nil, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return noStore(response), nil
}
