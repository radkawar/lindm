package device

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
	"lindm/internal/trust"
)

func (s *Service) GetDeviceActionWork(ctx context.Context, req *connect.Request[devicev1.GetDeviceActionWorkRequest]) (*connect.Response[devicev1.GetDeviceActionWorkResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	principal, ok := devicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_device_action_work")
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
	now, err := dispatchClock(ctx, q)
	if err != nil {
		return nil, mapErr(err)
	}
	if !enrollmentIssuanceResumable(device.certificate, now) {
		return nil, mapErr(errCertificateRejected)
	}
	action, err := q.GetOpenDeviceAction(ctx, principal.DeviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		// Policy minting re-authorizes its actor before locking this device, so
		// end this transaction first; a committed action is then served below.
		if err := tx.Rollback(ctx); err != nil {
			return nil, mapErr(err)
		}
		minted, err := s.mintLocalAdminRotation(ctx, principal, req.Msg.GetSessionEpoch())
		if err != nil {
			return nil, err
		}
		if minted {
			return s.GetDeviceActionWork(ctx, req)
		}
		return noStore(&devicev1.GetDeviceActionWorkResponse{}), nil
	}
	if err != nil {
		return nil, mapErr(err)
	}
	if action.GenerationID != principal.GenerationID {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "device_action_generation_pending")
	}
	if len(action.StartGrantEnvelope) == 0 && !action.OutcomeUnknown {
		if err := s.requireReleaseCompatibility(ctx, q, principal.GenerationID, req.Msg.GetSessionEpoch()); err != nil {
			return nil, mapErr(err)
		}
	}
	if !action.OutcomeUnknown && len(action.StartGrantEnvelope) == 0 && !now.Before(action.ExpiresAt.Time) {
		if err := q.CloseDeviceAction(ctx, devicedb.CloseDeviceActionParams{ID: action.ID, ClosedAt: timestamptz(now), ClosedReason: "expired_unstarted"}); err != nil {
			return nil, mapErr(err)
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, mapErr(err)
		}
		return noStore(&devicev1.GetDeviceActionWorkResponse{}), nil
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, mapErr(err)
	}
	expires := now.Add(time.Minute)
	if err := q.SetDeviceActionNonce(ctx, devicedb.SetDeviceActionNonceParams{ID: action.ID, ResultNonce: nonce[:], NonceExpiresAt: timestamptz(expires)}); err != nil {
		return nil, mapErr(err)
	}
	work := &devicev1.DeviceActionWork{ActionId: action.ID.String(), IntentEnvelope: action.IntentEnvelope, StartGrantEnvelope: action.StartGrantEnvelope, ResultNonce: nonce[:], ResultNonceExpiresAt: timestamppb.New(expires), EscrowReceiptEnvelope: action.EscrowReceiptEnvelope, InventoryReceiptEnvelope: action.InventoryReceiptEnvelope}
	intent, err := actionIntent(action)
	if err != nil {
		return nil, mapErr(err)
	}
	if intent.GetSpec().GetSanitize().GetRecovery() != nil {
		work.RecoveryHandoff = true
		recovery, recoveryErr := q.GetDeviceActionRecovery(ctx, action.ID)
		if recoveryErr == nil {
			work.RecoveryCredentialEnvelope = recovery.CredentialEnvelope
			work.RecoveryBootGrantEnvelope = recovery.BootGrantEnvelope
		} else if !errors.Is(recoveryErr, pgx.ErrNoRows) {
			return nil, mapErr(recoveryErr)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	if len(work.EscrowReceiptEnvelope) == 0 {
		work.EscrowReceiptEnvelope, err = s.deviceActionReceipt(ctx, principal, req.Msg.GetSessionEpoch(), action.ID)
		if err != nil {
			return nil, err
		}
	}
	return noStore(&devicev1.GetDeviceActionWorkResponse{Work: work}), nil
}

func (s *Service) AuthorizeDeviceActionStart(ctx context.Context, req *connect.Request[devicev1.AuthorizeDeviceActionStartRequest]) (*connect.Response[devicev1.AuthorizeDeviceActionStartResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	principal, ok := devicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_device_action_start")
	}
	if s.identity == nil || s.signing == nil || s.execution == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "execution_signing_unconfigured")
	}
	id, _ := uuid.Parse(req.Msg.GetActionId())
	captured, err := devicedb.New(s.pool).GetDeviceAction(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	if captured.DeviceID != principal.DeviceID || captured.GenerationID != principal.GenerationID {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "device_action_binding_rejected")
	}
	intent, err := actionIntent(captured)
	if err != nil {
		return nil, mapErr(err)
	}
	if intent.GetSpec().GetSanitize().GetRecovery() != nil {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "recovery_handoff_required")
	}
	challenge := new(agentv1.DeviceActionChallenge)
	if err := s.authority.Verify(ctx, req.Msg.GetChallengeProof(), challenge, 1, principal.PublicKey); err != nil {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "device_action_challenge_rejected")
	}
	digest := sha256.Sum256(captured.IntentEnvelope)
	if challenge.GetDeploymentId() != intent.GetDeploymentId() || challenge.GetDeviceId() != intent.GetDeviceId() || challenge.GetEnrollmentGeneration() != intent.GetEnrollmentGeneration() || challenge.GetActionId() != intent.GetActionId() || challenge.GetActionSequence() != intent.GetActionSequence() || challenge.GetRecoveryEpoch() != intent.GetRecoveryEpoch() || !bytes.Equal(challenge.GetIntentSha256(), digest[:]) || !bytes.Equal(challenge.GetSpecSha256(), intent.GetSpecSha256()) {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "device_action_challenge_binding_rejected")
	}
	permission := deviceActionPermission(intent.GetSpec())
	var authorization *identity.Authorization
	var consumption *identity.ApprovalConsumption
	if len(captured.StartGrantEnvelope) == 0 {
		authorization, err = s.identity.AuthorizeFresh(ctx, captured.ActorID, permission)
		if err != nil {
			return nil, executionError(err)
		}
		if authorization.Version() != intent.GetAuthorizationVersion() {
			return nil, executionError(identity.ErrAuthorizationChanged)
		}
		if captured.ApprovalID != nil {
			request, err := actionRequest(captured)
			if err != nil {
				return nil, mapErr(err)
			}
			consumption, err = s.identity.PrepareApprovalConsumption(ctx, captured.ActorID, *captured.ApprovalID, request)
			if err != nil {
				return nil, approvalError(err)
			}
		} else if destructiveDeviceAction(intent.GetSpec()) || s.identity.ApprovalRequired(permission) && !policyMintedAction(intent.GetSpec()) {
			return nil, approvalError(identity.ErrApprovalRequired)
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// The approval pair locks principals before invoking scope. Acquire authority
	// inside that callback, before it locks devices, matching ordinary dispatch.
	approvalScope := func(ctx context.Context, tx pgx.Tx, actor identity.Principal, permission identity.Permission, target uuid.UUID) error {
		if _, _, err := s.execution.CurrentInTransaction(ctx, tx); err != nil {
			return err
		}
		return s.approvalScope(ctx, tx, actor, permission, target)
	}
	if consumption != nil {
		if err := s.identity.LockAndConsumeApproval(ctx, tx, consumption, approvalScope); err != nil {
			return nil, approvalError(err)
		}
	}
	if authorization != nil {
		if err := s.identity.LockAuthorization(ctx, tx, authorization, permission); err != nil {
			return nil, executionError(err)
		}
	}
	snapshot, verifier, err := s.execution.CurrentInTransaction(ctx, tx)
	if err != nil {
		return nil, executionError(err)
	}
	q := devicedb.New(tx)
	device, err := s.lockAuthority(ctx, q, principal)
	if err != nil {
		return nil, mapErr(err)
	}
	if uint64(device.generation.SessionEpoch) != req.Msg.GetSessionEpoch() {
		return nil, mapErr(errSessionFenced)
	}
	action, err := q.LockDeviceAction(ctx, id)
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
	if len(action.StartGrantEnvelope) > 0 {
		if !bytes.Equal(action.ChallengeProof, req.Msg.GetChallengeProof()) {
			return nil, rpcreason.Error(connect.CodeAlreadyExists, "device_action_start_conflict")
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, mapErr(err)
		}
		return noStore(&devicev1.AuthorizeDeviceActionStartResponse{StartGrantEnvelope: action.StartGrantEnvelope}), nil
	}
	if err := s.requireReleaseCompatibility(ctx, q, principal.GenerationID, req.Msg.GetSessionEpoch()); err != nil {
		return nil, mapErr(err)
	}
	if action.ClosedAt.Valid || !now.Before(action.ExpiresAt.Time) {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "device_action_expired")
	}
	if err := requireDeviceScope(ctx, q, authorization.Principal(), permission, principal.DeviceID); err != nil {
		return nil, mapErr(err)
	}
	if intent.GetSpec().GetRefreshInventory() != nil {
		if err := requireDeviceScope(ctx, q, authorization.Principal(), identity.PermissionReadFleet, principal.DeviceID); err != nil {
			return nil, mapErr(err)
		}
	}
	if err := requireActionInventory(ctx, q, principal.GenerationID, intent.GetSpec(), now); err != nil {
		return nil, mapErr(err)
	}
	if err := requireLiveRootEscrow(ctx, q, principal.DeviceID, intent.GetSpec()); err != nil {
		return nil, mapErr(err)
	}
	if err := requireActionRestriction(ctx, q, principal.DeviceID, intent.GetSpec()); err != nil {
		return nil, mapErr(err)
	}
	if err := requireLockActionRestriction(ctx, q, principal.DeviceID, principal.GenerationID, intent.GetSpec()); err != nil {
		return nil, mapErr(err)
	}
	if !deviceActionSignerDelegated(snapshot.Delegation, s.signing.StartKey, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, action.Capability) {
		return nil, deviceActionCapabilityError(action.Capability, "start")
	}
	plan := challenge.GetNativePlan()
	planDigest, err := actionDigest(plan)
	if err != nil {
		return nil, mapErr(err)
	}
	if plan == nil || !proto.Equal(plan.GetSpec(), intent.GetSpec()) || !bytes.Equal(planDigest, challenge.GetNativePlanSha256()) || !plan.GetBefore().GetSupported() {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "device_action_preflight_rejected")
	}
	if destructiveDeviceAction(intent.GetSpec()) && !liveRootAction(intent.GetSpec()) && (!plan.GetBefore().GetRecoveryEnvironment() || !plan.GetBefore().GetOffTargetJournal()) {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "device_action_recovery_environment_required")
	}
	if err := validateLiveRootPlan(intent.GetSpec(), plan); err != nil {
		return nil, err
	}
	issued := challenge.GetIssuedAt().AsTime()
	expires := challenge.GetExpiresAt().AsTime()
	if issued.After(now.Add(trust.MaxDeviceClockSkew)) || !now.Add(-trust.MaxDeviceClockSkew).Before(expires) {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "device_clock_skew")
	}
	if _, err := verifier.VerifyDeviceActionIntent(ctx, snapshot.Root, snapshot.Delegation, action.IntentEnvelope, now); err != nil {
		return nil, executionError(err)
	}
	for _, limit := range []time.Time{issued.Add(30 * time.Second), issued.Add(authorization.ExpiresAt().Sub(now)), intent.GetExpiresAt().AsTime(), snapshot.Delegation.GetExpiresAt().AsTime()} {
		if limit.Before(expires) {
			expires = limit
		}
	}
	if !expires.After(issued) {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "device_action_start_window_empty")
	}
	grant := &agentv1.DeviceActionStartGrant{Challenge: challenge, ActorId: intent.GetActorId(), AuthorizationVersion: authorization.Version(), RootVersion: snapshot.Root.GetVersion(), DelegationVersion: snapshot.Delegation.GetVersion(), NotBefore: challenge.GetIssuedAt(), ExpiresAt: timestamppb.New(expires)}
	if consumption != nil {
		binding := &agentv1.DeviceActionApprovalBinding{DeviceId: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), SpecSha256: intent.GetSpecSha256(), ExpiresAt: intent.GetExpiresAt()}
		for _, human := range []*identity.Authorization{consumption.Requester(), consumption.Approver()} {
			grant.Approvals = append(grant.Approvals, &agentv1.DeviceActionHumanApproval{ActorId: human.ActorID().String(), AuthorizationVersion: human.Version(), Binding: binding})
		}
	}
	envelope, err := s.authority.Sign(ctx, grant, s.signing.StartKey)
	if err != nil {
		return nil, executionError(err)
	}
	if _, err := verifier.VerifyDeviceActionStart(ctx, snapshot.Root, snapshot.Delegation, envelope, intent, challenge, issued); err != nil {
		return nil, executionError(err)
	}
	challengeDocument, err := proto.Marshal(challenge)
	if err != nil {
		return nil, mapErr(err)
	}
	if err := q.SetDeviceActionGrant(ctx, devicedb.SetDeviceActionGrantParams{ID: id, ChallengeProof: req.Msg.GetChallengeProof(), ChallengeDocument: challengeDocument, StartGrantEnvelope: envelope, StartAuthorizedAt: timestamptz(now)}); err != nil {
		return nil, mapErr(err)
	}
	// Quarantine/lock restrictions are fail-closed from grant issuance; release only
	// clears them after a device-signed successful native result.
	if intent.GetSpec().GetLockSessions() != nil || intent.GetSpec().GetQuarantine() != nil {
		if err := q.SetDeviceActionRestriction(ctx, devicedb.SetDeviceActionRestrictionParams{DeviceID: principal.DeviceID, ActionID: id, SessionsLocked: intent.GetSpec().GetLockSessions() != nil, Quarantined: intent.GetSpec().GetQuarantine() != nil, SetSessions: intent.GetSpec().GetLockSessions() != nil, SetQuarantine: intent.GetSpec().GetQuarantine() != nil, UpdatedAt: timestamptz(now)}); err != nil {
			return nil, mapErr(err)
		}
	}
	if err := dispatchSystemAudit(ctx, q, &action.ActorID, "device_action.start", id, "authority", "fresh_authorization"); err != nil {
		return nil, mapErr(err)
	}
	if consumption != nil {
		if err := s.identity.LockAndConsumeApproval(ctx, tx, consumption, approvalScope); err != nil {
			return nil, approvalError(err)
		}
	}
	if err := s.identity.LockAuthorization(ctx, tx, authorization, permission); err != nil {
		return nil, executionError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return noStore(&devicev1.AuthorizeDeviceActionStartResponse{StartGrantEnvelope: envelope}), nil
}
