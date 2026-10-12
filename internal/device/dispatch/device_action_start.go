package dispatch

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"time"

	"lindm/internal/auditkind"
	"lindm/internal/device/core"

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
)

func (s *Service) GetDeviceActionWork(ctx context.Context, req *connect.Request[devicev1.GetDeviceActionWorkRequest]) (*connect.Response[devicev1.GetDeviceActionWorkResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	principal, ok := core.DevicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_device_action_work")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := devicedb.New(tx)
	device, err := s.LockAuthority(ctx, q, principal)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if uint64(device.Generation.SessionEpoch) != req.Msg.GetSessionEpoch() {
		return nil, core.MapErr(core.ErrSessionFenced)
	}
	now, err := core.DispatchClock(ctx, q)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if !core.EnrollmentIssuanceResumable(device.Certificate, now) {
		return nil, core.MapErr(core.ErrCertificateRejected)
	}
	action, err := q.GetOpenDeviceAction(ctx, principal.DeviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		// Policy minting re-authorizes its actor before locking this device, so
		// end this transaction first; a committed action is then served below.
		if err := tx.Rollback(ctx); err != nil {
			return nil, core.MapErr(err)
		}
		minted, err := s.secrets.MintLocalAdminRotation(ctx, principal, req.Msg.GetSessionEpoch())
		if err != nil {
			return nil, err
		}
		if minted {
			return s.GetDeviceActionWork(ctx, req)
		}
		return core.NoStore(&devicev1.GetDeviceActionWorkResponse{}), nil
	}
	if err != nil {
		return nil, core.MapErr(err)
	}
	if action.GenerationID != principal.GenerationID {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "device_action_generation_pending")
	}
	if len(action.StartGrantEnvelope) == 0 && !action.OutcomeUnknown {
		if err := s.RequireReleaseCompatibility(ctx, q, principal.GenerationID, req.Msg.GetSessionEpoch()); err != nil {
			return nil, core.MapErr(err)
		}
	}
	if !action.OutcomeUnknown && len(action.StartGrantEnvelope) == 0 && !now.Before(action.ExpiresAt.Time) {
		if err := q.CloseDeviceAction(ctx, devicedb.CloseDeviceActionParams{ID: action.ID, ClosedAt: core.Timestamptz(now), ClosedReason: "expired_unstarted"}); err != nil {
			return nil, core.MapErr(err)
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, core.MapErr(err)
		}
		return core.NoStore(&devicev1.GetDeviceActionWorkResponse{}), nil
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, core.MapErr(err)
	}
	expires := now.Add(time.Minute)
	if err := q.SetDeviceActionNonce(ctx, devicedb.SetDeviceActionNonceParams{ID: action.ID, ResultNonce: nonce[:], NonceExpiresAt: core.Timestamptz(expires)}); err != nil {
		return nil, core.MapErr(err)
	}
	work := &devicev1.DeviceActionWork{ActionId: action.ID.String(), IntentEnvelope: action.IntentEnvelope, StartGrantEnvelope: action.StartGrantEnvelope, ResultNonce: nonce[:], ResultNonceExpiresAt: timestamppb.New(expires), EscrowReceiptEnvelope: action.EscrowReceiptEnvelope, InventoryReceiptEnvelope: action.InventoryReceiptEnvelope}
	intent, err := core.ActionIntent(action)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if intent.GetSpec().GetSanitize().GetRecovery() != nil {
		work.RecoveryHandoff = true
		recovery, recoveryErr := q.GetDeviceActionRecovery(ctx, action.ID)
		if recoveryErr == nil {
			work.RecoveryCredentialEnvelope = recovery.CredentialEnvelope
			work.RecoveryBootGrantEnvelope = recovery.BootGrantEnvelope
		} else if !errors.Is(recoveryErr, pgx.ErrNoRows) {
			return nil, core.MapErr(recoveryErr)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	if len(work.EscrowReceiptEnvelope) == 0 {
		work.EscrowReceiptEnvelope, err = s.secrets.DeviceActionReceipt(ctx, principal, req.Msg.GetSessionEpoch(), action.ID)
		if err != nil {
			return nil, err
		}
	}
	return core.NoStore(&devicev1.GetDeviceActionWorkResponse{Work: work}), nil
}

var deviceActionReasons = signedReasons{
	invalidStart: "invalid_device_action_start", invalidResult: "invalid_device_action_result", resultAudit: auditkind.DeviceActionResult,
	binding:          reason{connect.CodePermissionDenied, "device_action_binding_rejected"},
	challenge:        reason{connect.CodePermissionDenied, "device_action_challenge_rejected"},
	challengeBinding: reason{connect.CodePermissionDenied, "device_action_challenge_binding_rejected"},
	startConflict:    reason{connect.CodeAlreadyExists, "device_action_start_conflict"},
	startWindow:      reason{connect.CodePermissionDenied, "device_action_start_window_empty"},
	nonce:            reason{connect.CodePermissionDenied, "device_action_result_nonce_rejected"},
	attestation:      reason{connect.CodePermissionDenied, "device_action_result_rejected"},
	resultConflict:   reason{connect.CodeAlreadyExists, "device_action_result_conflict"},
	ungranted:        reason{connect.CodePermissionDenied, "device_action_ungranted_result"},
}

func (s *Service) AuthorizeDeviceActionStart(ctx context.Context, req *connect.Request[devicev1.AuthorizeDeviceActionStartRequest]) (*connect.Response[devicev1.AuthorizeDeviceActionStartResponse], error) {
	envelope, err := authorizeSignedStart(ctx, s, core.Message(req), new(agentv1.DeviceActionChallenge), &deviceActionStart{})
	if err != nil {
		return nil, err
	}
	return core.NoStore(&devicev1.AuthorizeDeviceActionStartResponse{StartGrantEnvelope: envelope}), nil
}

// deviceActionStart is the device-action half of start authorization: the
// action permission, an exactly bound approval consumed at start, and the
// native preflight and restriction rules of the requested action.
type deviceActionStart struct {
	captured      devicedb.DeviceAction
	intent        *agentv1.DeviceActionIntent
	permission    identity.Permission
	authorization *identity.Authorization
	consumption   *identity.ApprovalConsumption
	action        devicedb.DeviceAction
}

var _ startKind[*agentv1.DeviceActionChallenge] = (*deviceActionStart)(nil)

func (*deviceActionStart) reasons() signedReasons { return deviceActionReasons }

func (k *deviceActionStart) capture(ctx context.Context, s *Service, id uuid.UUID) (signedRow, error) {
	var err error
	k.captured, err = devicedb.New(s.Pool).GetDeviceAction(ctx, id)
	return deviceActionRow(k.captured), err
}

func (k *deviceActionStart) decode() error {
	var err error
	if k.intent, err = core.ActionIntent(k.captured); err != nil {
		return core.MapErr(err)
	}
	if k.intent.GetSpec().GetSanitize().GetRecovery() != nil {
		return rpcreason.Error(connect.CodePermissionDenied, "recovery_handoff_required")
	}
	k.permission = DeviceActionPermission(k.intent.GetSpec())
	return nil
}

func (k *deviceActionStart) binds(challenge *agentv1.DeviceActionChallenge, digest []byte) bool {
	intent := k.intent
	return challenge.GetDeploymentId() == intent.GetDeploymentId() && challenge.GetDeviceId() == intent.GetDeviceId() && challenge.GetEnrollmentGeneration() == intent.GetEnrollmentGeneration() && challenge.GetActionId() == intent.GetActionId() && challenge.GetActionSequence() == intent.GetActionSequence() && challenge.GetRecoveryEpoch() == intent.GetRecoveryEpoch() && bytes.Equal(challenge.GetIntentSha256(), digest) && bytes.Equal(challenge.GetSpecSha256(), intent.GetSpecSha256())
}

func (k *deviceActionStart) authorize(ctx context.Context, s *Service) error {
	var err error
	if k.authorization, err = s.Identity.AuthorizeFresh(ctx, k.captured.ActorID, k.permission); err != nil {
		return core.ExecutionError(err)
	}
	if k.authorization.Version() != k.intent.GetAuthorizationVersion() {
		return core.ExecutionError(identity.ErrAuthorizationChanged)
	}
	if k.captured.ApprovalID == nil {
		if DestructiveDeviceAction(k.intent.GetSpec()) || k.authorization.ApprovalRequired(k.permission) && !policyMintedAction(k.intent.GetSpec()) {
			return core.ApprovalError(identity.ErrApprovalRequired)
		}
		return nil
	}
	request, err := actionRequest(k.captured)
	if err != nil {
		return core.MapErr(err)
	}
	if k.consumption, err = s.Identity.PrepareApprovalConsumption(ctx, k.captured.ActorID, *k.captured.ApprovalID, request); err != nil {
		return core.ApprovalError(err)
	}
	return nil
}

// executionApprovalScope acquires execution authority inside the approval
// pair's principal locks, before it locks devices, matching ordinary dispatch.
func (s *Service) executionApprovalScope(ctx context.Context, tx pgx.Tx, actor identity.Principal, permission identity.Permission, target uuid.UUID) error {
	if _, _, err := s.Execution.CurrentInTransaction(ctx, tx); err != nil {
		return err
	}
	return s.ApprovalScope(ctx, tx, actor, permission, target)
}

// lock consumes the approval pair, relocks fresh authority, then execution authority.
func (k *deviceActionStart) lock(ctx context.Context, s *Service, st *startState[*agentv1.DeviceActionChallenge]) error {
	if k.consumption != nil {
		if err := s.Identity.LockAndConsumeApproval(ctx, st.tx, k.consumption, s.executionApprovalScope); err != nil {
			return core.ApprovalError(err)
		}
	}
	if k.authorization != nil {
		if err := s.Identity.LockAuthorization(ctx, st.tx, k.authorization, k.permission); err != nil {
			return core.ExecutionError(err)
		}
	}
	var err error
	if st.snapshot, st.verifier, err = s.Execution.CurrentInTransaction(ctx, st.tx); err != nil {
		return core.ExecutionError(err)
	}
	return nil
}

func (k *deviceActionStart) lockAction(ctx context.Context, _ *Service, st *startState[*agentv1.DeviceActionChallenge]) (signedRow, error) {
	var err error
	if k.action, err = st.q.LockDeviceAction(ctx, st.id); err != nil {
		return signedRow{}, core.MapErr(err)
	}
	return deviceActionRow(k.action), nil
}

func (k *deviceActionStart) admit(ctx context.Context, s *Service, st *startState[*agentv1.DeviceActionChallenge]) (bool, error) {
	spec, device, q := k.intent.GetSpec(), st.principal.DeviceID, st.q
	if k.action.ClosedAt.Valid || !st.now.Before(k.action.ExpiresAt.Time) {
		return false, rpcreason.Error(connect.CodePermissionDenied, "device_action_expired")
	}
	if err := core.RequireDeviceScope(ctx, q, k.authorization.Principal(), k.permission, device); err != nil {
		return false, core.MapErr(err)
	}
	if spec.GetRefreshInventory() != nil {
		if err := core.RequireDeviceScope(ctx, q, k.authorization.Principal(), identity.PermissionReadFleet, device); err != nil {
			return false, core.MapErr(err)
		}
	}
	if err := requireActionInventory(ctx, q, st.principal.GenerationID, spec, st.now); err != nil {
		return false, core.MapErr(err)
	}
	if err := requireLiveRootEscrow(ctx, q, device, spec); err != nil {
		return false, core.MapErr(err)
	}
	if err := core.RequireActionRestriction(ctx, q, device, spec); err != nil {
		return false, core.MapErr(err)
	}
	if err := requireLockActionRestriction(ctx, q, device, st.principal.GenerationID, spec); err != nil {
		return false, core.MapErr(err)
	}
	if !core.DeviceActionSignerDelegated(st.snapshot.Delegation, s.Signing.StartKey, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, k.action.Capability) {
		return false, core.DeviceActionCapabilityError(k.action.Capability, "start")
	}
	plan := st.challenge.GetNativePlan()
	planDigest, err := core.ActionDigest(plan)
	if err != nil {
		return false, core.MapErr(err)
	}
	if plan == nil || !proto.Equal(plan.GetSpec(), spec) || !bytes.Equal(planDigest, st.challenge.GetNativePlanSha256()) || !plan.GetBefore().GetSupported() {
		return false, rpcreason.Error(connect.CodePermissionDenied, "device_action_preflight_rejected")
	}
	if DestructiveDeviceAction(spec) && !core.LiveRootAction(spec) && (!plan.GetBefore().GetRecoveryEnvironment() || !plan.GetBefore().GetOffTargetJournal()) {
		return false, rpcreason.Error(connect.CodePermissionDenied, "device_action_recovery_environment_required")
	}
	return false, validateLiveRootPlan(spec, plan)
}

func (k *deviceActionStart) verifyIntent(ctx context.Context, st *startState[*agentv1.DeviceActionChallenge]) error {
	if _, err := st.verifier.VerifyDeviceActionIntent(ctx, st.snapshot.Root, st.snapshot.Delegation, k.action.IntentEnvelope, st.now); err != nil {
		return core.ExecutionError(err)
	}
	return nil
}

func (k *deviceActionStart) limits(st *startState[*agentv1.DeviceActionChallenge], issued time.Time) []time.Time {
	return []time.Time{issued.Add(k.authorization.ExpiresAt().Sub(st.now)), k.intent.GetExpiresAt().AsTime()}
}

func (k *deviceActionStart) grant(st *startState[*agentv1.DeviceActionChallenge], expires time.Time) proto.Message {
	intent := k.intent
	grant := &agentv1.DeviceActionStartGrant{Challenge: st.challenge, ActorId: intent.GetActorId(), AuthorizationVersion: k.authorization.Version(), RootVersion: st.snapshot.Root.GetVersion(), DelegationVersion: st.snapshot.Delegation.GetVersion(), NotBefore: st.challenge.GetIssuedAt(), ExpiresAt: timestamppb.New(expires)}
	if k.consumption != nil {
		binding := &agentv1.DeviceActionApprovalBinding{DeviceId: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), SpecSha256: intent.GetSpecSha256(), ExpiresAt: intent.GetExpiresAt()}
		for _, human := range []*identity.Authorization{k.consumption.Requester(), k.consumption.Approver()} {
			grant.Approvals = append(grant.Approvals, &agentv1.DeviceActionHumanApproval{ActorId: human.ActorID().String(), AuthorizationVersion: human.Version(), Binding: binding})
		}
	}
	return grant
}

func (*deviceActionStart) signFailed(err error) error { return core.ExecutionError(err) }

func (k *deviceActionStart) verifyGrant(ctx context.Context, st *startState[*agentv1.DeviceActionChallenge], envelope []byte) error {
	if _, err := st.verifier.VerifyDeviceActionStart(ctx, st.snapshot.Root, st.snapshot.Delegation, envelope, k.intent, st.challenge, st.challenge.GetIssuedAt().AsTime()); err != nil {
		return core.ExecutionError(err)
	}
	return nil
}

func (k *deviceActionStart) persist(ctx context.Context, s *Service, st *startState[*agentv1.DeviceActionChallenge], envelope []byte) error {
	document, err := proto.Marshal(st.challenge)
	if err != nil {
		return core.MapErr(err)
	}
	if err := st.q.SetDeviceActionGrant(ctx, devicedb.SetDeviceActionGrantParams{ID: st.id, ChallengeProof: st.proof, ChallengeDocument: document, StartGrantEnvelope: envelope, StartAuthorizedAt: core.Timestamptz(st.now)}); err != nil {
		return core.MapErr(err)
	}
	// Quarantine/lock restrictions are fail-closed from grant issuance; release only
	// clears them after a device-signed successful native result.
	spec := k.intent.GetSpec()
	if spec.GetLockSessions() != nil || spec.GetQuarantine() != nil {
		if err := st.q.SetDeviceActionRestriction(ctx, devicedb.SetDeviceActionRestrictionParams{DeviceID: st.principal.DeviceID, ActionID: st.id, SessionsLocked: spec.GetLockSessions() != nil, Quarantined: spec.GetQuarantine() != nil, SetSessions: spec.GetLockSessions() != nil, SetQuarantine: spec.GetQuarantine() != nil, UpdatedAt: core.Timestamptz(st.now)}); err != nil {
			return core.MapErr(err)
		}
	}
	if err := core.DispatchSystemAudit(ctx, st.q, &k.action.ActorID, auditkind.DeviceActionStart, st.id, "authority", "fresh_authorization"); err != nil {
		return core.MapErr(err)
	}
	if k.consumption != nil {
		if err := s.Identity.LockAndConsumeApproval(ctx, st.tx, k.consumption, s.executionApprovalScope); err != nil {
			return core.ApprovalError(err)
		}
	}
	if err := s.Identity.LockAuthorization(ctx, st.tx, k.authorization, k.permission); err != nil {
		return core.ExecutionError(err)
	}
	return nil
}

func deviceActionRow(action devicedb.DeviceAction) signedRow {
	return signedRow{id: action.ID, deviceID: action.DeviceID, generationID: action.GenerationID, intentEnvelope: action.IntentEnvelope, challengeProof: action.ChallengeProof, startGrant: action.StartGrantEnvelope, resultNonce: action.ResultNonce, nonceExpiresAt: action.NonceExpiresAt, revision: action.ActionRevision, attestation: action.AttestationEnvelope, attestationCertificate: action.AttestationCertificate, closed: action.ClosedAt.Valid}
}
