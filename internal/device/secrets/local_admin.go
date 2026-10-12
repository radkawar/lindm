package secrets

import (
	"bytes"
	"context"
	"errors"
	"time"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/escrow"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

// Managed local-admin passwords: a per-device policy names one account; the
// server mints the local_admin_password_rotate action while polling device
// actions, authorized freshly as the policy actor. The device escrows before
// it sets the password. Rows track whether each escrowed password is in effect.
const (
	localAdminCapability = "device.local-admin-rotate.v1"
	// A minted attempt that does not succeed is retried at most hourly; a
	// successful set schedules the next rotation by the policy interval.
	localAdminRetryAfter     = time.Hour
	localAdminIntentLifetime = 10 * time.Minute

	localAdminBlockedAuthority = "policy_authority_changed"
	localAdminBlockedEscrow    = "escrow_unconfigured"

	methodSetLocalAdminPolicy     = "SetLocalAdminPasswordPolicy"
	methodRemoveLocalAdminPolicy  = "RemoveLocalAdminPasswordPolicy"
	methodRequestLocalAdminRotate = "RequestLocalAdminPasswordRotation"
)

func localAdminState(state string) adminv1.LocalAdminPasswordState {
	switch state {
	case "escrowed":
		return adminv1.LocalAdminPasswordState_LOCAL_ADMIN_PASSWORD_STATE_ESCROWED
	case "current":
		return adminv1.LocalAdminPasswordState_LOCAL_ADMIN_PASSWORD_STATE_CURRENT
	case "superseded":
		return adminv1.LocalAdminPasswordState_LOCAL_ADMIN_PASSWORD_STATE_SUPERSEDED
	case "unknown":
		return adminv1.LocalAdminPasswordState_LOCAL_ADMIN_PASSWORD_STATE_UNKNOWN
	case "failed":
		return adminv1.LocalAdminPasswordState_LOCAL_ADMIN_PASSWORD_STATE_FAILED
	}
	return adminv1.LocalAdminPasswordState_LOCAL_ADMIN_PASSWORD_STATE_UNSPECIFIED
}

func localAdminEscrowMessage(row devicedb.LocalAdminPassword) *adminv1.LocalAdminPasswordEscrow {
	return &adminv1.LocalAdminPasswordEscrow{
		ActionId: row.ActionID.String(), AccountName: row.AccountName, AccountUid: uint32(row.AccountUid), State: localAdminState(row.State),
		EscrowedAt: timestamppb.New(row.EscrowedAt.Time),
		SettledAt:  core.ProtoTime(row.SettledAt), LastRevealedAt: core.ProtoTime(row.LastRevealedAt),
	}
}

// localAdminStatus projects metadata only: never ciphertext, digests or material.
func (s *Service) localAdminStatus(ctx context.Context, q *devicedb.Queries, deviceID uuid.UUID) (*adminv1.LocalAdminPasswordStatus, error) {
	status := &adminv1.LocalAdminPasswordStatus{DeviceId: deviceID.String()}
	if s.Escrow != nil {
		status.EscrowKeyId = s.Escrow.KeyID()
	}
	policy, err := q.GetLocalAdminPolicy(ctx, deviceID)
	if err == nil {
		status.Policy = &adminv1.LocalAdminPasswordPolicy{AccountName: policy.AccountName, RotationInterval: durationpb.New(time.Duration(policy.RotationIntervalSeconds) * time.Second), PostRevealRotationDelay: durationpb.New(time.Duration(policy.PostRevealDelaySeconds) * time.Second)}
		status.RotationDueAt = timestamppb.New(policy.RotateDueAt.Time)
		status.BlockedReason = policy.BlockedReason
		status.PolicyActorId = policy.ActorID.String()
		status.PolicyActorDisplayName = policy.ActorDisplayName
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	rows, err := q.ListLocalAdminPasswords(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		status.Escrows = append(status.Escrows, localAdminEscrowMessage(row))
	}
	return status, nil
}

// localAdminMutation authorizes secrets.manage freshly for the exact device and
// fences the request ID. apply runs once per request ID; replays return status.
func (s *Service) localAdminMutation(ctx context.Context, message proto.Message, method string, deviceID, requestID uuid.UUID, apply func(context.Context, *devicedb.Queries, *identity.Authorization, devicedb.GetDeviceForUpdateRow, time.Time) error) (*adminv1.LocalAdminPasswordStatus, error) {
	permission := identity.PermissionManageSecrets
	actor, err := s.Require(ctx, permission)
	if err != nil {
		return nil, err
	}
	if s.Identity == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	authorization, err := s.Identity.AuthorizeFresh(ctx, actor.ID, permission)
	if err != nil {
		return nil, core.ExecutionError(err)
	}
	digest, err := core.ActionDigest(message)
	if err != nil {
		return nil, core.MapErr(err)
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.Identity.LockAuthorization(ctx, tx, authorization, permission); err != nil {
		return nil, core.ExecutionError(err)
	}
	q := devicedb.New(tx)
	device, err := core.LockDeviceScope(ctx, q, authorization.Principal(), permission, deviceID)
	if err != nil {
		return nil, core.MapErr(err)
	}
	_, owned, err := s.BeginAdminRequest(ctx, q, actor.ID, method, requestID, digest)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if owned {
		now, err := core.DispatchClock(ctx, q)
		if err != nil {
			return nil, core.MapErr(err)
		}
		if err := apply(ctx, q, authorization, device, now); err != nil {
			return nil, core.MapErr(err)
		}
		if err := core.CompleteAdmin(ctx, q, actor.ID, method, requestID, uuid.Nil, deviceID, time.Unix(0, 0).UTC()); err != nil {
			return nil, core.MapErr(err)
		}
	}
	status, err := s.localAdminStatus(ctx, q, deviceID)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if err := s.Identity.LockAuthorization(ctx, tx, authorization, permission); err != nil {
		return nil, core.ExecutionError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	return status, nil
}

// A policy whose online keys lack the exact capability could never rotate;
// reject it while the administrator is present rather than block silently.
func (s *Service) requireLocalAdminSigning(ctx context.Context) error {
	if s.Signing == nil || s.Execution == nil {
		return rpcreason.Error(connect.CodeFailedPrecondition, "execution_signing_unconfigured")
	}
	snapshot, err := s.Execution.Get(ctx)
	if err != nil {
		return core.ExecutionError(err)
	}
	if snapshot.Delegation == nil {
		return rpcreason.Error(connect.CodeFailedPrecondition, "execution_authority_unconfigured")
	}
	if !core.DeviceActionSignerDelegated(snapshot.Delegation, s.Signing.PlanKey, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, localAdminCapability) {
		return core.DeviceActionCapabilityError(localAdminCapability, "plan")
	}
	if !core.DeviceActionSignerDelegated(snapshot.Delegation, s.Signing.StartKey, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, localAdminCapability) {
		return core.DeviceActionCapabilityError(localAdminCapability, "start")
	}
	return nil
}

func (s *Service) SetLocalAdminPasswordPolicy(ctx context.Context, req *connect.Request[adminv1.SetLocalAdminPasswordPolicyRequest]) (*connect.Response[adminv1.SetLocalAdminPasswordPolicyResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	if _, err := s.Require(ctx, identity.PermissionManageSecrets); err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil || core.HasNUL(req.Msg.GetReason()) {
		return nil, core.Invalid("invalid_local_admin_policy")
	}
	if err := s.requireLocalAdminSigning(ctx); err != nil {
		return nil, err
	}
	deviceID, requestID := uuid.MustParse(req.Msg.GetDeviceId()), uuid.MustParse(req.Msg.GetRequestId())
	policy := req.Msg.GetPolicy()
	status, err := s.localAdminMutation(ctx, req.Msg, methodSetLocalAdminPolicy, deviceID, requestID, func(ctx context.Context, q *devicedb.Queries, authorization *identity.Authorization, device devicedb.GetDeviceForUpdateRow, now time.Time) error {
		if device.State != core.StateActive {
			return rpcreason.Error(connect.CodeFailedPrecondition, "device_not_active")
		}
		interval := policy.GetRotationInterval().AsDuration()
		due := now
		current, err := q.GetCurrentLocalAdminPassword(ctx, deviceID)
		if err == nil && current.AccountName == policy.GetAccountName() && current.SettledAt.Valid {
			due = current.SettledAt.Time.Add(interval)
		} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err := q.UpsertLocalAdminPolicy(ctx, devicedb.UpsertLocalAdminPolicyParams{DeviceID: deviceID, AccountName: policy.GetAccountName(), RotationIntervalSeconds: int32(interval / time.Second), PostRevealDelaySeconds: int32(policy.GetPostRevealRotationDelay().AsDuration() / time.Second), ActorID: authorization.ActorID(), AuthorizationVersion: int64(authorization.Version()), RequestID: requestID, RotateDueAt: core.Timestamptz(due), UpdatedAt: core.Timestamptz(now)}); err != nil {
			return err
		}
		return core.DispatchAudit(ctx, q, new(authorization.ActorID()), "local_admin.policy_set", deviceID, req.Msg.GetReason())
	})
	if err != nil {
		return nil, err
	}
	return core.NoStore(&adminv1.SetLocalAdminPasswordPolicyResponse{Status: status}), nil
}

func (s *Service) RemoveLocalAdminPasswordPolicy(ctx context.Context, req *connect.Request[adminv1.RemoveLocalAdminPasswordPolicyRequest]) (*connect.Response[adminv1.RemoveLocalAdminPasswordPolicyResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	if _, err := s.Require(ctx, identity.PermissionManageSecrets); err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil || core.HasNUL(req.Msg.GetReason()) {
		return nil, core.Invalid("invalid_local_admin_policy")
	}
	deviceID, requestID := uuid.MustParse(req.Msg.GetDeviceId()), uuid.MustParse(req.Msg.GetRequestId())
	_, err := s.localAdminMutation(ctx, req.Msg, methodRemoveLocalAdminPolicy, deviceID, requestID, func(ctx context.Context, q *devicedb.Queries, authorization *identity.Authorization, _ devicedb.GetDeviceForUpdateRow, _ time.Time) error {
		removed, err := q.DeleteLocalAdminPolicy(ctx, deviceID)
		if err != nil {
			return err
		}
		if removed == 0 {
			return core.ErrNotFound
		}
		return core.DispatchAudit(ctx, q, new(authorization.ActorID()), "local_admin.policy_removed", deviceID, req.Msg.GetReason())
	})
	if err != nil {
		return nil, err
	}
	return core.NoStore(&adminv1.RemoveLocalAdminPasswordPolicyResponse{}), nil
}

func (s *Service) RequestLocalAdminPasswordRotation(ctx context.Context, req *connect.Request[adminv1.RequestLocalAdminPasswordRotationRequest]) (*connect.Response[adminv1.RequestLocalAdminPasswordRotationResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	if _, err := s.Require(ctx, identity.PermissionManageSecrets); err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil || core.HasNUL(req.Msg.GetReason()) {
		return nil, core.Invalid("invalid_local_admin_rotation")
	}
	if err := s.requireLocalAdminSigning(ctx); err != nil {
		return nil, err
	}
	deviceID, requestID := uuid.MustParse(req.Msg.GetDeviceId()), uuid.MustParse(req.Msg.GetRequestId())
	status, err := s.localAdminMutation(ctx, req.Msg, methodRequestLocalAdminRotate, deviceID, requestID, func(ctx context.Context, q *devicedb.Queries, authorization *identity.Authorization, device devicedb.GetDeviceForUpdateRow, now time.Time) error {
		if device.State != core.StateActive {
			return rpcreason.Error(connect.CodeFailedPrecondition, "device_not_active")
		}
		if _, err := q.LockLocalAdminPolicy(ctx, deviceID); errors.Is(err, pgx.ErrNoRows) {
			return rpcreason.Error(connect.CodeFailedPrecondition, "local_admin_policy_required")
		} else if err != nil {
			return err
		}
		// An explicit request supersedes a rotation whose native set is signed
		// UNKNOWN; its escrowed password remains revealable as a candidate. The
		// device never retries that set: the next action sets a new password.
		open, err := q.GetOpenDeviceAction(ctx, deviceID)
		if err == nil && open.Capability == localAdminCapability && open.OutcomeUnknown && len(open.StatusDocument) > 0 {
			status := new(agentv1.DeviceActionStatus)
			if proto.Unmarshal(open.StatusDocument, status) != nil {
				return core.ErrInternalState
			}
			if status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN {
				if err := q.CloseDeviceAction(ctx, devicedb.CloseDeviceActionParams{ID: open.ID, ClosedAt: core.Timestamptz(now), ClosedReason: "outcome_unknown"}); err != nil {
					return err
				}
			}
		} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err := q.SetLocalAdminPolicyDue(ctx, devicedb.SetLocalAdminPolicyDueParams{DeviceID: deviceID, RotateDueAt: core.Timestamptz(now), ClearBlock: true, UpdatedAt: core.Timestamptz(now)}); err != nil {
			return err
		}
		return core.DispatchAudit(ctx, q, new(authorization.ActorID()), "local_admin.rotation_requested", deviceID, req.Msg.GetReason())
	})
	if err != nil {
		return nil, err
	}
	return core.NoStore(&adminv1.RequestLocalAdminPasswordRotationResponse{Status: status}), nil
}

func (s *Service) GetLocalAdminPasswordStatus(ctx context.Context, req *connect.Request[adminv1.GetLocalAdminPasswordStatusRequest]) (*connect.Response[adminv1.GetLocalAdminPasswordStatusResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_local_admin_status")
	}
	deviceID := uuid.MustParse(req.Msg.GetDeviceId())
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := devicedb.New(tx)
	if err := core.RequireDeviceScope(ctx, q, actor, identity.PermissionReadFleet, deviceID); err != nil {
		return nil, core.MapErr(err)
	}
	status, err := s.localAdminStatus(ctx, q, deviceID)
	if err != nil {
		return nil, core.MapErr(err)
	}
	approval, err := s.CallerRevealApproval(ctx, q, actor, identity.PermissionRevealSecrets, deviceID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	return core.NoStore(&adminv1.GetLocalAdminPasswordStatusResponse{Status: status, RevealApproval: approval}), nil
}

func localAdminAuthorityRejected(err error) bool {
	return errors.Is(err, identity.ErrAuthorizationDenied) || errors.Is(err, identity.ErrAuthorizationExpired) || errors.Is(err, identity.ErrAuthorizationChanged) || errors.Is(err, identity.ErrSubjectUnqualified) || errors.Is(err, core.ErrNotFound)
}

func (s *Service) blockLocalAdminPolicy(ctx context.Context, policy devicedb.GetLocalAdminPolicyRow, reason string) error {
	return core.MapErr(devicedb.New(s.Pool).BlockLocalAdminPolicy(ctx, devicedb.BlockLocalAdminPolicyParams{DeviceID: policy.DeviceID, RequestID: policy.RequestID, BlockedReason: reason}))
}

// mintLocalAdminRotation runs when the device has no open action. It never
// remints while an action is open and returns true only after committing one.
// Changed or denied policy authority and missing escrow block the policy
// visibly instead of minting.
func (s *Service) MintLocalAdminRotation(ctx context.Context, principal core.DevicePrincipal, epoch uint64) (bool, error) {
	if s.Identity == nil || s.Signing == nil || s.Execution == nil {
		return false, nil
	}
	policy, err := devicedb.New(s.Pool).GetLocalAdminPolicy(ctx, principal.DeviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, core.MapErr(err)
	}
	now, err := core.DispatchClock(ctx, devicedb.New(s.Pool))
	if err != nil {
		return false, core.MapErr(err)
	}
	if policy.BlockedReason != "" || now.Before(policy.RotateDueAt.Time) {
		return false, nil
	}
	if s.Escrow == nil {
		return false, s.blockLocalAdminPolicy(ctx, policy, localAdminBlockedEscrow)
	}
	permission := identity.PermissionManageSecrets
	authorization, err := s.Identity.AuthorizeFresh(ctx, policy.ActorID, permission)
	if localAdminAuthorityRejected(err) || err == nil && authorization.Version() != uint64(policy.AuthorizationVersion) {
		return false, s.blockLocalAdminPolicy(ctx, policy, localAdminBlockedAuthority)
	}
	if err != nil {
		// A transient directory or store failure neither mints nor blocks.
		return false, nil
	}
	minted, err := s.mintLocalAdminAction(ctx, principal, epoch, policy, authorization)
	if localAdminAuthorityRejected(err) {
		return false, s.blockLocalAdminPolicy(ctx, policy, localAdminBlockedAuthority)
	}
	return minted, err
}

func (s *Service) mintLocalAdminAction(ctx context.Context, principal core.DevicePrincipal, epoch uint64, policy devicedb.GetLocalAdminPolicyRow, authorization *identity.Authorization) (bool, error) {
	permission := identity.PermissionManageSecrets
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return false, core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Principal-before-device lock order, matching CreateDeviceAction.
	if err := s.Identity.LockAuthorization(ctx, tx, authorization, permission); err != nil {
		return false, err
	}
	snapshot, verifier, err := s.Execution.CurrentInTransaction(ctx, tx)
	if err != nil {
		return false, core.ExecutionError(err)
	}
	q := devicedb.New(tx)
	device, err := s.LockAuthority(ctx, q, principal)
	if err != nil {
		return false, core.MapErr(err)
	}
	if uint64(device.Generation.SessionEpoch) != epoch {
		return false, core.MapErr(core.ErrSessionFenced)
	}
	locked, err := q.LockLocalAdminPolicy(ctx, principal.DeviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, core.MapErr(err)
	}
	now, err := core.DispatchClock(ctx, q)
	if err != nil {
		return false, core.MapErr(err)
	}
	if locked.RequestID != policy.RequestID || locked.BlockedReason != "" || now.Before(locked.RotateDueAt.Time) {
		return false, nil
	}
	if err := core.RequireDeviceScope(ctx, q, authorization.Principal(), permission, principal.DeviceID); err != nil {
		return false, err
	}
	if _, err := q.GetOpenDeviceAction(ctx, principal.DeviceID); err == nil {
		return false, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return false, core.MapErr(err)
	}
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LocalAdminPasswordRotate{LocalAdminPasswordRotate: &agentv1.LocalAdminPasswordRotateAction{AccountName: locked.AccountName, EscrowKeyId: s.Escrow.KeyID(), EscrowPublicKey: s.Escrow.PublicKey()}}}
	if snapshot.Delegation == nil || !core.DeviceActionSignerDelegated(snapshot.Delegation, s.Signing.PlanKey, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, localAdminCapability) || !core.DeviceActionSignerDelegated(snapshot.Delegation, s.Signing.StartKey, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, localAdminCapability) {
		// Set/Request refuse this configuration; a later key rollover is
		// visible as an overdue rotation, never as an unsigned action.
		return false, nil
	}
	if err := core.RequireActionRestriction(ctx, q, principal.DeviceID, spec); err != nil {
		return false, nil
	}
	expires := now.Add(localAdminIntentLifetime)
	if limit := snapshot.Delegation.GetExpiresAt().AsTime(); limit.Before(expires) {
		expires = limit
	}
	if !expires.After(now) {
		return false, nil
	}
	count, err := q.DeviceActionCount(ctx, principal.GenerationID)
	if err != nil {
		return false, core.MapErr(err)
	}
	if count >= 262144 {
		return false, nil
	}
	sequence, err := q.NextResourceSequence(ctx, devicedb.NextResourceSequenceParams{GenerationID: principal.GenerationID, ResourceKind: 1, CanonicalKey: "device.actions"})
	if err != nil {
		return false, core.MapErr(err)
	}
	specDigest, err := core.ActionDigest(spec)
	if err != nil {
		return false, core.MapErr(err)
	}
	// The policy is the request: a synthesized, server-owned document keeps
	// action listings and digests uniform without an administrator request ID.
	request := &adminv1.CreateDeviceActionRequest{RequestId: uuid.NewString(), DeviceId: principal.DeviceID.String(), EnrollmentGeneration: principal.GenerationID.String(), Spec: spec, Reason: "local_admin_policy", ExpiresAt: timestamppb.New(expires)}
	requestDigest, err := core.ActionDigest(request)
	if err != nil {
		return false, core.MapErr(err)
	}
	document, err := proto.Marshal(request)
	if err != nil {
		return false, core.MapErr(err)
	}
	id := uuid.New()
	intent := &agentv1.DeviceActionIntent{DeploymentId: s.DeploymentID.String(), DeviceId: principal.DeviceID.String(), EnrollmentGeneration: principal.GenerationID.String(), ActionId: id.String(), ActorId: locked.ActorID.String(), ActionSequence: uint64(sequence), RecoveryEpoch: snapshot.Delegation.GetMinimumRecoveryEpoch(), RootVersion: snapshot.Root.GetVersion(), DelegationVersion: snapshot.Delegation.GetVersion(), AuthorizationVersion: authorization.Version(), NotBefore: timestamppb.New(core.DeviceActionNotBefore(now, snapshot.Delegation)), ExpiresAt: timestamppb.New(expires), Spec: spec, SpecSha256: specDigest}
	envelope, err := s.Authority.Sign(ctx, intent, s.Signing.PlanKey)
	if err != nil {
		return false, core.ExecutionError(err)
	}
	if _, err := verifier.VerifyDeviceActionIntent(ctx, snapshot.Root, snapshot.Delegation, envelope, now); err != nil {
		return false, core.ExecutionError(err)
	}
	intentBytes, err := proto.Marshal(intent)
	if err != nil {
		return false, core.MapErr(err)
	}
	requestID := uuid.MustParse(request.GetRequestId())
	if err := q.InsertDeviceAction(ctx, devicedb.InsertDeviceActionParams{ID: id, DeviceID: principal.DeviceID, GenerationID: principal.GenerationID, Capability: localAdminCapability, LuksUuids: []uuid.UUID{}, RequestID: requestID, RequestDigest: requestDigest, RequestDocument: document, ActorID: locked.ActorID, AuthorizationVersion: int64(authorization.Version()), IntentEnvelope: envelope, IntentDocument: intentBytes, IssuedAt: core.Timestamptz(now), ExpiresAt: core.Timestamptz(expires)}); err != nil {
		return false, core.MapErr(err)
	}
	if err := core.DispatchSystemAudit(ctx, q, &locked.ActorID, "device_action.create", id, "source", "local_admin_policy"); err != nil {
		return false, core.MapErr(err)
	}
	if err := q.SetLocalAdminPolicyDue(ctx, devicedb.SetLocalAdminPolicyDueParams{DeviceID: principal.DeviceID, RotateDueAt: core.Timestamptz(now.Add(localAdminRetryAfter)), UpdatedAt: core.Timestamptz(now)}); err != nil {
		return false, core.MapErr(err)
	}
	if err := s.Identity.LockAuthorization(ctx, tx, authorization, permission); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, core.MapErr(err)
	}
	return true, nil
}

// ingestLocalAdminEscrow stores exactly the root-planned binding's ciphertext
// before any receipt exists. The device has not changed the account yet.
func (s *Service) IngestLocalAdminEscrow(ctx context.Context, q *devicedb.Queries, action devicedb.DeviceAction, intent *agentv1.DeviceActionIntent, incoming *agentv1.DeviceActionEscrow) error {
	rotate := intent.GetSpec().GetLocalAdminPasswordRotate()
	if len(action.StartGrantEnvelope) == 0 || s.Escrow == nil || incoming.GetEscrowKeyId() != s.Escrow.KeyID() || incoming.GetEscrowKeyId() != rotate.GetEscrowKeyId() || incoming.GetLuksUuid() != "" {
		return rpcreason.Error(connect.CodePermissionDenied, "device_action_escrow_binding_rejected")
	}
	challenge := new(agentv1.DeviceActionChallenge)
	if err := proto.Unmarshal(action.ChallengeDocument, challenge); err != nil {
		return core.ErrInternalState
	}
	planned := challenge.GetNativePlan().GetLocalAdminBinding()
	if planned == nil || !proto.Equal(planned, incoming.GetLocalAdmin()) || planned.GetDeviceId() != intent.GetDeviceId() || planned.GetEnrollmentGeneration() != intent.GetEnrollmentGeneration() || planned.GetActionId() != intent.GetActionId() || planned.GetAccountName() != rotate.GetAccountName() || planned.GetAccountUid() == 0 {
		return rpcreason.Error(connect.CodePermissionDenied, "device_action_escrow_binding_rejected")
	}
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(planned)
	if err != nil {
		return err
	}
	retained, err := q.GetDeviceActionEscrow(ctx, action.ID)
	if err == nil {
		if !bytes.Equal(retained.BindingDocument, canonical) || !bytes.Equal(retained.SecretSha256, incoming.GetRecoveryKeySha256()) {
			return rpcreason.Error(connect.CodeAlreadyExists, "device_action_escrow_conflict")
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	sealed, err := s.Escrow.OpenAndSealLocalAdminPassword(canonical, incoming.GetCiphertext())
	if err != nil {
		return rpcreason.Error(connect.CodePermissionDenied, "device_action_escrow_rejected")
	}
	if !bytes.Equal(sealed.SecretSHA256, incoming.GetRecoveryKeySha256()) {
		return rpcreason.Error(connect.CodePermissionDenied, "device_action_escrow_digest_rejected")
	}
	if _, err := q.InsertDeviceActionEscrow(ctx, devicedb.InsertDeviceActionEscrowParams{ActionID: action.ID, BindingDocument: canonical, KeyID: sealed.KeyID, WrappedKey: sealed.WrappedKey, Ciphertext: sealed.Ciphertext, SecretSha256: sealed.SecretSHA256}); err != nil {
		return err
	}
	if err := q.InsertLocalAdminPassword(ctx, devicedb.InsertLocalAdminPasswordParams{ActionID: action.ID, DeviceID: action.DeviceID, GenerationID: action.GenerationID, AccountName: planned.GetAccountName(), AccountUid: int64(planned.GetAccountUid())}); err != nil {
		return err
	}
	return core.DispatchSystemAudit(ctx, q, nil, "local_admin.escrow_store", action.ID, "proof", "verified_encrypted_local_admin_password")
}

// settleLocalAdminPassword records whether the escrowed password is in effect
// from a verified device-signed result. Rows settle once, from ESCROWED only.
func SettleLocalAdminPassword(ctx context.Context, q *devicedb.Queries, action devicedb.DeviceAction, status *agentv1.DeviceActionStatus, now time.Time) error {
	var state string
	switch status.GetState() {
	case agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED:
		if !status.GetVerification().GetVerified() || len(action.EscrowReceiptEnvelope) == 0 {
			return rpcreason.Error(connect.CodeFailedPrecondition, "device_action_escrow_receipt_required")
		}
		state = "current"
	case agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN:
		state = "unknown"
	case agentv1.DeviceActionState_DEVICE_ACTION_STATE_FAILED, agentv1.DeviceActionState_DEVICE_ACTION_STATE_EXPIRED:
		state = "failed"
	default:
		return nil
	}
	if _, err := q.LockLocalAdminPassword(ctx, action.ID); errors.Is(err, pgx.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	if state == "current" {
		if err := q.SupersedeLocalAdminPasswords(ctx, devicedb.SupersedeLocalAdminPasswordsParams{DeviceID: action.DeviceID, ActionID: action.ID}); err != nil {
			return err
		}
	}
	settled, err := q.SettleLocalAdminPassword(ctx, devicedb.SettleLocalAdminPasswordParams{ActionID: action.ID, State: state, SettledAt: core.Timestamptz(now)})
	if err != nil || settled == 0 || state != "current" {
		return err
	}
	policy, err := q.LockLocalAdminPolicy(ctx, action.DeviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return q.SetLocalAdminPolicyDue(ctx, devicedb.SetLocalAdminPolicyDueParams{DeviceID: action.DeviceID, RotateDueAt: core.Timestamptz(now.Add(time.Duration(policy.RotationIntervalSeconds) * time.Second)), UpdatedAt: core.Timestamptz(now)})
}

func (s *Service) RevealLocalAdminPassword(ctx context.Context, req *connect.Request[adminv1.RevealLocalAdminPasswordRequest]) (*connect.Response[adminv1.RevealLocalAdminPasswordResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	permission := identity.PermissionRevealSecrets
	actor, err := s.Require(ctx, permission)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil || core.HasNUL(req.Msg.GetReason()) {
		return nil, core.Invalid("invalid_local_admin_reveal")
	}
	if s.Identity == nil || s.Escrow == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "escrow_unconfigured")
	}
	if err := s.Identity.RequireRecentStepUp(ctx, 5*time.Minute); err != nil {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "recent_step_up_required")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	authorization, err := s.Identity.AuthorizeFresh(ctx, actor.ID, permission)
	if err != nil {
		return nil, core.ExecutionError(err)
	}
	deviceID, id := uuid.MustParse(req.Msg.GetDeviceId()), uuid.MustParse(req.Msg.GetActionId())
	if err := s.RequireRevealApproval(ctx, authorization.Principal(), permission, deviceID, req.Msg.GetApprovalId()); err != nil {
		return nil, err
	}
	consumption, err := s.PrepareActionApproval(ctx, actor, permission, req.Msg.GetApprovalId(), req.Msg)
	if err != nil {
		return nil, err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.LockActionApproval(ctx, tx, consumption, authorization, permission); err != nil {
		return nil, core.ApprovalError(err)
	}
	q := devicedb.New(tx)
	if _, err := core.LockDeviceScope(ctx, q, authorization.Principal(), permission, deviceID); err != nil {
		return nil, core.MapErr(err)
	}
	action, err := q.GetDeviceAction(ctx, id)
	if err != nil {
		return nil, core.MapErr(core.NotFoundIfMissing(err))
	}
	if action.DeviceID != deviceID || action.Capability != localAdminCapability {
		return nil, core.MapErr(core.ErrNotFound)
	}
	row, err := q.LockLocalAdminPassword(ctx, id)
	if err != nil {
		return nil, core.MapErr(core.NotFoundIfMissing(err))
	}
	// A FAILED row was verified never set; every other state may be in effect.
	if row.State == "failed" {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "local_admin_password_not_in_effect")
	}
	stored, err := q.GetDeviceActionEscrow(ctx, id)
	if err != nil {
		return nil, core.MapErr(core.NotFoundIfMissing(err))
	}
	now, err := core.DispatchClock(ctx, q)
	if err != nil {
		return nil, core.MapErr(err)
	}
	// Audit admission commits before plaintext is released, including every replay.
	if err := core.DispatchAudit(ctx, q, &actor.ID, "local_admin.reveal", id, req.Msg.GetReason()); err != nil {
		return nil, core.MapErr(err)
	}
	if err := q.MarkLocalAdminPasswordRevealed(ctx, devicedb.MarkLocalAdminPasswordRevealedParams{ActionID: id, RevealedAt: core.Timestamptz(now)}); err != nil {
		return nil, core.MapErr(err)
	}
	row.LastRevealedAt = core.Timestamptz(now)
	var rotationDue *timestamppb.Timestamp
	policy, err := q.LockLocalAdminPolicy(ctx, deviceID)
	if err == nil {
		due := now.Add(time.Duration(policy.PostRevealDelaySeconds) * time.Second)
		if policy.RotateDueAt.Time.Before(due) {
			due = policy.RotateDueAt.Time
		}
		if err := q.AdvanceLocalAdminPolicyDue(ctx, devicedb.AdvanceLocalAdminPolicyDueParams{DeviceID: deviceID, RotateDueAt: core.Timestamptz(due), UpdatedAt: core.Timestamptz(now)}); err != nil {
			return nil, core.MapErr(err)
		}
		rotationDue = timestamppb.New(due)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, core.MapErr(err)
	}
	if err := s.LockActionApproval(ctx, tx, consumption, authorization, permission); err != nil {
		return nil, core.ApprovalError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	password, err := s.Escrow.RevealLocalAdminPassword(stored.BindingDocument, &escrow.Record{KeyID: stored.KeyID, WrappedKey: stored.WrappedKey, Ciphertext: stored.Ciphertext, SecretSHA256: stored.SecretSha256})
	if err != nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "escrow_custody_rejected")
	}
	return core.NoStore(&adminv1.RevealLocalAdminPasswordResponse{Password: password, Escrow: localAdminEscrowMessage(row), RotationDueAt: rotationDue}), nil
}
