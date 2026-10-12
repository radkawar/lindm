package dispatch

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
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/executionauthority"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
	"lindm/internal/trust"
)

func (s *Service) CreateDeviceAction(ctx context.Context, req *connect.Request[adminv1.CreateDeviceActionRequest]) (*connect.Response[adminv1.CreateDeviceActionResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	permission := identity.PermissionRunRemoteExecution
	if req != nil && req.Msg != nil {
		permission = DeviceActionPermission(req.Msg.GetSpec())
	}
	actor, err := s.Require(ctx, permission)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil || core.HasNUL(req.Msg.GetReason()) {
		return nil, core.Invalid("invalid_device_action")
	}
	// Only the policy scheduler or RequestLocalAdminPasswordRotation mint this
	// arm, authorized as the policy actor with the server's own escrow key.
	if req.Msg.GetSpec().GetLocalAdminPasswordRotate() != nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "local_admin_policy_required")
	}
	if s.Identity == nil || s.Signing == nil || s.Execution == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "execution_signing_unconfigured")
	}
	if actor.ServiceAccount && DestructiveDeviceAction(req.Msg.GetSpec()) {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "human_approval_required")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	authorization, err := s.Identity.AuthorizeFresh(ctx, actor.ID, permission)
	if err != nil {
		return nil, core.ExecutionError(err)
	}
	canonical := proto.CloneOf(req.Msg)
	canonical.ApprovalId = ""
	digest, err := core.ActionDigest(canonical)
	if err != nil {
		return nil, core.MapErr(err)
	}
	document, err := proto.Marshal(canonical)
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
	snapshot, verifier, err := s.Execution.CurrentInTransaction(ctx, tx)
	if err != nil {
		return nil, core.ExecutionError(err)
	}
	if snapshot.Delegation == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "execution_authority_unconfigured")
	}
	q := devicedb.New(tx)
	deviceID, _ := uuid.Parse(req.Msg.GetDeviceId())
	generationID, _ := uuid.Parse(req.Msg.GetEnrollmentGeneration())
	requestID, _ := uuid.Parse(req.Msg.GetRequestId())
	device, err := core.LockMutableDevice(ctx, q, authorization.Principal(), permission, deviceID)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if req.Msg.GetSpec().GetRefreshInventory() != nil {
		if err := core.RequireDeviceScope(ctx, q, authorization.Principal(), identity.PermissionReadFleet, deviceID); err != nil {
			return nil, core.MapErr(err)
		}
	}
	old, err := q.GetDeviceActionRequest(ctx, requestID)
	if err == nil {
		if old.ActorID != actor.ID || !bytes.Equal(old.RequestDigest, digest) {
			return nil, core.MapErr(core.ErrIdempotencyConflict)
		}
		action, err := actionMessage(old)
		if err != nil {
			return nil, core.MapErr(err)
		}
		if err := s.Identity.LockAuthorization(ctx, tx, authorization, permission); err != nil {
			return nil, core.ExecutionError(err)
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, core.MapErr(err)
		}
		return core.NoStore(&adminv1.CreateDeviceActionResponse{Action: action}), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, core.MapErr(err)
	}
	return s.createAuthorizedDeviceAction(ctx, tx, q, req, actor, authorization, permission, snapshot, verifier, device, generationID, requestID, digest, document)
}

func (s *Service) createAuthorizedDeviceAction(ctx context.Context, tx pgx.Tx, q *devicedb.Queries, req *connect.Request[adminv1.CreateDeviceActionRequest], actor identity.Principal, authorization *identity.Authorization, permission identity.Permission, snapshot *executionauthority.Snapshot, verifier *trust.ExecutionVerifier, device devicedb.GetDeviceForUpdateRow, generationID, requestID uuid.UUID, digest, document []byte) (*connect.Response[adminv1.CreateDeviceActionResponse], error) {
	now, err := requireActionDevice(ctx, q, device, generationID)
	if err != nil {
		return nil, err
	}
	expires := req.Msg.GetExpiresAt().AsTime()
	if !expires.After(now) || expires.After(now.Add(10*time.Minute)) || expires.After(snapshot.Delegation.GetExpiresAt().AsTime()) {
		return nil, core.Invalid("device_action_expiry")
	}
	open, closeReason, err := s.requireActionPreconditions(ctx, q, device.ID, generationID, req.Msg.GetSpec(), now)
	if err != nil {
		return nil, err
	}
	if open != nil {
		if err := q.CloseDeviceAction(ctx, devicedb.CloseDeviceActionParams{ID: open.ID, ClosedAt: core.Timestamptz(now), ClosedReason: closeReason}); err != nil {
			return nil, core.MapErr(err)
		}
	}
	return s.mintDeviceAction(ctx, tx, q, req, actor, authorization, permission, snapshot, verifier, device.ID, generationID, requestID, digest, document, now, expires)
}

// requireActionDevice admits only the current, connected generation and returns
// the dispatch clock. Intent is an online preflight, not an offline queue.
func requireActionDevice(ctx context.Context, q *devicedb.Queries, device devicedb.GetDeviceForUpdateRow, generationID uuid.UUID) (time.Time, error) {
	now, err := core.DispatchClock(ctx, q)
	if err != nil {
		return time.Time{}, core.MapErr(err)
	}
	if device.State != core.StateActive || device.CurrentGenerationID == nil || *device.CurrentGenerationID != generationID {
		return now, rpcreason.Error(connect.CodeFailedPrecondition, "device_action_generation_rejected")
	}
	generation, err := q.GetGenerationAuthority(ctx, generationID)
	if err != nil {
		return now, core.MapErr(err)
	}
	if generation.State != core.StateActive || generation.SessionEpoch <= 0 {
		return now, rpcreason.Error(connect.CodeFailedPrecondition, "device_action_session_unavailable")
	}
	if !device.LastSeenAt.Valid || now.Sub(device.LastSeenAt.Time) > time.Minute {
		return now, rpcreason.Error(connect.CodeFailedPrecondition, "device_action_offline")
	}
	return now, nil
}

// requireActionPreconditions runs the spec's readiness, inventory, restriction
// and open-action checks. It never writes: an open action that a new one
// supersedes is returned with its close reason for the caller to close.
func (s *Service) requireActionPreconditions(ctx context.Context, q *devicedb.Queries, deviceID, generationID uuid.UUID, spec *agentv1.DeviceActionSpec, now time.Time) (*devicedb.DeviceAction, string, error) {
	if err := s.inventory.RequireRecoveryReadiness(ctx, q, generationID, spec, now); err != nil {
		return nil, "", core.MapErr(err)
	}
	if err := requireActionInventory(ctx, q, generationID, spec, now); err != nil {
		return nil, "", core.MapErr(err)
	}
	if err := requireLiveRootEscrow(ctx, q, deviceID, spec); err != nil {
		return nil, "", core.MapErr(err)
	}
	if err := core.RequireActionRestriction(ctx, q, deviceID, spec); err != nil {
		return nil, "", core.MapErr(err)
	}
	if err := requireLockActionRestriction(ctx, q, deviceID, generationID, spec); err != nil {
		return nil, "", core.MapErr(err)
	}
	if rotate := spec.GetEscrowRotate(); rotate != nil {
		if s.Escrow == nil || rotate.GetEscrowKeyId() != s.Escrow.KeyID() || !bytes.Equal(rotate.GetEscrowPublicKey(), s.Escrow.PublicKey()) {
			return nil, "", rpcreason.Error(connect.CodeFailedPrecondition, "escrow_key_rejected")
		}
	}
	open, err := q.GetOpenDeviceAction(ctx, deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", core.MapErr(err)
	}
	inverse, err := releaseSupersedesUnknownLock(open, generationID, spec)
	if err != nil {
		return nil, "", core.MapErr(err)
	}
	if inverse {
		return &open, "outcome_unknown", nil
	}
	if open.OutcomeUnknown || len(open.StartGrantEnvelope) > 0 || now.Before(open.ExpiresAt.Time) {
		return nil, "", rpcreason.Error(connect.CodeFailedPrecondition, "device_action_pending")
	}
	return &open, "expired_unstarted", nil
}

// requireActionDelegated rejects capabilities the current delegation does not
// grant to both online signing roles, before any intent is signed.
func (s *Service) requireActionDelegated(snapshot *executionauthority.Snapshot, spec *agentv1.DeviceActionSpec) (string, error) {
	capability, err := trust.DeviceActionCapability(spec)
	if err != nil {
		return "", core.Invalid("invalid_device_action")
	}
	if !core.DeviceActionSignerDelegated(snapshot.Delegation, s.Signing.PlanKey, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, capability) {
		return "", core.DeviceActionCapabilityError(capability, "plan")
	}
	if !core.DeviceActionSignerDelegated(snapshot.Delegation, s.Signing.StartKey, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, capability) {
		return "", core.DeviceActionCapabilityError(capability, "start")
	}
	return capability, nil
}

func (s *Service) mintDeviceAction(ctx context.Context, tx pgx.Tx, q *devicedb.Queries, req *connect.Request[adminv1.CreateDeviceActionRequest], actor identity.Principal, authorization *identity.Authorization, permission identity.Permission, snapshot *executionauthority.Snapshot, verifier *trust.ExecutionVerifier, deviceID, generationID, requestID uuid.UUID, digest, document []byte, now, expires time.Time) (*connect.Response[adminv1.CreateDeviceActionResponse], error) {
	var approvalID *uuid.UUID
	if req.Msg.GetApprovalId() != "" {
		parsed, _ := uuid.Parse(req.Msg.GetApprovalId())
		approvalID = &parsed
	}
	if (DestructiveDeviceAction(req.Msg.GetSpec()) || authorization.ApprovalRequired(permission)) && approvalID == nil {
		return nil, core.ApprovalError(identity.ErrApprovalRequired)
	}
	count, err := q.DeviceActionCount(ctx, generationID)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if count >= 262144 {
		return nil, rpcreason.Error(connect.CodeResourceExhausted, "device_action_capacity")
	}
	sequence, err := q.NextResourceSequence(ctx, devicedb.NextResourceSequenceParams{GenerationID: generationID, ResourceKind: 1, CanonicalKey: "device.actions"})
	if err != nil {
		return nil, core.MapErr(err)
	}
	specDigest, err := core.ActionDigest(req.Msg.GetSpec())
	if err != nil {
		return nil, core.MapErr(err)
	}
	capability, err := s.requireActionDelegated(snapshot, req.Msg.GetSpec())
	if err != nil {
		return nil, err
	}
	id := uuid.New()
	intent := &agentv1.DeviceActionIntent{DeploymentId: s.DeploymentID.String(), DeviceId: deviceID.String(), EnrollmentGeneration: generationID.String(), ActionId: id.String(), ActorId: actor.ID.String(), ActionSequence: uint64(sequence), RecoveryEpoch: snapshot.Delegation.GetMinimumRecoveryEpoch(), RootVersion: snapshot.Root.GetVersion(), DelegationVersion: snapshot.Delegation.GetVersion(), AuthorizationVersion: authorization.Version(), NotBefore: timestamppb.New(core.DeviceActionNotBefore(now, snapshot.Delegation)), ExpiresAt: req.Msg.GetExpiresAt(), Spec: req.Msg.GetSpec(), SpecSha256: specDigest}
	envelope, err := s.Authority.Sign(ctx, intent, s.Signing.PlanKey)
	if err != nil {
		return nil, core.ExecutionError(err)
	}
	if _, err := verifier.VerifyDeviceActionIntent(ctx, snapshot.Root, snapshot.Delegation, envelope, now); err != nil {
		return nil, core.ExecutionError(err)
	}
	intentBytes, err := proto.Marshal(intent)
	if err != nil {
		return nil, core.MapErr(err)
	}
	luksUUIDs, err := actionLUKSUUIDs(req.Msg.GetSpec())
	if err != nil {
		return nil, err
	}
	if err := q.InsertDeviceAction(ctx, devicedb.InsertDeviceActionParams{ID: id, DeviceID: deviceID, GenerationID: generationID, Capability: capability, LuksUuids: luksUUIDs, RequestID: requestID, RequestDigest: digest, RequestDocument: document, ActorID: actor.ID, AuthorizationVersion: int64(authorization.Version()), ApprovalID: approvalID, IntentEnvelope: envelope, IntentDocument: intentBytes, IssuedAt: core.Timestamptz(now), ExpiresAt: core.Timestamptz(expires)}); err != nil {
		return nil, core.MapErr(err)
	}
	if err := core.DispatchAudit(ctx, q, &actor.ID, "device_action.create", id, req.Msg.GetReason()); err != nil {
		return nil, core.MapErr(err)
	}
	row, err := q.GetDeviceAction(ctx, id)
	if err != nil {
		return nil, core.MapErr(err)
	}
	action, err := actionMessage(row)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if err := s.Identity.LockAuthorization(ctx, tx, authorization, permission); err != nil {
		return nil, core.ExecutionError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	return core.NoStore(&adminv1.CreateDeviceActionResponse{Action: action}), nil
}

func (s *Service) GetDeviceActions(ctx context.Context, req *connect.Request[adminv1.GetDeviceActionsRequest]) (*connect.Response[adminv1.GetDeviceActionsResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_device_actions")
	}
	id, _ := uuid.Parse(req.Msg.GetDeviceId())
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := devicedb.New(tx)
	if err := core.RequireDeviceScope(ctx, q, actor, identity.PermissionReadFleet, id); err != nil {
		return nil, core.MapErr(err)
	}
	params := devicedb.ListDeviceActionsParams{DeviceID: id, PageLimit: core.PageLimit(req.Msg.GetPageSize()) + 1, CursorTime: core.Timestamptz(time.Unix(0, 0))}
	if req.Msg.GetPageToken() != "" {
		stamp, cursor, err := core.DecodeCursor(req.Msg.GetPageToken())
		if err != nil {
			return nil, err
		}
		params.HasCursor = true
		params.CursorTime = core.Timestamptz(stamp)
		params.CursorID = cursor
	}
	rows, err := q.ListDeviceActions(ctx, params)
	if err != nil {
		return nil, core.MapErr(err)
	}
	response := &adminv1.GetDeviceActionsResponse{}
	restriction, restrictionErr := q.GetDeviceActionRestriction(ctx, id)
	if restrictionErr == nil {
		now, err := core.DispatchClock(ctx, q)
		if err != nil {
			return nil, core.MapErr(err)
		}
		response.SessionsLocked = restriction.SessionsLocked
		if restriction.LockActionID != nil {
			response.LockActionId = restriction.LockActionID.String()
		}
		response.Quarantined = restriction.Quarantined && restriction.QuarantineUntil.Valid && now.Before(restriction.QuarantineUntil.Time)
		if restriction.QuarantineUntil.Valid {
			response.QuarantineUntil = timestamppb.New(restriction.QuarantineUntil.Time)
		}
	} else if !errors.Is(restrictionErr, pgx.ErrNoRows) {
		return nil, core.MapErr(restrictionErr)
	}
	names, err := actionActorNames(ctx, q, rows...)
	if err != nil {
		return nil, core.MapErr(err)
	}
	var budget core.ResponsePageBudget
	for _, row := range rows {
		if len(response.Actions) == int(params.PageLimit)-1 {
			break
		}
		action, err := actionMessage(row)
		if err != nil {
			return nil, core.MapErr(err)
		}
		action.ActorDisplayName = names[row.ActorID]
		fits, err := budget.Take(action)
		if err != nil {
			return nil, core.MapErr(err)
		}
		if !fits {
			break
		}
		response.Actions = append(response.Actions, action)
	}
	if len(response.Actions) < len(rows) {
		if len(response.Actions) == 0 {
			return nil, rpcreason.Error(connect.CodeResourceExhausted, "device_action_page_capacity")
		}
		last := rows[len(response.Actions)-1]
		response.NextPageToken, err = core.EncodeCursor(last.IssuedAt.Time, last.ID)
		if err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	return core.NoStore(response), nil
}
func (s *Service) GetDeviceAction(ctx context.Context, req *connect.Request[adminv1.GetDeviceActionRequest]) (*connect.Response[adminv1.GetDeviceActionResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_device_action")
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	id, _ := uuid.Parse(req.Msg.GetActionId())
	q := devicedb.New(tx)
	row, err := q.GetDeviceAction(ctx, id)
	if err != nil {
		return nil, core.MapErr(core.NotFoundIfMissing(err))
	}
	if err := core.RequireDeviceScope(ctx, q, actor, identity.PermissionReadFleet, row.DeviceID); err != nil {
		return nil, core.MapErr(err)
	}
	action, err := actionMessage(row)
	if err != nil {
		return nil, core.MapErr(err)
	}
	names, err := actionActorNames(ctx, q, row)
	if err != nil {
		return nil, core.MapErr(err)
	}
	action.ActorDisplayName = names[row.ActorID]
	if err := tx.Commit(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	return core.NoStore(&adminv1.GetDeviceActionResponse{Action: action}), nil
}
