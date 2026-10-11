package device

import (
	"bytes"
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
	"lindm/internal/trust"
)

func (s *Service) CreateDeviceAction(ctx context.Context, req *connect.Request[adminv1.CreateDeviceActionRequest]) (*connect.Response[adminv1.CreateDeviceActionResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	permission := identity.PermissionRunRemoteExecution
	if req != nil && req.Msg != nil {
		permission = deviceActionPermission(req.Msg.GetSpec())
	}
	actor, err := s.require(ctx, permission)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil || hasNUL(req.Msg.GetReason()) {
		return nil, invalid("invalid_device_action")
	}
	// Only the policy scheduler or RequestLocalAdminPasswordRotation mint this
	// arm, authorized as the policy actor with the server's own escrow key.
	if req.Msg.GetSpec().GetLocalAdminPasswordRotate() != nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "local_admin_policy_required")
	}
	if s.identity == nil || s.signing == nil || s.execution == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "execution_signing_unconfigured")
	}
	if actor.ServiceAccount && destructiveDeviceAction(req.Msg.GetSpec()) {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "human_approval_required")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	authorization, err := s.identity.AuthorizeFresh(ctx, actor.ID, permission)
	if err != nil {
		return nil, executionError(err)
	}
	canonical := proto.CloneOf(req.Msg)
	canonical.ApprovalId = ""
	digest, err := actionDigest(canonical)
	if err != nil {
		return nil, mapErr(err)
	}
	document, err := proto.Marshal(canonical)
	if err != nil {
		return nil, mapErr(err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.identity.LockAuthorization(ctx, tx, authorization, permission); err != nil {
		return nil, executionError(err)
	}
	snapshot, verifier, err := s.execution.CurrentInTransaction(ctx, tx)
	if err != nil {
		return nil, executionError(err)
	}
	if snapshot.Delegation == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "execution_authority_unconfigured")
	}
	q := devicedb.New(tx)
	deviceID, _ := uuid.Parse(req.Msg.GetDeviceId())
	generationID, _ := uuid.Parse(req.Msg.GetEnrollmentGeneration())
	requestID, _ := uuid.Parse(req.Msg.GetRequestId())
	device, err := lockDeviceScope(ctx, q, authorization.Principal(), permission, deviceID)
	if err != nil {
		return nil, mapErr(err)
	}
	if req.Msg.GetSpec().GetRefreshInventory() != nil {
		if err := requireDeviceScope(ctx, q, authorization.Principal(), identity.PermissionReadFleet, deviceID); err != nil {
			return nil, mapErr(err)
		}
	}
	old, err := q.GetDeviceActionRequest(ctx, requestID)
	if err == nil {
		if old.ActorID != actor.ID || !bytes.Equal(old.RequestDigest, digest) {
			return nil, mapErr(errIdempotencyConflict)
		}
		action, err := actionMessage(old)
		if err != nil {
			return nil, mapErr(err)
		}
		if err := s.identity.LockAuthorization(ctx, tx, authorization, permission); err != nil {
			return nil, executionError(err)
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, mapErr(err)
		}
		return noStore(&adminv1.CreateDeviceActionResponse{Action: action}), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, mapErr(err)
	}
	if device.State != stateActive || device.CurrentGenerationID == nil || *device.CurrentGenerationID != generationID {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "device_action_generation_rejected")
	}
	generation, err := q.GetGenerationAuthority(ctx, generationID)
	if err != nil {
		return nil, mapErr(err)
	}
	if generation.State != stateActive || generation.SessionEpoch <= 0 {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "device_action_session_unavailable")
	}
	now, err := dispatchClock(ctx, q)
	if err != nil {
		return nil, mapErr(err)
	}
	// Intent is an online preflight, not an offline destructive queue.
	if !device.LastSeenAt.Valid || now.Sub(device.LastSeenAt.Time) > time.Minute {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "device_action_offline")
	}
	expires := req.Msg.GetExpiresAt().AsTime()
	if !expires.After(now) || expires.After(now.Add(10*time.Minute)) || expires.After(snapshot.Delegation.GetExpiresAt().AsTime()) {
		return nil, invalid("device_action_expiry")
	}
	if err := s.requireRecoveryReadiness(ctx, q, generationID, req.Msg.GetSpec(), now); err != nil {
		return nil, mapErr(err)
	}
	if err := requireActionInventory(ctx, q, generationID, req.Msg.GetSpec(), now); err != nil {
		return nil, mapErr(err)
	}
	if err := requireLiveRootEscrow(ctx, q, deviceID, req.Msg.GetSpec()); err != nil {
		return nil, mapErr(err)
	}
	if err := requireActionRestriction(ctx, q, deviceID, req.Msg.GetSpec()); err != nil {
		return nil, mapErr(err)
	}
	if err := requireLockActionRestriction(ctx, q, deviceID, generationID, req.Msg.GetSpec()); err != nil {
		return nil, mapErr(err)
	}
	if rotate := req.Msg.GetSpec().GetEscrowRotate(); rotate != nil {
		if s.escrow == nil || rotate.GetEscrowKeyId() != s.escrow.KeyID() || !bytes.Equal(rotate.GetEscrowPublicKey(), s.escrow.PublicKey()) {
			return nil, rpcreason.Error(connect.CodeFailedPrecondition, "escrow_key_rejected")
		}
	}
	open, err := q.GetOpenDeviceAction(ctx, deviceID)
	if err == nil {
		inverse, err := releaseSupersedesUnknownLock(open, generationID, req.Msg.GetSpec())
		if err != nil {
			return nil, mapErr(err)
		}
		reason := "expired_unstarted"
		if inverse {
			reason = "outcome_unknown"
		} else if open.OutcomeUnknown || len(open.StartGrantEnvelope) > 0 || now.Before(open.ExpiresAt.Time) {
			return nil, rpcreason.Error(connect.CodeFailedPrecondition, "device_action_pending")
		}
		if err := q.CloseDeviceAction(ctx, devicedb.CloseDeviceActionParams{ID: open.ID, ClosedAt: timestamptz(now), ClosedReason: reason}); err != nil {
			return nil, mapErr(err)
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, mapErr(err)
	}
	var approvalID *uuid.UUID
	if req.Msg.GetApprovalId() != "" {
		parsed, _ := uuid.Parse(req.Msg.GetApprovalId())
		approvalID = &parsed
	}
	if (destructiveDeviceAction(req.Msg.GetSpec()) || s.identity.ApprovalRequired(permission)) && approvalID == nil {
		return nil, approvalError(identity.ErrApprovalRequired)
	}
	count, err := q.DeviceActionCount(ctx, generationID)
	if err != nil {
		return nil, mapErr(err)
	}
	if count >= 262144 {
		return nil, rpcreason.Error(connect.CodeResourceExhausted, "device_action_capacity")
	}
	sequence, err := q.NextResourceSequence(ctx, devicedb.NextResourceSequenceParams{GenerationID: generationID, ResourceKind: 1, CanonicalKey: "device.actions"})
	if err != nil {
		return nil, mapErr(err)
	}
	specDigest, err := actionDigest(req.Msg.GetSpec())
	if err != nil {
		return nil, mapErr(err)
	}
	capability, err := trust.DeviceActionCapability(req.Msg.GetSpec())
	if err != nil {
		return nil, invalid("invalid_device_action")
	}
	if !deviceActionSignerDelegated(snapshot.Delegation, s.signing.PlanKey, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, capability) {
		return nil, deviceActionCapabilityError(capability, "plan")
	}
	if !deviceActionSignerDelegated(snapshot.Delegation, s.signing.StartKey, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, capability) {
		return nil, deviceActionCapabilityError(capability, "start")
	}
	id := uuid.New()
	intent := &agentv1.DeviceActionIntent{DeploymentId: s.deploymentID.String(), DeviceId: deviceID.String(), EnrollmentGeneration: generationID.String(), ActionId: id.String(), ActorId: actor.ID.String(), ActionSequence: uint64(sequence), RecoveryEpoch: snapshot.Delegation.GetMinimumRecoveryEpoch(), RootVersion: snapshot.Root.GetVersion(), DelegationVersion: snapshot.Delegation.GetVersion(), AuthorizationVersion: authorization.Version(), NotBefore: timestamppb.New(now.Add(-trust.MaxDeviceClockSkew)), ExpiresAt: req.Msg.GetExpiresAt(), Spec: req.Msg.GetSpec(), SpecSha256: specDigest}
	envelope, err := s.authority.Sign(ctx, intent, s.signing.PlanKey)
	if err != nil {
		return nil, executionError(err)
	}
	if _, err := verifier.VerifyDeviceActionIntent(ctx, snapshot.Root, snapshot.Delegation, envelope, now); err != nil {
		return nil, executionError(err)
	}
	intentBytes, err := proto.Marshal(intent)
	if err != nil {
		return nil, mapErr(err)
	}
	luksUUIDs, err := actionLUKSUUIDs(req.Msg.GetSpec())
	if err != nil {
		return nil, err
	}
	if err := q.InsertDeviceAction(ctx, devicedb.InsertDeviceActionParams{ID: id, DeviceID: deviceID, GenerationID: generationID, Capability: capability, LuksUuids: luksUUIDs, RequestID: requestID, RequestDigest: digest, RequestDocument: document, ActorID: actor.ID, AuthorizationVersion: int64(authorization.Version()), ApprovalID: approvalID, IntentEnvelope: envelope, IntentDocument: intentBytes, IssuedAt: timestamptz(now), ExpiresAt: timestamptz(expires)}); err != nil {
		return nil, mapErr(err)
	}
	if err := dispatchAudit(ctx, q, &actor.ID, "device_action.create", id, req.Msg.GetReason()); err != nil {
		return nil, mapErr(err)
	}
	row, err := q.GetDeviceAction(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	action, err := actionMessage(row)
	if err != nil {
		return nil, mapErr(err)
	}
	if err := s.identity.LockAuthorization(ctx, tx, authorization, permission); err != nil {
		return nil, executionError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return noStore(&adminv1.CreateDeviceActionResponse{Action: action}), nil
}

func (s *Service) GetDeviceActions(ctx context.Context, req *connect.Request[adminv1.GetDeviceActionsRequest]) (*connect.Response[adminv1.GetDeviceActionsResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_device_actions")
	}
	id, _ := uuid.Parse(req.Msg.GetDeviceId())
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := devicedb.New(tx)
	if err := requireDeviceScope(ctx, q, actor, identity.PermissionReadFleet, id); err != nil {
		return nil, mapErr(err)
	}
	params := devicedb.ListDeviceActionsParams{DeviceID: id, PageLimit: pageLimit(req.Msg.GetPageSize()) + 1, CursorTime: timestamptz(time.Unix(0, 0))}
	if req.Msg.GetPageToken() != "" {
		stamp, cursor, err := decodeCursor(req.Msg.GetPageToken())
		if err != nil {
			return nil, err
		}
		params.HasCursor = true
		params.CursorTime = timestamptz(stamp)
		params.CursorID = cursor
	}
	rows, err := q.ListDeviceActions(ctx, params)
	if err != nil {
		return nil, mapErr(err)
	}
	response := &adminv1.GetDeviceActionsResponse{}
	restriction, restrictionErr := q.GetDeviceActionRestriction(ctx, id)
	if restrictionErr == nil {
		now, err := dispatchClock(ctx, q)
		if err != nil {
			return nil, mapErr(err)
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
		return nil, mapErr(restrictionErr)
	}
	var budget responsePageBudget
	for _, row := range rows {
		if len(response.Actions) == int(params.PageLimit)-1 {
			break
		}
		action, err := actionMessage(row)
		if err != nil {
			return nil, mapErr(err)
		}
		fits, err := budget.take(action)
		if err != nil {
			return nil, mapErr(err)
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
		response.NextPageToken, err = encodeCursor(last.IssuedAt.Time, last.ID)
		if err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return noStore(response), nil
}
func (s *Service) GetDeviceAction(ctx context.Context, req *connect.Request[adminv1.GetDeviceActionRequest]) (*connect.Response[adminv1.GetDeviceActionResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_device_action")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	id, _ := uuid.Parse(req.Msg.GetActionId())
	q := devicedb.New(tx)
	row, err := q.GetDeviceAction(ctx, id)
	if err != nil {
		return nil, mapErr(notFoundIfMissing(err))
	}
	if err := requireDeviceScope(ctx, q, actor, identity.PermissionReadFleet, row.DeviceID); err != nil {
		return nil, mapErr(err)
	}
	action, err := actionMessage(row)
	if err != nil {
		return nil, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return noStore(&adminv1.GetDeviceActionResponse{Action: action}), nil
}
