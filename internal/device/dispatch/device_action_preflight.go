package dispatch

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
	"lindm/internal/device/inventory"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

// PreflightDeviceAction answers, at review time, whether CreateDeviceAction
// would refuse this spec for a device, inventory, restriction or delegation
// precondition. It takes CreateDeviceAction's authority fence and locks in the
// same order, then always rolls back: nothing is created, signed, closed or
// audited. Request expiry, idempotency and approval remain create-time checks.
func (s *Service) PreflightDeviceAction(ctx context.Context, req *connect.Request[adminv1.PreflightDeviceActionRequest]) (*connect.Response[adminv1.PreflightDeviceActionResponse], error) {
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
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_device_action")
	}
	spec := req.Msg.GetSpec()
	if actor.ServiceAccount && DestructiveDeviceAction(spec) {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "human_approval_required")
	}
	response := &adminv1.PreflightDeviceActionResponse{}
	if spec.GetLocalAdminPasswordRotate() != nil {
		return s.preflightBlocked(response, "local_admin_policy_required")
	}
	if s.Identity == nil || s.Signing == nil || s.Execution == nil {
		return s.preflightBlocked(response, "execution_signing_unconfigured")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	authorization, err := s.Identity.AuthorizeFresh(ctx, actor.ID, permission)
	if err != nil {
		return nil, core.ExecutionError(err)
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.Identity.LockAuthorization(ctx, tx, authorization, permission); err != nil {
		return nil, core.ExecutionError(err)
	}
	snapshot, _, err := s.Execution.CurrentInTransaction(ctx, tx)
	if err != nil {
		return nil, core.ExecutionError(err)
	}
	q := devicedb.New(tx)
	deviceID, _ := uuid.Parse(req.Msg.GetDeviceId())
	generationID, _ := uuid.Parse(req.Msg.GetEnrollmentGeneration())
	device, err := core.LockDeviceScope(ctx, q, authorization.Principal(), permission, deviceID)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if spec.GetRefreshInventory() != nil {
		if err := core.RequireDeviceScope(ctx, q, authorization.Principal(), identity.PermissionReadFleet, deviceID); err != nil {
			return nil, core.MapErr(err)
		}
	}
	if snapshot.Delegation == nil {
		return s.preflightBlocked(response, "execution_authority_unconfigured")
	}
	if device.LastSeenAt.Valid {
		response.LastSeenAt = timestamppb.New(device.LastSeenAt.Time)
	}
	if err := preflightInventoryFacts(ctx, q, generationID, response); err != nil {
		return nil, err
	}
	if spec.GetRefreshInventory() == nil {
		response.InventoryMaxAgeSeconds = uint32(inventory.ActionInventoryMaxAge / time.Second)
	}
	now, err := requireActionDevice(ctx, q, device, generationID)
	if err == nil {
		_, _, err = s.requireActionPreconditions(ctx, q, deviceID, generationID, spec, now)
	}
	if err == nil {
		_, err = s.requireActionDelegated(snapshot, spec)
	}
	if err != nil && (connect.CodeOf(err) != connect.CodeFailedPrecondition || rpcreason.Get(err) == "") {
		return nil, core.MapErr(err)
	}
	response.CheckedAt = timestamppb.New(now)
	response.BlockedReason = rpcreason.Get(err)
	response.BlockingAction = blockingAction(err)
	return core.NoStore(response), nil
}

// preflightBlocked reports a deployment-wide prerequisite found before any
// device fact was read.
func (s *Service) preflightBlocked(response *adminv1.PreflightDeviceActionResponse, reason string) (*connect.Response[adminv1.PreflightDeviceActionResponse], error) {
	response.BlockedReason = reason
	response.CheckedAt = timestamppb.New(s.Now())
	return core.NoStore(response), nil
}

// preflightInventoryFacts reports when the latest host inventory arrived, so a
// stale-inventory refusal can name its age next to the device's last check-in.
func preflightInventoryFacts(ctx context.Context, q *devicedb.Queries, generationID uuid.UUID, response *adminv1.PreflightDeviceActionResponse) error {
	host, err := q.GetHostObservation(ctx, generationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return core.MapErr(err)
	}
	if host.ReceivedAt.Valid {
		response.InventoryReceivedAt = timestamppb.New(host.ReceivedAt.Time)
	}
	return nil
}
