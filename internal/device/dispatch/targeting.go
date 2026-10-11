package dispatch

import (
	"context"
	"errors"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
	"lindm/internal/targeting"
)

// Every targeting operation shares the principal-before-domain lock order.
// Even previews write immutable evidence and therefore require fresh authority.
func targetingRPC[Request, Response any](ctx context.Context, s *Service, req *connect.Request[Request], permission identity.Permission, run func(context.Context, pgx.Tx, *identity.Authorization, *Request) (*Response, error)) (*connect.Response[Response], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, permission)
	if err != nil {
		return nil, err
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	if req == nil || req.Msg == nil {
		return nil, core.Invalid("invalid_targeting_request")
	}
	if s.Identity == nil || s.Targeting == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "targeting_unavailable")
	}
	authorization, err := s.Identity.AuthorizeFresh(ctx, actor.ID, permission)
	if err != nil {
		return nil, core.ExecutionError(err)
	}
	readOnly := targetingReadOnly(req.Msg)
	var consumption *identity.ApprovalConsumption
	activation, needsApproval := any(req.Msg).(*adminv1.ActivateTargetPreviewRequest)
	if needsApproval {
		consumption, err = s.PrepareActionApproval(ctx, actor, permission, activation.GetApprovalId(), activation)
		if err != nil {
			return nil, err
		}
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return nil, core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	fence := func() error {
		if consumption != nil {
			if err := s.Identity.LockAndConsumeApproval(ctx, tx, consumption, func(ctx context.Context, tx pgx.Tx, p identity.Principal, permission identity.Permission, target uuid.UUID) error {
				if err := s.Targeting.Lock(ctx, tx); err != nil {
					return err
				}
				return s.ApprovalScope(ctx, tx, p, permission, target)
			}); err != nil {
				return err
			}
		} else if needsApproval && s.Identity.ApprovalRequired(permission) {
			return identity.ErrApprovalRequired
		}
		if err := s.Identity.LockAuthorization(ctx, tx, authorization, permission); err != nil {
			return err
		}
		if readOnly {
			return nil
		}
		return s.Targeting.Lock(ctx, tx)
	}
	if err := fence(); err != nil {
		return nil, targetingError(err)
	}
	response, err := run(ctx, tx, authorization, req.Msg)
	if err != nil {
		return nil, targetingError(err)
	}
	message, ok := any(response).(proto.Message)
	if !ok {
		return nil, targetingError(targeting.ErrRejected)
	}
	if err := targeting.ValidateResponse(message); err != nil {
		return nil, targetingError(err)
	}
	if err := fence(); err != nil {
		return nil, targetingError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, targetingError(err)
	}
	return core.NoStore(response), nil
}
func targetingError(err error) error {
	var rpc *connect.Error
	if errors.As(err, &rpc) {
		return err
	}
	var database *pgconn.PgError
	if errors.As(err, &database) && (database.Code == "40001" || database.Code == "40P01") {
		return rpcreason.Error(connect.CodeAborted, "targeting_revision_conflict")
	}
	switch {
	case errors.Is(err, targeting.ErrRejected):
		return core.Invalid("invalid_targeting_request")
	case errors.Is(err, targeting.ErrConflict):
		return rpcreason.Error(connect.CodeAborted, "targeting_revision_conflict")
	case errors.Is(err, targeting.ErrNotFound), errors.Is(err, pgx.ErrNoRows):
		return rpcreason.Error(connect.CodeNotFound, "targeting_not_found")
	case errors.Is(err, targeting.ErrCapacity):
		return rpcreason.Error(connect.CodeResourceExhausted, "targeting_capacity")
	case errors.Is(err, targeting.ErrPaused):
		return rpcreason.Error(connect.CodeFailedPrecondition, "rollout_paused")
	case errors.Is(err, targeting.ErrNotReady):
		return rpcreason.Error(connect.CodeFailedPrecondition, "targeting_not_ready")
	default:
		return core.ApprovalError(err)
	}
}
func (s *Service) PutDynamicGroup(ctx context.Context, r *connect.Request[adminv1.PutDynamicGroupRequest]) (*connect.Response[adminv1.PutDynamicGroupResponse], error) {
	return targetingRPC(ctx, s, r, identity.PermissionManageInventory, func(ctx context.Context, tx pgx.Tx, a *identity.Authorization, r *adminv1.PutDynamicGroupRequest) (*adminv1.PutDynamicGroupResponse, error) {
		return s.Targeting.PutDynamicGroup(ctx, tx, a.Principal(), identity.PermissionManageInventory, r)
	})
}
func (s *Service) ListDynamicGroups(ctx context.Context, r *connect.Request[adminv1.ListDynamicGroupsRequest]) (*connect.Response[adminv1.ListDynamicGroupsResponse], error) {
	return targetingRPC(ctx, s, r, identity.PermissionManageInventory, func(ctx context.Context, tx pgx.Tx, a *identity.Authorization, r *adminv1.ListDynamicGroupsRequest) (*adminv1.ListDynamicGroupsResponse, error) {
		return s.Targeting.ListDynamicGroups(ctx, tx, a.Principal(), identity.PermissionManageInventory, r)
	})
}
func (s *Service) PutTargetAssignment(ctx context.Context, r *connect.Request[adminv1.PutTargetAssignmentRequest]) (*connect.Response[adminv1.PutTargetAssignmentResponse], error) {
	return targetingRPC(ctx, s, r, identity.PermissionAssignResources, func(ctx context.Context, tx pgx.Tx, a *identity.Authorization, r *adminv1.PutTargetAssignmentRequest) (*adminv1.PutTargetAssignmentResponse, error) {
		return s.Targeting.PutAssignment(ctx, tx, a.Principal(), identity.PermissionAssignResources, r)
	})
}
func (s *Service) ListTargetAssignments(ctx context.Context, r *connect.Request[adminv1.ListTargetAssignmentsRequest]) (*connect.Response[adminv1.ListTargetAssignmentsResponse], error) {
	return targetingRPC(ctx, s, r, identity.PermissionAssignResources, func(ctx context.Context, tx pgx.Tx, a *identity.Authorization, r *adminv1.ListTargetAssignmentsRequest) (*adminv1.ListTargetAssignmentsResponse, error) {
		return s.Targeting.ListAssignments(ctx, tx, a.Principal(), identity.PermissionAssignResources, r)
	})
}
func (s *Service) PreviewTargetAssignments(ctx context.Context, r *connect.Request[adminv1.PreviewTargetAssignmentsRequest]) (*connect.Response[adminv1.PreviewTargetAssignmentsResponse], error) {
	return targetingRPC(ctx, s, r, identity.PermissionAssignResources, func(ctx context.Context, tx pgx.Tx, a *identity.Authorization, r *adminv1.PreviewTargetAssignmentsRequest) (*adminv1.PreviewTargetAssignmentsResponse, error) {
		p, err := s.Targeting.Preview(ctx, tx, a.Principal(), identity.PermissionAssignResources, r, s.resolveTargetCandidates)
		if err != nil {
			return nil, err
		}
		return &adminv1.PreviewTargetAssignmentsResponse{Preview: p}, nil
	})
}
func (s *Service) ActivateTargetPreview(ctx context.Context, r *connect.Request[adminv1.ActivateTargetPreviewRequest]) (*connect.Response[adminv1.ActivateTargetPreviewResponse], error) {
	return targetingRPC(ctx, s, r, identity.PermissionAssignResources, func(ctx context.Context, tx pgx.Tx, a *identity.Authorization, r *adminv1.ActivateTargetPreviewRequest) (*adminv1.ActivateTargetPreviewResponse, error) {
		p, err := s.Targeting.Activate(ctx, tx, a.Principal(), identity.PermissionAssignResources, r, func(ctx context.Context, tx pgx.Tx, p *policyv1.TargetPreview) error {
			return s.activateTargetPreview(ctx, tx, p, a.ActorID(), a.Version(), r.GetApprovalId())
		})
		if err != nil {
			return nil, err
		}
		return &adminv1.ActivateTargetPreviewResponse{Preview: p}, nil
	})
}
func (s *Service) PutRollout(ctx context.Context, r *connect.Request[adminv1.PutRolloutRequest]) (*connect.Response[adminv1.PutRolloutResponse], error) {
	return targetingRPC(ctx, s, r, identity.PermissionAssignResources, func(ctx context.Context, tx pgx.Tx, a *identity.Authorization, r *adminv1.PutRolloutRequest) (*adminv1.PutRolloutResponse, error) {
		return s.Targeting.PutRollout(ctx, tx, a.Principal(), identity.PermissionAssignResources, r)
	})
}
func (s *Service) ControlRollout(ctx context.Context, r *connect.Request[adminv1.ControlRolloutRequest]) (*connect.Response[adminv1.ControlRolloutResponse], error) {
	return targetingRPC(ctx, s, r, identity.PermissionAssignResources, func(ctx context.Context, tx pgx.Tx, a *identity.Authorization, r *adminv1.ControlRolloutRequest) (*adminv1.ControlRolloutResponse, error) {
		return s.Targeting.ControlRollout(ctx, tx, a.Principal(), identity.PermissionAssignResources, r)
	})
}
func (s *Service) ListRollouts(ctx context.Context, r *connect.Request[adminv1.ListRolloutsRequest]) (*connect.Response[adminv1.ListRolloutsResponse], error) {
	return targetingRPC(ctx, s, r, identity.PermissionAssignResources, func(ctx context.Context, tx pgx.Tx, a *identity.Authorization, r *adminv1.ListRolloutsRequest) (*adminv1.ListRolloutsResponse, error) {
		return s.Targeting.ListRollouts(ctx, tx, a.Principal(), identity.PermissionAssignResources, r)
	})
}

func (s *Service) GetDynamicGroup(ctx context.Context, r *connect.Request[adminv1.GetDynamicGroupRequest]) (*connect.Response[adminv1.GetDynamicGroupResponse], error) {
	return targetingRPC(ctx, s, r, identity.PermissionManageInventory, func(ctx context.Context, tx pgx.Tx, a *identity.Authorization, r *adminv1.GetDynamicGroupRequest) (*adminv1.GetDynamicGroupResponse, error) {
		return s.Targeting.GetDynamicGroup(ctx, tx, a.Principal(), identity.PermissionManageInventory, r)
	})
}

func targetingReadOnly(request any) bool {
	switch request.(type) {
	case *adminv1.GetDynamicGroupRequest, *adminv1.ListDynamicGroupsRequest, *adminv1.ListTargetAssignmentsRequest, *adminv1.ListRolloutsRequest:
		return true
	default:
		return false
	}
}
