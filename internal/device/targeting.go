package device

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/identity"
	"lindm/internal/targeting"
)

// Every targeting operation shares the principal-before-domain lock order.
// Even previews write immutable evidence and therefore require fresh authority.
func targetingRPC[Request, Response any](ctx context.Context, s *Service, req *connect.Request[Request], permission identity.Permission, run func(context.Context, pgx.Tx, *identity.Authorization, *Request) (*Response, error)) (*connect.Response[Response], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.require(ctx, permission)
	if err != nil {
		return nil, err
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	if req == nil || req.Msg == nil {
		return nil, invalid("invalid_targeting_request")
	}
	if s.identity == nil || s.targeting == nil {
		return nil, rpcError(connect.CodeFailedPrecondition, "targeting_unavailable")
	}
	authorization, err := s.identity.AuthorizeFresh(ctx, actor.ID, permission)
	if err != nil {
		return nil, executionError(err)
	}
	var consumption *identity.ApprovalConsumption
	activation, needsApproval := any(req.Msg).(*adminv1.ActivateTargetPreviewRequest)
	if needsApproval {
		consumption, err = s.prepareActionApproval(ctx, actor, permission, activation.GetApprovalId(), activation)
		if err != nil {
			return nil, err
		}
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	fence := func() error {
		if consumption != nil {
			if err := s.identity.LockAndConsumeApproval(ctx, tx, consumption, func(ctx context.Context, tx pgx.Tx, p identity.Principal, permission identity.Permission, target uuid.UUID) error {
				if err := s.targeting.Lock(ctx, tx); err != nil {
					return err
				}
				return s.approvalScope(ctx, tx, p, permission, target)
			}); err != nil {
				return err
			}
		} else if needsApproval && s.identity.ApprovalRequired(permission) {
			return identity.ErrApprovalRequired
		}
		if err := s.identity.LockAuthorization(ctx, tx, authorization, permission); err != nil {
			return err
		}
		return s.targeting.Lock(ctx, tx)
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
	return noStore(response), nil
}
func targetingError(err error) error {
	var rpc *connect.Error
	if errors.As(err, &rpc) {
		return err
	}
	var database *pgconn.PgError
	if errors.As(err, &database) && (database.Code == "40001" || database.Code == "40P01") {
		return rpcError(connect.CodeAborted, "targeting_revision_conflict")
	}
	switch {
	case errors.Is(err, targeting.ErrRejected):
		return invalid("invalid_targeting_request")
	case errors.Is(err, targeting.ErrConflict):
		return rpcError(connect.CodeAborted, "targeting_revision_conflict")
	case errors.Is(err, targeting.ErrNotFound), errors.Is(err, pgx.ErrNoRows):
		return rpcError(connect.CodeNotFound, "targeting_not_found")
	case errors.Is(err, targeting.ErrCapacity):
		return rpcError(connect.CodeResourceExhausted, "targeting_capacity")
	case errors.Is(err, targeting.ErrPaused):
		return rpcError(connect.CodeFailedPrecondition, "rollout_paused")
	case errors.Is(err, targeting.ErrNotReady):
		return rpcError(connect.CodeFailedPrecondition, "targeting_not_ready")
	default:
		return approvalError(err)
	}
}
func (s *Service) PutDynamicGroup(ctx context.Context, r *connect.Request[adminv1.PutDynamicGroupRequest]) (*connect.Response[adminv1.PutDynamicGroupResponse], error) {
	return targetingRPC(ctx, s, r, identity.PermissionManageInventory, func(ctx context.Context, tx pgx.Tx, a *identity.Authorization, r *adminv1.PutDynamicGroupRequest) (*adminv1.PutDynamicGroupResponse, error) {
		return s.targeting.PutDynamicGroup(ctx, tx, a.Principal(), identity.PermissionManageInventory, r)
	})
}
func (s *Service) ListDynamicGroups(ctx context.Context, r *connect.Request[adminv1.ListDynamicGroupsRequest]) (*connect.Response[adminv1.ListDynamicGroupsResponse], error) {
	return targetingRPC(ctx, s, r, identity.PermissionManageInventory, func(ctx context.Context, tx pgx.Tx, a *identity.Authorization, r *adminv1.ListDynamicGroupsRequest) (*adminv1.ListDynamicGroupsResponse, error) {
		return s.targeting.ListDynamicGroups(ctx, tx, a.Principal(), identity.PermissionManageInventory, r)
	})
}
func (s *Service) PutTargetAssignment(ctx context.Context, r *connect.Request[adminv1.PutTargetAssignmentRequest]) (*connect.Response[adminv1.PutTargetAssignmentResponse], error) {
	return targetingRPC(ctx, s, r, identity.PermissionAssignResources, func(ctx context.Context, tx pgx.Tx, a *identity.Authorization, r *adminv1.PutTargetAssignmentRequest) (*adminv1.PutTargetAssignmentResponse, error) {
		return s.targeting.PutAssignment(ctx, tx, a.Principal(), identity.PermissionAssignResources, r)
	})
}
func (s *Service) ListTargetAssignments(ctx context.Context, r *connect.Request[adminv1.ListTargetAssignmentsRequest]) (*connect.Response[adminv1.ListTargetAssignmentsResponse], error) {
	return targetingRPC(ctx, s, r, identity.PermissionAssignResources, func(ctx context.Context, tx pgx.Tx, a *identity.Authorization, r *adminv1.ListTargetAssignmentsRequest) (*adminv1.ListTargetAssignmentsResponse, error) {
		return s.targeting.ListAssignments(ctx, tx, a.Principal(), identity.PermissionAssignResources, r)
	})
}
func (s *Service) PreviewTargetAssignments(ctx context.Context, r *connect.Request[adminv1.PreviewTargetAssignmentsRequest]) (*connect.Response[adminv1.PreviewTargetAssignmentsResponse], error) {
	return targetingRPC(ctx, s, r, identity.PermissionAssignResources, func(ctx context.Context, tx pgx.Tx, a *identity.Authorization, r *adminv1.PreviewTargetAssignmentsRequest) (*adminv1.PreviewTargetAssignmentsResponse, error) {
		p, err := s.targeting.Preview(ctx, tx, a.Principal(), identity.PermissionAssignResources, r, s.resolveTargetCandidates)
		if err != nil {
			return nil, err
		}
		return &adminv1.PreviewTargetAssignmentsResponse{Preview: p}, nil
	})
}
func (s *Service) ActivateTargetPreview(ctx context.Context, r *connect.Request[adminv1.ActivateTargetPreviewRequest]) (*connect.Response[adminv1.ActivateTargetPreviewResponse], error) {
	return targetingRPC(ctx, s, r, identity.PermissionAssignResources, func(ctx context.Context, tx pgx.Tx, a *identity.Authorization, r *adminv1.ActivateTargetPreviewRequest) (*adminv1.ActivateTargetPreviewResponse, error) {
		p, err := s.targeting.Activate(ctx, tx, a.Principal(), identity.PermissionAssignResources, r, func(ctx context.Context, tx pgx.Tx, p *policyv1.TargetPreview) error {
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
		return s.targeting.PutRollout(ctx, tx, a.Principal(), identity.PermissionAssignResources, r)
	})
}
func (s *Service) ControlRollout(ctx context.Context, r *connect.Request[adminv1.ControlRolloutRequest]) (*connect.Response[adminv1.ControlRolloutResponse], error) {
	return targetingRPC(ctx, s, r, identity.PermissionAssignResources, func(ctx context.Context, tx pgx.Tx, a *identity.Authorization, r *adminv1.ControlRolloutRequest) (*adminv1.ControlRolloutResponse, error) {
		return s.targeting.ControlRollout(ctx, tx, a.Principal(), identity.PermissionAssignResources, r)
	})
}
func (s *Service) ListRollouts(ctx context.Context, r *connect.Request[adminv1.ListRolloutsRequest]) (*connect.Response[adminv1.ListRolloutsResponse], error) {
	return targetingRPC(ctx, s, r, identity.PermissionAssignResources, func(ctx context.Context, tx pgx.Tx, a *identity.Authorization, r *adminv1.ListRolloutsRequest) (*adminv1.ListRolloutsResponse, error) {
		return s.targeting.ListRollouts(ctx, tx, a.Principal(), identity.PermissionAssignResources, r)
	})
}

func (s *Service) GetDynamicGroup(ctx context.Context, r *connect.Request[adminv1.GetDynamicGroupRequest]) (*connect.Response[adminv1.GetDynamicGroupResponse], error) {
	return targetingRPC(ctx, s, r, identity.PermissionManageInventory, func(ctx context.Context, tx pgx.Tx, a *identity.Authorization, r *adminv1.GetDynamicGroupRequest) (*adminv1.GetDynamicGroupResponse, error) {
		return s.targeting.GetDynamicGroup(ctx, tx, a.Principal(), identity.PermissionManageInventory, r)
	})
}
