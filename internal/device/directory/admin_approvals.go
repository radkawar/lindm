package directory

import (
	"context"
	"encoding/base64"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

func (s *Service) CreateApproval(ctx context.Context, req *connect.Request[adminv1.CreateApprovalRequest]) (*connect.Response[adminv1.CreateApprovalResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, ok := identity.PrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if actor.ServiceAccount {
		return nil, core.ApprovalError(identity.ErrAuthorizationDenied)
	}
	if s.Identity == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_approval")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	scope := s.inventory.RecoveryReadinessApprovalScope(req.Msg.GetCreateDeviceAction())
	var targetPreview *policyv1.TargetPreview
	if request := req.Msg.GetActivateTargetPreview(); request != nil {
		base := scope
		scope = func(ctx context.Context, tx pgx.Tx, principal identity.Principal, permission identity.Permission, target uuid.UUID) error {
			if err := base(ctx, tx, principal, permission, target); err != nil {
				return err
			}
			if s.Targeting == nil {
				return rpcreason.Error(connect.CodeFailedPrecondition, "targeting_unavailable")
			}
			var err error
			targetPreview, err = s.Targeting.ApprovalPreview(ctx, tx, request)
			if err != nil {
				return targetApprovalError(err)
			}
			if targetPreview == nil {
				return rpcreason.Error(connect.CodeNotFound, "targeting_not_found")
			}
			return nil
		}
	}
	approval, err := s.Identity.CreateApproval(ctx, actor.ID, req.Msg, scope)
	if err != nil {
		return nil, core.ApprovalError(err)
	}
	approval.TargetPreview = targetPreview
	if err := s.populateAdvisoryApproval(ctx, actor, approval); err != nil {
		return nil, err
	}
	return core.NoStore(&adminv1.CreateApprovalResponse{Approval: approval}), nil
}

func (s *Service) ListApprovals(ctx context.Context, req *connect.Request[adminv1.ListApprovalsRequest]) (*connect.Response[adminv1.ListApprovalsResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, ok := identity.PrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if s.Identity == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_approval")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	approvals, next, err := s.Identity.ListApprovals(ctx, actor.ID, req.Msg)
	if err != nil {
		return nil, core.ApprovalError(err)
	}
	var budget core.ResponsePageBudget
	for i, item := range approvals {
		if err := s.populateTargetApproval(ctx, actor, item); err != nil {
			return nil, err
		}
		if err := s.populateAdvisoryApproval(ctx, actor, item); err != nil {
			return nil, err
		}
		fits, err := budget.Take(item)
		if err != nil {
			return nil, core.MapErr(err)
		}
		if !fits {
			if i == 0 {
				return nil, core.MapErr(core.ErrInternalState)
			}
			last, err := core.ParseUUID(approvals[i-1].GetId())
			if err != nil {
				return nil, core.MapErr(core.ErrInternalState)
			}
			next = base64.RawURLEncoding.EncodeToString(last[:])
			approvals = approvals[:i]
			break
		}
	}
	return core.NoStore(&adminv1.ListApprovalsResponse{Approvals: approvals, NextPageToken: next, CurrentPrincipalId: actor.ID.String()}), nil
}

func (s *Service) ApproveApproval(ctx context.Context, req *connect.Request[adminv1.ApproveApprovalRequest]) (*connect.Response[adminv1.ApproveApprovalResponse], error) {
	approval, err := s.decideApproval(ctx, core.Message(req), true)
	if err != nil {
		return nil, err
	}
	return core.NoStore(&adminv1.ApproveApprovalResponse{Approval: approval}), nil
}

func (s *Service) RejectApproval(ctx context.Context, req *connect.Request[adminv1.RejectApprovalRequest]) (*connect.Response[adminv1.RejectApprovalResponse], error) {
	approval, err := s.decideApproval(ctx, core.Message(req), false)
	if err != nil {
		return nil, err
	}
	return core.NoStore(&adminv1.RejectApprovalResponse{Approval: approval}), nil
}

// WithdrawApproval lets a human requester close their own pending request;
// the identity layer refuses anyone else.
func (s *Service) WithdrawApproval(ctx context.Context, req *connect.Request[adminv1.WithdrawApprovalRequest]) (*connect.Response[adminv1.WithdrawApprovalResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, ok := identity.PrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if actor.ServiceAccount {
		return nil, core.ApprovalError(identity.ErrAuthorizationDenied)
	}
	if s.Identity == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_approval")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	id, err := core.ParseUUID(req.Msg.GetApprovalId())
	if err != nil {
		return nil, core.Invalid("invalid_id")
	}
	approval, err := s.Identity.WithdrawApproval(ctx, actor.ID, id, req.Msg.GetReason())
	if err != nil {
		return nil, core.ApprovalError(err)
	}
	return core.NoStore(&adminv1.WithdrawApprovalResponse{Approval: approval}), nil
}

type approvalDecision interface {
	proto.Message
	GetApprovalId() string
	GetReason() string
}

// decideApproval records one human reviewer's decision; service accounts never
// review.
func (s *Service) decideApproval(ctx context.Context, msg approvalDecision, approve bool) (*adminv1.Approval, error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionManageApprovals)
	if err != nil {
		return nil, err
	}
	if actor.ServiceAccount {
		return nil, core.ApprovalError(identity.ErrAuthorizationDenied)
	}
	if s.Identity == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	if !msg.ProtoReflect().IsValid() || s.Rules.Validate(msg) != nil {
		return nil, core.Invalid("invalid_approval")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	id, err := core.ParseUUID(msg.GetApprovalId())
	if err != nil {
		return nil, core.Invalid("invalid_id")
	}
	approval, err := s.Identity.DecideApproval(ctx, actor.ID, id, approve, msg.GetReason(), s.ApprovalScope, s.admitApproval)
	if err != nil {
		return nil, core.ApprovalError(err)
	}
	return approval, nil
}
