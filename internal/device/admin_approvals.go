package device

import (
	"context"
	"encoding/base64"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

func approvalError(err error) error {
	switch {
	case errors.Is(err, identity.ErrApprovalRequired):
		return rpcreason.Error(connect.CodePermissionDenied, "approval_required")
	case errors.Is(err, identity.ErrApprovalInvalid):
		return rpcreason.Error(connect.CodePermissionDenied, "approval_invalid")
	default:
		return executionError(err)
	}
}

func (s *Service) prepareActionApproval(ctx context.Context, actor identity.Principal, permission identity.Permission, id string, payload proto.Message) (*identity.ApprovalConsumption, error) {
	if s.identity == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	if !s.identity.ApprovalRequired(permission) && id == "" {
		return nil, nil
	}
	if actor.ServiceAccount {
		return nil, approvalError(identity.ErrAuthorizationDenied)
	}
	approvalID, err := uuid.Parse(id)
	if err != nil || approvalID == uuid.Nil {
		return nil, approvalError(identity.ErrApprovalRequired)
	}
	approval, err := s.identity.PrepareApprovalConsumption(ctx, actor.ID, approvalID, payload)
	if err != nil {
		return nil, approvalError(err)
	}
	return approval, nil
}

func (s *Service) prepareRevokeApproval(ctx context.Context, actor identity.Principal, request *adminv1.RevokeDeviceRequest) (*identity.ApprovalConsumption, error) {
	return s.prepareActionApproval(ctx, actor, identity.PermissionRevokeDevice, request.GetApprovalId(), request)
}

func (s *Service) lockActionApproval(ctx context.Context, tx pgx.Tx, consumption *identity.ApprovalConsumption, authorization *identity.Authorization, permission identity.Permission) error {
	if consumption != nil {
		if err := s.identity.LockAndConsumeApproval(ctx, tx, consumption, s.approvalScope); err != nil {
			return err
		}
		return s.identity.LockAuthorization(ctx, tx, authorization, permission)
	}
	if s.identity.ApprovalRequired(permission) {
		return identity.ErrApprovalRequired
	}
	return s.identity.LockAuthorization(ctx, tx, authorization, permission)
}

func (s *Service) CreateApproval(ctx context.Context, req *connect.Request[adminv1.CreateApprovalRequest]) (*connect.Response[adminv1.CreateApprovalResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, ok := identity.PrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if actor.ServiceAccount {
		return nil, approvalError(identity.ErrAuthorizationDenied)
	}
	if s.identity == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_approval")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	approval, err := s.identity.CreateApproval(ctx, actor.ID, req.Msg, s.recoveryReadinessApprovalScope(req.Msg.GetCreateDeviceAction()))
	if err != nil {
		return nil, approvalError(err)
	}
	return noStore(&adminv1.CreateApprovalResponse{Approval: approval}), nil
}

func (s *Service) ListApprovals(ctx context.Context, req *connect.Request[adminv1.ListApprovalsRequest]) (*connect.Response[adminv1.ListApprovalsResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, ok := identity.PrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if s.identity == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_approval")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	approvals, next, err := s.identity.ListApprovals(ctx, actor.ID, req.Msg)
	if err != nil {
		return nil, approvalError(err)
	}
	var budget responsePageBudget
	for i, item := range approvals {
		fits, err := budget.take(item)
		if err != nil {
			return nil, mapErr(err)
		}
		if !fits {
			if i == 0 {
				return nil, mapErr(errInternalState)
			}
			last, err := parseUUID(approvals[i-1].GetId())
			if err != nil {
				return nil, mapErr(errInternalState)
			}
			next = base64.RawURLEncoding.EncodeToString(last[:])
			approvals = approvals[:i]
			break
		}
	}
	return noStore(&adminv1.ListApprovalsResponse{Approvals: approvals, NextPageToken: next}), nil
}

func (s *Service) ApproveApproval(ctx context.Context, req *connect.Request[adminv1.ApproveApprovalRequest]) (*connect.Response[adminv1.ApproveApprovalResponse], error) {
	approval, err := s.decideApproval(ctx, message(req), true)
	if err != nil {
		return nil, err
	}
	return noStore(&adminv1.ApproveApprovalResponse{Approval: approval}), nil
}

func (s *Service) RejectApproval(ctx context.Context, req *connect.Request[adminv1.RejectApprovalRequest]) (*connect.Response[adminv1.RejectApprovalResponse], error) {
	approval, err := s.decideApproval(ctx, message(req), false)
	if err != nil {
		return nil, err
	}
	return noStore(&adminv1.RejectApprovalResponse{Approval: approval}), nil
}

type approvalDecision interface {
	proto.Message
	GetApprovalId() string
	GetReason() string
}

// decideApproval records one human reviewer's decision; service accounts never
// review.
func (s *Service) decideApproval(ctx context.Context, msg approvalDecision, approve bool) (*adminv1.Approval, error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.require(ctx, identity.PermissionManageApprovals)
	if err != nil {
		return nil, err
	}
	if actor.ServiceAccount {
		return nil, approvalError(identity.ErrAuthorizationDenied)
	}
	if s.identity == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	if !msg.ProtoReflect().IsValid() || s.rules.Validate(msg) != nil {
		return nil, invalid("invalid_approval")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	id, err := parseUUID(msg.GetApprovalId())
	if err != nil {
		return nil, invalid("invalid_id")
	}
	approval, err := s.identity.DecideApproval(ctx, actor.ID, id, approve, msg.GetReason(), s.approvalScope)
	if err != nil {
		return nil, approvalError(err)
	}
	return approval, nil
}
