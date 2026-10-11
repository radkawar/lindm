package core

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

func ApprovalError(err error) error {
	switch {
	case errors.Is(err, identity.ErrApprovalRequired):
		return rpcreason.Error(connect.CodePermissionDenied, "approval_required")
	case errors.Is(err, identity.ErrApprovalInvalid):
		return rpcreason.Error(connect.CodePermissionDenied, "approval_invalid")
	default:
		return ExecutionError(err)
	}
}

func (s *Service) PrepareActionApproval(ctx context.Context, actor identity.Principal, permission identity.Permission, id string, payload proto.Message) (*identity.ApprovalConsumption, error) {
	if s.Identity == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	if !actor.ApprovalRequired(permission) && id == "" {
		return nil, nil
	}
	if actor.ServiceAccount {
		return nil, ApprovalError(identity.ErrAuthorizationDenied)
	}
	approvalID, err := uuid.Parse(id)
	if err != nil || approvalID == uuid.Nil {
		return nil, ApprovalError(identity.ErrApprovalRequired)
	}
	approval, err := s.Identity.PrepareApprovalConsumption(ctx, actor.ID, approvalID, payload)
	if err != nil {
		return nil, ApprovalError(err)
	}
	return approval, nil
}

func (s *Service) LockActionApproval(ctx context.Context, tx pgx.Tx, consumption *identity.ApprovalConsumption, authorization *identity.Authorization, permission identity.Permission) error {
	if consumption != nil {
		if err := s.Identity.LockAndConsumeApproval(ctx, tx, consumption, s.ApprovalScope); err != nil {
			return err
		}
		return s.Identity.LockAuthorization(ctx, tx, authorization, permission)
	}
	if authorization.ApprovalRequired(permission) {
		return identity.ErrApprovalRequired
	}
	return s.Identity.LockAuthorization(ctx, tx, authorization, permission)
}

func (s *Service) prepareRevokeApproval(ctx context.Context, actor identity.Principal, request *adminv1.RevokeDeviceRequest) (*identity.ApprovalConsumption, error) {
	return s.PrepareActionApproval(ctx, actor, identity.PermissionRevokeDevice, request.GetApprovalId(), request)
}
