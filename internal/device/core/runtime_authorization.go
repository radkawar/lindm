package core

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

func (s *Service) GetAuthorization(ctx context.Context, _ *connect.Request[adminv1.GetAuthorizationRequest]) (*connect.Response[adminv1.GetAuthorizationResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	if _, err := s.RequireUnrestricted(ctx, identity.PermissionManageAccounts); err != nil {
		return nil, err
	}
	if s.Identity == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
	state, err := s.Identity.GetAuthorization(ctx)
	if err != nil {
		return nil, ExecutionError(err)
	}
	state.ConfiguredApprovalPermissions = configuredApprovalPermissions(s.RevealApproval)
	return NoStore(&adminv1.GetAuthorizationResponse{Authorization: state}), nil
}

// configuredApprovalPermissions names the reveals escrow.reveal_approval_required
// gates (recovery keys, stored secrets and local admin passwords), so the policy
// editor never presents them as optional while the server enforces them.
func configuredApprovalPermissions(revealApproval bool) []string {
	if !revealApproval {
		return nil
	}
	return []string{string(identity.PermissionReadRecoveryKeys), string(identity.PermissionRevealSecrets)}
}

func (s *Service) UpdateAuthorization(ctx context.Context, req *connect.Request[adminv1.UpdateAuthorizationRequest]) (*connect.Response[adminv1.UpdateAuthorizationResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	if _, err := s.RequireUnrestricted(ctx, identity.PermissionManageAccounts); err != nil {
		return nil, err
	}
	if s.Identity == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	if req == nil || req.Msg == nil {
		return nil, Invalid("invalid_authorization_policy")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
	state, err := s.Identity.UpdateAuthorization(ctx, req.Msg)
	switch {
	case errors.Is(err, identity.ErrPolicyConflict):
		return nil, rpcreason.Error(connect.CodeAborted, "authorization_revision_conflict")
	case errors.Is(err, identity.ErrPolicyReplay):
		return nil, rpcreason.Error(connect.CodeAlreadyExists, "authorization_request_conflict")
	case errors.Is(err, identity.ErrPolicyInvalid):
		return nil, Invalid("invalid_authorization_policy")
	case err != nil:
		return nil, ExecutionError(err)
	}
	state.ConfiguredApprovalPermissions = configuredApprovalPermissions(s.RevealApproval)
	return NoStore(&adminv1.UpdateAuthorizationResponse{Authorization: state}), nil
}
