// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/executionauthority"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

func (s *Service) GetExecutionAuthority(ctx context.Context, _ *connect.Request[adminv1.GetExecutionAuthorityRequest]) (*connect.Response[adminv1.GetExecutionAuthorityResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	if _, err := s.RequireUnrestricted(ctx, identity.PermissionReadFleet); err != nil {
		return nil, err
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
	if s.Execution == nil {
		return NoStore(&adminv1.GetExecutionAuthorityResponse{}), nil
	}
	state, err := s.Execution.Get(ctx)
	if err != nil {
		return nil, ExecutionError(err)
	}
	return NoStore(&adminv1.GetExecutionAuthorityResponse{
		Root: state.Root, Delegation: state.Delegation,
		AcceptedAt: timestamppb.New(state.AcceptedAt), Revision: state.Revision,
	}), nil
}

func (s *Service) UpdateExecutionAuthority(ctx context.Context, req *connect.Request[adminv1.UpdateExecutionAuthorityRequest]) (*connect.Response[adminv1.UpdateExecutionAuthorityResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	actor, err := s.RequireUnrestricted(ctx, identity.PermissionManageExecutionTrust)
	if err != nil {
		return nil, err
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
	if req == nil || req.Msg == nil || HasNUL(req.Msg.GetReason()) {
		return nil, Invalid("invalid_execution_authority_request")
	}
	if err := s.Rules.Validate(req.Msg); err != nil {
		return nil, Invalid("invalid_execution_authority_request")
	}
	if s.Execution == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "execution_authority_unconfigured")
	}
	approval, err := s.Identity.AuthorizeFresh(ctx, actor.ID, identity.PermissionManageExecutionTrust)
	if err != nil {
		return nil, ExecutionError(err)
	}
	if err := RequireUnrestrictedPrincipal(approval.Principal(), identity.PermissionManageExecutionTrust); err != nil {
		return nil, err
	}
	consumption, err := s.PrepareActionApproval(ctx, actor, identity.PermissionManageExecutionTrust, req.Msg.GetApprovalId(), req.Msg)
	if err != nil {
		return nil, err
	}
	// No transaction spans the authoritative directory read. Principal first,
	// then authority: revocation and the audited public update serialize together.
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.LockActionApproval(ctx, tx, consumption, approval, identity.PermissionManageExecutionTrust); err != nil {
		return nil, ApprovalError(err)
	}
	receipt, err := s.Execution.Apply(ctx, tx, req.Msg.GetUpdate(), actor.ID, req.Msg.GetReason())
	if err != nil {
		return nil, ExecutionError(err)
	}
	// Waiting for authority serialization or verification must not outlive the
	// approval. An expired fence rolls back the update, its receipt and its audit.
	if err := s.LockActionApproval(ctx, tx, consumption, approval, identity.PermissionManageExecutionTrust); err != nil {
		return nil, ApprovalError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, MapErr(err)
	}
	return NoStore(&adminv1.UpdateExecutionAuthorityResponse{Receipt: receipt}), nil
}

func (s *Service) GetExecutionTrust(ctx context.Context, req *connect.Request[devicev1.GetExecutionTrustRequest]) (*connect.Response[devicev1.GetExecutionTrustResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	principal, ok := DevicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req == nil || req.Msg == nil {
		return nil, Invalid("invalid_execution_trust_cursor")
	}
	if err := s.Rules.Validate(req.Msg); err != nil {
		return nil, Invalid("invalid_execution_trust_cursor")
	}
	// Public trust delivery has no durable side effect. One snapshot preserves
	// the device/generation/certificate/session fence without a WAL-producing
	// row lock; GetSyncState remains the durable polling heartbeat.
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := devicedb.New(tx)
	device, err := s.ReadAuthority(ctx, q, principal)
	if err != nil {
		return nil, MapErr(err)
	}
	if uint64(device.Generation.SessionEpoch) != req.Msg.GetSessionEpoch() {
		return nil, MapErr(ErrSessionFenced)
	}
	response := &devicev1.GetExecutionTrustResponse{}
	if s.Execution != nil {
		state, update, err := s.Execution.ForDevice(ctx, tx,
			req.Msg.GetRootVersion(), req.Msg.GetDelegationVersion(), req.Msg.GetMinimumRecoveryEpoch(),
			req.Msg.GetRootSha256(), req.Msg.GetDelegationSha256(),
		)
		if err != nil {
			return nil, ExecutionError(err)
		}
		response.Update = update
		response.RootVersion = state.Root.GetVersion()
		response.DelegationVersion = state.Delegation.GetVersion()
		response.MinimumRecoveryEpoch = state.Delegation.GetMinimumRecoveryEpoch()
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, MapErr(err)
	}
	// These are desired public documents, not proof that the relay committed them.
	return NoStore(response), nil
}

func ExecutionError(err error) error {
	switch {
	case errors.Is(err, executionauthority.ErrRejected):
		return rpcreason.Error(connect.CodePermissionDenied, "execution_authority_rejected")
	case errors.Is(err, executionauthority.ErrIncompatible):
		return rpcreason.Error(connect.CodeFailedPrecondition, "execution_authority_incompatible")
	case errors.Is(err, executionauthority.ErrServerBehind):
		return rpcreason.Error(connect.CodeFailedPrecondition, "execution_authority_server_behind")
	case errors.Is(err, executionauthority.ErrReprovisioning):
		return rpcreason.Error(connect.CodeFailedPrecondition, "execution_authority_reprovisioning_required")
	case errors.Is(err, executionauthority.ErrCapacity):
		return rpcreason.Error(connect.CodeResourceExhausted, "execution_authority_capacity")
	case errors.Is(err, executionauthority.ErrCorrupt), errors.Is(err, executionauthority.ErrConfigured):
		return rpcreason.Error(connect.CodeFailedPrecondition, "execution_authority_recovery_hold")
	case errors.Is(err, identity.ErrAuthorizationDenied), errors.Is(err, identity.ErrAuthorizationExpired), errors.Is(err, identity.ErrAuthorizationChanged), errors.Is(err, identity.ErrSubjectUnqualified):
		return rpcreason.Error(connect.CodePermissionDenied, "actor_authorization_rejected")
	case errors.Is(err, identity.ErrDirectoryUnavailable):
		return rpcreason.Error(connect.CodeUnavailable, "directory_unavailable")
	default:
		return MapErr(err)
	}
}
