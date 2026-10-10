package device

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
)

func (s *Service) GetExecutionAuthority(ctx context.Context, _ *connect.Request[adminv1.GetExecutionAuthorityRequest]) (*connect.Response[adminv1.GetExecutionAuthorityResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	if _, err := s.requireUnrestricted(ctx, identity.PermissionReadFleet); err != nil {
		return nil, err
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	if s.execution == nil {
		return noStore(&adminv1.GetExecutionAuthorityResponse{}), nil
	}
	state, err := s.execution.Get(ctx)
	if err != nil {
		return nil, executionError(err)
	}
	return noStore(&adminv1.GetExecutionAuthorityResponse{
		Root: state.Root, Delegation: state.Delegation,
		AcceptedAt: timestamppb.New(state.AcceptedAt), Revision: state.Revision,
	}), nil
}

func (s *Service) UpdateExecutionAuthority(ctx context.Context, req *connect.Request[adminv1.UpdateExecutionAuthorityRequest]) (*connect.Response[adminv1.UpdateExecutionAuthorityResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.requireUnrestricted(ctx, identity.PermissionManageExecutionTrust)
	if err != nil {
		return nil, err
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	if req == nil || req.Msg == nil || hasNUL(req.Msg.GetReason()) {
		return nil, invalid("invalid_execution_authority_request")
	}
	if err := s.rules.Validate(req.Msg); err != nil {
		return nil, invalid("invalid_execution_authority_request")
	}
	if s.execution == nil {
		return nil, rpcError(connect.CodeFailedPrecondition, "execution_authority_unconfigured")
	}
	approval, err := s.identity.AuthorizeFresh(ctx, actor.ID, identity.PermissionManageExecutionTrust)
	if err != nil {
		return nil, executionError(err)
	}
	if err := requireUnrestrictedPrincipal(approval.Principal(), identity.PermissionManageExecutionTrust); err != nil {
		return nil, err
	}
	consumption, err := s.prepareActionApproval(ctx, actor, identity.PermissionManageExecutionTrust, req.Msg.GetApprovalId(), req.Msg)
	if err != nil {
		return nil, err
	}
	// No transaction spans the authoritative directory read. Principal first,
	// then authority: revocation and the audited public update serialize together.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.lockActionApproval(ctx, tx, consumption, approval, identity.PermissionManageExecutionTrust); err != nil {
		return nil, approvalError(err)
	}
	receipt, err := s.execution.Apply(ctx, tx, req.Msg.GetUpdate(), actor.ID, req.Msg.GetReason())
	if err != nil {
		return nil, executionError(err)
	}
	// Waiting for authority serialization or verification must not outlive the
	// approval. An expired fence rolls back the update, its receipt and its audit.
	if err := s.lockActionApproval(ctx, tx, consumption, approval, identity.PermissionManageExecutionTrust); err != nil {
		return nil, approvalError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return noStore(&adminv1.UpdateExecutionAuthorityResponse{Receipt: receipt}), nil
}

func (s *Service) GetExecutionTrust(ctx context.Context, req *connect.Request[devicev1.GetExecutionTrustRequest]) (*connect.Response[devicev1.GetExecutionTrustResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	principal, ok := devicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcError(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req == nil || req.Msg == nil {
		return nil, invalid("invalid_execution_trust_cursor")
	}
	if err := s.rules.Validate(req.Msg); err != nil {
		return nil, invalid("invalid_execution_trust_cursor")
	}
	// Public trust delivery has no durable side effect. One snapshot preserves
	// the device/generation/certificate/session fence without a WAL-producing
	// row lock; GetSyncState remains the durable polling heartbeat.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := devicedb.New(tx)
	device, err := s.readAuthority(ctx, q, principal)
	if err != nil {
		return nil, mapErr(err)
	}
	if uint64(device.generation.SessionEpoch) != req.Msg.GetSessionEpoch() {
		return nil, mapErr(errSessionFenced)
	}
	response := &devicev1.GetExecutionTrustResponse{}
	if s.execution != nil {
		state, update, err := s.execution.ForDevice(ctx, tx,
			req.Msg.GetRootVersion(), req.Msg.GetDelegationVersion(), req.Msg.GetMinimumRecoveryEpoch(),
			req.Msg.GetRootSha256(), req.Msg.GetDelegationSha256(),
		)
		if err != nil {
			return nil, executionError(err)
		}
		response.Update = update
		response.RootVersion = state.Root.GetVersion()
		response.DelegationVersion = state.Delegation.GetVersion()
		response.MinimumRecoveryEpoch = state.Delegation.GetMinimumRecoveryEpoch()
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	// These are desired public documents, not proof that the relay committed them.
	return noStore(response), nil
}

func executionError(err error) error {
	switch {
	case errors.Is(err, executionauthority.ErrRejected):
		return rpcError(connect.CodePermissionDenied, "execution_authority_rejected")
	case errors.Is(err, executionauthority.ErrIncompatible):
		return rpcError(connect.CodeFailedPrecondition, "execution_authority_incompatible")
	case errors.Is(err, executionauthority.ErrServerBehind):
		return rpcError(connect.CodeFailedPrecondition, "execution_authority_server_behind")
	case errors.Is(err, executionauthority.ErrReprovisioning):
		return rpcError(connect.CodeFailedPrecondition, "execution_authority_reprovisioning_required")
	case errors.Is(err, executionauthority.ErrCapacity):
		return rpcError(connect.CodeResourceExhausted, "execution_authority_capacity")
	case errors.Is(err, executionauthority.ErrCorrupt), errors.Is(err, executionauthority.ErrConfigured):
		return rpcError(connect.CodeFailedPrecondition, "execution_authority_recovery_hold")
	case errors.Is(err, identity.ErrAuthorizationDenied), errors.Is(err, identity.ErrAuthorizationExpired), errors.Is(err, identity.ErrAuthorizationChanged), errors.Is(err, identity.ErrSubjectUnqualified):
		return rpcError(connect.CodePermissionDenied, "actor_authorization_rejected")
	case errors.Is(err, identity.ErrDirectoryUnavailable):
		return rpcError(connect.CodeUnavailable, "directory_unavailable")
	default:
		return mapErr(err)
	}
}
