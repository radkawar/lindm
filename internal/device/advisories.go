package device

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/advisory"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

func (s *Service) ListDeviceFindings(ctx context.Context, req *connect.Request[adminv1.ListDeviceFindingsRequest]) (*connect.Response[adminv1.ListDeviceFindingsResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_advisory_request")
	}
	id, err := uuid.Parse(req.Msg.GetDeviceId())
	if err != nil {
		return nil, invalid("invalid_id")
	}
	if err := requireDeviceScope(ctx, devicedb.New(s.pool), actor, identity.PermissionReadFleet, id); err != nil {
		return nil, mapErr(err)
	}
	if s.advisories == nil {
		return nil, rpcError(connect.CodeFailedPrecondition, "advisory_unavailable")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	unrestricted, scopes, err := deviceScopeFilter(actor, identity.PermissionReadFleet)
	if err != nil {
		return nil, mapErr(err)
	}
	out, err := s.advisories.ListDevice(ctx, req.Msg, unrestricted, scopes)
	if err != nil {
		return nil, advisoryError(err)
	}
	return noStore(out), nil
}

func (s *Service) ListAdvisorySummary(ctx context.Context, req *connect.Request[adminv1.ListAdvisorySummaryRequest]) (*connect.Response[adminv1.ListAdvisorySummaryResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_advisory_request")
	}
	unrestricted, scopes, err := deviceScopeFilter(actor, identity.PermissionReadFleet)
	if err != nil {
		return nil, mapErr(err)
	}
	if s.advisories == nil {
		return nil, rpcError(connect.CodeFailedPrecondition, "advisory_unavailable")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	out, err := s.advisories.Summary(ctx, req.Msg, unrestricted, scopes)
	if err != nil {
		return nil, advisoryError(err)
	}
	return noStore(out), nil
}

func (s *Service) ListAdvisoryFeeds(ctx context.Context, req *connect.Request[adminv1.ListAdvisoryFeedsRequest]) (*connect.Response[adminv1.ListAdvisoryFeedsResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	if _, err := s.requireUnrestricted(ctx, identity.PermissionReadFleet); err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil {
		return nil, invalid("invalid_advisory_request")
	}
	if s.advisories == nil {
		return nil, rpcError(connect.CodeFailedPrecondition, "advisory_unavailable")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	out, err := s.advisories.Feeds(ctx)
	if err != nil {
		return nil, advisoryError(err)
	}
	return noStore(out), nil
}

func (s *Service) AcceptAdvisoryFinding(ctx context.Context, req *connect.Request[adminv1.AcceptAdvisoryFindingRequest]) (*connect.Response[adminv1.AcceptAdvisoryFindingResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.require(ctx, identity.PermissionManageAdvisoryExceptions)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_advisory_request")
	}
	id, err := uuid.Parse(req.Msg.GetDeviceId())
	if err != nil {
		return nil, invalid("invalid_id")
	}
	if err := requireDeviceScope(ctx, devicedb.New(s.pool), actor, identity.PermissionManageAdvisoryExceptions, id); err != nil {
		return nil, mapErr(err)
	}
	if s.advisories == nil || s.identity == nil {
		return nil, rpcError(connect.CodeFailedPrecondition, "advisory_unavailable")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	approval, err := s.identity.AuthorizeFresh(ctx, actor.ID, identity.PermissionManageAdvisoryExceptions)
	if err != nil {
		return nil, executionError(err)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.identity.LockAuthorization(ctx, tx, approval, identity.PermissionManageAdvisoryExceptions); err != nil {
		return nil, executionError(err)
	}
	if _, err := lockDeviceScope(ctx, devicedb.New(tx), approval.Principal(), identity.PermissionManageAdvisoryExceptions, id); err != nil {
		return nil, mapErr(err)
	}
	out, err := s.advisories.Accept(ctx, tx, actor.ID, req.Msg)
	if err != nil {
		return nil, advisoryError(err)
	}
	if err := s.identity.LockAuthorization(ctx, tx, approval, identity.PermissionManageAdvisoryExceptions); err != nil {
		return nil, executionError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return noStore(out), nil
}

func advisoryError(err error) error {
	switch {
	case errors.Is(err, advisory.ErrNotFound):
		return errNotFound
	case errors.Is(err, advisory.ErrInvalid):
		return invalid("invalid_advisory_request")
	case errors.Is(err, advisory.ErrConflict):
		return rpcError(connect.CodeAborted, "advisory_evidence_changed")
	case errors.Is(err, advisory.ErrCapacity):
		return rpcError(connect.CodeResourceExhausted, "advisory_capacity")
	default:
		return mapErr(err)
	}
}
