// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"errors"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/advisory"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

func (s *Service) ListDeviceFindings(ctx context.Context, req *connect.Request[adminv1.ListDeviceFindingsRequest]) (*connect.Response[adminv1.ListDeviceFindingsResponse], error) {
	return deviceAdvisoryRead(ctx, s, req, s.Advisories.ListDevice)
}

func (s *Service) ListDeviceUncoveredPackages(ctx context.Context, req *connect.Request[adminv1.ListDeviceUncoveredPackagesRequest]) (*connect.Response[adminv1.ListDeviceUncoveredPackagesResponse], error) {
	return deviceAdvisoryRead(ctx, s, req, s.Advisories.ListUncovered)
}

// deviceAdvisoryRead authorizes one device-scoped advisory read against the
// device's fleet scope, then runs it in a bounded in-flight slot.
func deviceAdvisoryRead[Req any, P interface {
	*Req
	proto.Message
	GetDeviceId() string
}, Resp any](ctx context.Context, s *Service, req *connect.Request[Req], read func(context.Context, P, bool, []byte) (*Resp, error)) (*connect.Response[Resp], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(P(req.Msg)) != nil {
		return nil, core.Invalid("invalid_advisory_request")
	}
	id, err := uuid.Parse(P(req.Msg).GetDeviceId())
	if err != nil {
		return nil, core.Invalid("invalid_id")
	}
	if err := core.RequireDeviceScope(ctx, devicedb.New(s.Pool), actor, identity.PermissionReadFleet, id); err != nil {
		return nil, core.MapErr(err)
	}
	if s.Advisories == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "advisory_unavailable")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	unrestricted, scopes, err := core.DeviceScopeFilter(actor, identity.PermissionReadFleet)
	if err != nil {
		return nil, core.MapErr(err)
	}
	out, err := read(ctx, req.Msg, unrestricted, scopes)
	if err != nil {
		return nil, advisoryError(err)
	}
	return core.NoStore(out), nil
}

func (s *Service) ListAdvisorySummary(ctx context.Context, req *connect.Request[adminv1.ListAdvisorySummaryRequest]) (*connect.Response[adminv1.ListAdvisorySummaryResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_advisory_request")
	}
	unrestricted, scopes, err := core.DeviceScopeFilter(actor, identity.PermissionReadFleet)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if s.Advisories == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "advisory_unavailable")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	out, err := s.Advisories.Summary(ctx, req.Msg, unrestricted, scopes)
	if err != nil {
		return nil, advisoryError(err)
	}
	return core.NoStore(out), nil
}

func (s *Service) ListAdvisoryFeeds(ctx context.Context, req *connect.Request[adminv1.ListAdvisoryFeedsRequest]) (*connect.Response[adminv1.ListAdvisoryFeedsResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	if _, err := s.RequireUnrestricted(ctx, identity.PermissionReadFleet); err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil {
		return nil, core.Invalid("invalid_advisory_request")
	}
	if s.Advisories == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "advisory_unavailable")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	out, err := s.Advisories.Feeds(ctx)
	if err != nil {
		return nil, advisoryError(err)
	}
	return core.NoStore(out), nil
}

func (s *Service) AcceptAdvisoryFinding(ctx context.Context, req *connect.Request[adminv1.AcceptAdvisoryFindingRequest]) (*connect.Response[adminv1.AcceptAdvisoryFindingResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionManageAdvisoryExceptions)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_advisory_request")
	}
	id, err := uuid.Parse(req.Msg.GetDeviceId())
	if err != nil {
		return nil, core.Invalid("invalid_id")
	}
	if err := core.RequireDeviceScope(ctx, devicedb.New(s.Pool), actor, identity.PermissionManageAdvisoryExceptions, id); err != nil {
		return nil, core.MapErr(err)
	}
	if s.Advisories == nil || s.Identity == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "advisory_unavailable")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	approval, err := s.Identity.AuthorizeFresh(ctx, actor.ID, identity.PermissionManageAdvisoryExceptions)
	if err != nil {
		return nil, core.ExecutionError(err)
	}
	consumption, err := s.PrepareActionApproval(ctx, actor, identity.PermissionManageAdvisoryExceptions, req.Msg.GetApprovalId(), req.Msg)
	if err != nil {
		return nil, err
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.LockActionApproval(ctx, tx, consumption, approval, identity.PermissionManageAdvisoryExceptions); err != nil {
		return nil, core.ApprovalError(err)
	}
	if _, err := core.LockMutableDevice(ctx, devicedb.New(tx), approval.Principal(), identity.PermissionManageAdvisoryExceptions, id); err != nil {
		return nil, core.MapErr(err)
	}
	out, err := s.Advisories.Accept(ctx, tx, actor.ID, req.Msg)
	if err != nil {
		return nil, advisoryError(err)
	}
	if err := s.LockActionApproval(ctx, tx, consumption, approval, identity.PermissionManageAdvisoryExceptions); err != nil {
		return nil, core.ApprovalError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	return core.NoStore(out), nil
}

func advisoryError(err error) error {
	switch {
	case errors.Is(err, advisory.ErrNotFound):
		return core.ErrNotFound
	case errors.Is(err, advisory.ErrInvalid):
		return core.Invalid("invalid_advisory_request")
	case errors.Is(err, advisory.ErrConflict):
		return rpcreason.Error(connect.CodeAborted, "advisory_evidence_changed")
	case errors.Is(err, advisory.ErrCapacity):
		return rpcreason.Error(connect.CodeResourceExhausted, "advisory_capacity")
	default:
		return core.MapErr(err)
	}
}
