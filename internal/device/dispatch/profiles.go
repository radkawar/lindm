package dispatch

import (
	"context"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

func (s *Service) PublishProfileRevision(ctx context.Context, req *connect.Request[adminv1.PublishProfileRevisionRequest]) (*connect.Response[adminv1.PublishProfileRevisionResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.RequireUnrestricted(ctx, identity.PermissionManageProfiles)
	if err != nil {
		return nil, err
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	if req == nil || req.Msg == nil {
		return nil, core.Invalid("invalid_profile_request")
	}
	if err := s.Rules.Validate(req.Msg); err != nil {
		return nil, core.Invalid("invalid_profile_request")
	}
	for _, item := range req.Msg.GetSpec().GetResources() {
		if item.GetOwnership().GetAdoptionApprovalId() != "" {
			return nil, core.Invalid("profile_adoption_approval_must_be_assignment_bound")
		}
	}
	if s.Identity == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "profile_authorization_unavailable")
	}
	approval, err := s.Identity.AuthorizeFresh(ctx, actor.ID, identity.PermissionManageProfiles)
	if err != nil {
		return nil, core.ExecutionError(err)
	}
	if err := core.RequireUnrestrictedPrincipal(approval.Principal(), identity.PermissionManageProfiles); err != nil {
		return nil, err
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.Identity.LockAuthorization(ctx, tx, approval, identity.PermissionManageProfiles); err != nil {
		return nil, core.ExecutionError(err)
	}
	revision, err := s.Profiles.Publish(ctx, tx, req.Msg, actor.ID)
	if err != nil {
		return nil, core.ProfileError(err)
	}
	if err := s.Identity.LockAuthorization(ctx, tx, approval, identity.PermissionManageProfiles); err != nil {
		return nil, core.ExecutionError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	return core.NoStore(&adminv1.PublishProfileRevisionResponse{Revision: revision}), nil
}

func (s *Service) GetProfileRevision(ctx context.Context, req *connect.Request[adminv1.GetProfileRevisionRequest]) (*connect.Response[adminv1.GetProfileRevisionResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	if _, err := s.RequireUnrestricted(ctx, identity.PermissionReadFleet); err != nil {
		return nil, err
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	if req == nil || req.Msg == nil {
		return nil, core.Invalid("invalid_profile_request")
	}
	if err := s.Rules.Validate(req.Msg); err != nil {
		return nil, core.Invalid("invalid_profile_request")
	}
	id, err := uuid.Parse(req.Msg.GetProfileId())
	if err != nil {
		return nil, core.Invalid("invalid_profile_request")
	}
	var revisionID *uuid.UUID
	if req.Msg.RevisionId != nil {
		value, err := uuid.Parse(req.Msg.GetRevisionId())
		if err != nil {
			return nil, core.Invalid("invalid_profile_request")
		}
		revisionID = &value
	}
	revision, err := s.Profiles.Get(ctx, id, revisionID)
	if err != nil {
		return nil, core.ProfileError(err)
	}
	return core.NoStore(&adminv1.GetProfileRevisionResponse{Revision: revision}), nil
}

func (s *Service) ListProfiles(ctx context.Context, req *connect.Request[adminv1.ListProfilesRequest]) (*connect.Response[adminv1.ListProfilesResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	if _, err := s.RequireUnrestricted(ctx, identity.PermissionReadFleet); err != nil {
		return nil, err
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	if req == nil || req.Msg == nil {
		return nil, core.Invalid("invalid_profile_request")
	}
	if err := s.Rules.Validate(req.Msg); err != nil {
		return nil, core.Invalid("invalid_profile_request")
	}
	after, err := core.DecodeProfileCursor(req.Msg.GetPageToken())
	if err != nil {
		return nil, err
	}
	limit := req.Msg.GetPageSize()
	if limit == 0 {
		limit = 50
	}
	rows, next, err := s.Profiles.List(ctx, after, int32(limit))
	if err != nil {
		return nil, core.ProfileError(err)
	}
	var budget core.ResponsePageBudget
	for i, row := range rows {
		fits, err := budget.Take(row)
		if err != nil {
			return nil, core.MapErr(err)
		}
		if !fits {
			if i == 0 {
				return nil, core.MapErr(core.ErrInternalState)
			}
			rows = rows[:i]
			next, err = uuid.Parse(rows[i-1].GetProfileId())
			if err != nil {
				return nil, core.MapErr(core.ErrInternalState)
			}
			break
		}
	}
	return core.NoStore(&adminv1.ListProfilesResponse{Profiles: rows, NextPageToken: core.EncodeProfileCursor(next)}), nil
}
