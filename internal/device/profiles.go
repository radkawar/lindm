package device

import (
	"context"
	"encoding/base64"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/identity"
	"lindm/internal/policy"
	"lindm/internal/rpcreason"
)

func (s *Service) PublishProfileRevision(ctx context.Context, req *connect.Request[adminv1.PublishProfileRevisionRequest]) (*connect.Response[adminv1.PublishProfileRevisionResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.requireUnrestricted(ctx, identity.PermissionManageProfiles)
	if err != nil {
		return nil, err
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	if req == nil || req.Msg == nil {
		return nil, invalid("invalid_profile_request")
	}
	if err := s.rules.Validate(req.Msg); err != nil {
		return nil, invalid("invalid_profile_request")
	}
	for _, item := range req.Msg.GetSpec().GetResources() {
		if item.GetOwnership().GetAdoptionApprovalId() != "" {
			return nil, invalid("profile_adoption_approval_must_be_assignment_bound")
		}
	}
	if s.identity == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "profile_authorization_unavailable")
	}
	approval, err := s.identity.AuthorizeFresh(ctx, actor.ID, identity.PermissionManageProfiles)
	if err != nil {
		return nil, executionError(err)
	}
	if err := requireUnrestrictedPrincipal(approval.Principal(), identity.PermissionManageProfiles); err != nil {
		return nil, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.identity.LockAuthorization(ctx, tx, approval, identity.PermissionManageProfiles); err != nil {
		return nil, executionError(err)
	}
	revision, err := s.profiles.Publish(ctx, tx, req.Msg, actor.ID)
	if err != nil {
		return nil, profileError(err)
	}
	if err := s.identity.LockAuthorization(ctx, tx, approval, identity.PermissionManageProfiles); err != nil {
		return nil, executionError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return noStore(&adminv1.PublishProfileRevisionResponse{Revision: revision}), nil
}

func (s *Service) GetProfileRevision(ctx context.Context, req *connect.Request[adminv1.GetProfileRevisionRequest]) (*connect.Response[adminv1.GetProfileRevisionResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	if _, err := s.requireUnrestricted(ctx, identity.PermissionReadFleet); err != nil {
		return nil, err
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	if req == nil || req.Msg == nil {
		return nil, invalid("invalid_profile_request")
	}
	if err := s.rules.Validate(req.Msg); err != nil {
		return nil, invalid("invalid_profile_request")
	}
	id, err := uuid.Parse(req.Msg.GetProfileId())
	if err != nil {
		return nil, invalid("invalid_profile_request")
	}
	var revisionID *uuid.UUID
	if req.Msg.RevisionId != nil {
		value, err := uuid.Parse(req.Msg.GetRevisionId())
		if err != nil {
			return nil, invalid("invalid_profile_request")
		}
		revisionID = &value
	}
	revision, err := s.profiles.Get(ctx, id, revisionID)
	if err != nil {
		return nil, profileError(err)
	}
	return noStore(&adminv1.GetProfileRevisionResponse{Revision: revision}), nil
}

func (s *Service) ListProfiles(ctx context.Context, req *connect.Request[adminv1.ListProfilesRequest]) (*connect.Response[adminv1.ListProfilesResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	if _, err := s.requireUnrestricted(ctx, identity.PermissionReadFleet); err != nil {
		return nil, err
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	if req == nil || req.Msg == nil {
		return nil, invalid("invalid_profile_request")
	}
	if err := s.rules.Validate(req.Msg); err != nil {
		return nil, invalid("invalid_profile_request")
	}
	after, err := decodeProfileCursor(req.Msg.GetPageToken())
	if err != nil {
		return nil, err
	}
	limit := req.Msg.GetPageSize()
	if limit == 0 {
		limit = 50
	}
	rows, next, err := s.profiles.List(ctx, after, int32(limit))
	if err != nil {
		return nil, profileError(err)
	}
	var budget responsePageBudget
	for i, row := range rows {
		fits, err := budget.take(row)
		if err != nil {
			return nil, mapErr(err)
		}
		if !fits {
			if i == 0 {
				return nil, mapErr(errInternalState)
			}
			rows = rows[:i]
			next, err = uuid.Parse(rows[i-1].GetProfileId())
			if err != nil {
				return nil, mapErr(errInternalState)
			}
			break
		}
	}
	return noStore(&adminv1.ListProfilesResponse{Profiles: rows, NextPageToken: encodeProfileCursor(next)}), nil
}

func encodeProfileCursor(id uuid.UUID) string {
	if id == uuid.Nil {
		return ""
	}
	var encoded [17]byte
	encoded[0] = 'P'
	copy(encoded[1:], id[:])
	return base64.RawURLEncoding.EncodeToString(encoded[:])
}

func decodeProfileCursor(token string) (uuid.UUID, error) {
	if token == "" {
		return uuid.Nil, nil
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != 17 || decoded[0] != 'P' {
		return uuid.Nil, invalid("page_token")
	}
	id, err := uuid.FromBytes(decoded[1:])
	if err != nil || id == uuid.Nil {
		return uuid.Nil, invalid("page_token")
	}
	return id, nil
}

func profileError(err error) error {
	switch {
	case errors.Is(err, policy.ErrProfileRejected):
		return invalid("invalid_profile_request")
	case errors.Is(err, policy.ErrProfileConflict):
		return rpcreason.Error(connect.CodeAborted, "profile_revision_conflict")
	case errors.Is(err, policy.ErrProfileNotFound):
		return rpcreason.Error(connect.CodeNotFound, "profile_revision_not_found")
	case errors.Is(err, policy.ErrProfileCorrupt):
		return rpcreason.Error(connect.CodeFailedPrecondition, "profile_recovery_hold")
	case errors.Is(err, policy.ErrProfileCapacity):
		return rpcreason.Error(connect.CodeResourceExhausted, "profile_revision_capacity")
	default:
		return mapErr(err)
	}
}
