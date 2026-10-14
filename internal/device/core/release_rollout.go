// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	releasemanagementv1 "lindm/gen/lindm/releasemanagement/v1"
	updatev1 "lindm/gen/lindm/update/v1"
	"lindm/internal/auditkind"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

func (s *Service) GetRollout(ctx context.Context, req *connect.Request[releasemanagementv1.GetRolloutRequest]) (*connect.Response[releasemanagementv1.GetRolloutResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
	if _, err := s.RequireUnrestricted(ctx, identity.PermissionManageReleaseUpdates); err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, Invalid("invalid_rollout_request")
	}
	if s.ReleasePublisher == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "release_publisher_unconfigured")
	}
	channel, err := s.ReleasePublisher.Channel(ctx, req.Msg.GetRing())
	if err != nil {
		return nil, rpcreason.Error(connect.CodeUnavailable, "release_catalog_unavailable")
	}
	response := &releasemanagementv1.GetRolloutResponse{Channel: channel}
	pending, err := devicedb.New(s.Pool).GetPendingReleaseRollout(ctx, req.Msg.GetRing())
	if err == nil {
		response.PendingRequestId = pending.String()
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, MapErr(err)
	}
	return NoStore(response), nil
}

// SetRollout first commits the authorized intent and audit. Publication is a
// separately fenced external effect; a failed/crashed call leaves a truthful
// pending intent. Retrying the same actor/request ID reconciles the signed
// publication token, never claims that a database flag proves publication.
func (s *Service) SetRollout(ctx context.Context, req *connect.Request[releasemanagementv1.SetRolloutRequest]) (*connect.Response[releasemanagementv1.SetRolloutResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
	actor, err := s.RequireUnrestricted(ctx, identity.PermissionManageReleaseUpdates)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, Invalid("invalid_rollout_request")
	}
	if s.ReleasePublisher == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "release_publisher_unconfigured")
	}
	digest, err := ActionDigest(req.Msg)
	if err != nil {
		return nil, MapErr(err)
	}
	id, _ := uuid.Parse(req.Msg.GetRequestId())
	err = s.WithinUnrestrictedAuthorization(ctx, actor, identity.PermissionManageReleaseUpdates, func(ctx context.Context, q *devicedb.Queries) error {
		if err := q.LockReleaseControl(ctx); err != nil {
			return err
		}
		row, err := q.GetReleaseRollout(ctx, id)
		if err == nil {
			if row.ActorID != actor.ID || !DigestEqual(row.RequestDigest, digest) {
				return ErrIdempotencyConflict
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if _, err := q.GetPendingReleaseRollout(ctx, req.Msg.GetRing()); err == nil {
			return rpcreason.Error(connect.CodeAborted, "release_rollout_pending")
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		channel, err := s.ReleasePublisher.Channel(ctx, req.Msg.GetRing())
		if err != nil {
			return rpcreason.Error(connect.CodeUnavailable, "release_catalog_unavailable")
		}
		if channel.GetGeneration() != req.Msg.GetExpectedGeneration() {
			return rpcreason.Error(connect.CodeAborted, "release_generation_conflict")
		}
		if err := q.InsertReleaseRollout(ctx, devicedb.InsertReleaseRolloutParams{RequestID: id, ActorID: actor.ID, RequestDigest: digest, Ring: req.Msg.GetRing(), ExpectedGeneration: int64(req.Msg.GetExpectedGeneration()), Paused: req.Msg.GetPaused(), EligiblePercentage: int32(req.Msg.GetEligiblePercentage()), Reason: req.Msg.GetReason()}); err != nil {
			return err
		}
		return InsertAudit(ctx, q, &actor.ID, auditkind.ReleaseRolloutRequest, id.String(), req.Msg.GetReason())
	})
	if err != nil {
		return nil, MapErr(err)
	}
	var published *updatev1.AgentUpdateChannel
	err = s.WithinUnrestrictedAuthorization(ctx, actor, identity.PermissionManageReleaseUpdates, func(ctx context.Context, q *devicedb.Queries) error {
		if err := q.LockReleaseControl(ctx); err != nil {
			return err
		}
		row, err := q.GetReleaseRollout(ctx, id)
		if err != nil {
			return err
		}
		if row.ActorID != actor.ID || !DigestEqual(row.RequestDigest, digest) {
			return ErrIdempotencyConflict
		}
		if row.PublishedChannel != nil {
			published = new(updatev1.AgentUpdateChannel)
			return proto.Unmarshal(row.PublishedChannel, published)
		}
		published, err = s.ReleasePublisher.SetRolloutRequest(ctx, row.Ring, row.Paused, uint32(row.EligiblePercentage), uint64(row.ExpectedGeneration), row.RequestID.String())
		if err != nil {
			return rpcreason.Error(connect.CodeUnavailable, "release_publication_pending")
		}
		encoded, err := proto.Marshal(published)
		if err != nil {
			return err
		}
		if err := q.CompleteReleaseRollout(ctx, devicedb.CompleteReleaseRolloutParams{RequestID: id, PublishedChannel: encoded}); err != nil {
			return err
		}
		return InsertAudit(ctx, q, &actor.ID, auditkind.ReleaseRolloutPublished, id.String(), row.Reason)
	})
	if err != nil {
		return nil, MapErr(err)
	}
	return NoStore(&releasemanagementv1.SetRolloutResponse{Channel: published}), nil
}
