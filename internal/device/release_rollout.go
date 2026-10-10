package device

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	releasemanagementv1 "lindm/gen/lindm/releasemanagement/v1"
	updatev1 "lindm/gen/lindm/update/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

func (s *Service) GetRollout(ctx context.Context, req *connect.Request[releasemanagementv1.GetRolloutRequest]) (*connect.Response[releasemanagementv1.GetRolloutResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	if _, err := s.requireUnrestricted(ctx, identity.PermissionManageReleaseUpdates); err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_rollout_request")
	}
	if s.releasePublisher == nil {
		return nil, rpcError(connect.CodeFailedPrecondition, "release_publisher_unconfigured")
	}
	channel, err := s.releasePublisher.Channel(ctx, req.Msg.GetRing())
	if err != nil {
		return nil, rpcError(connect.CodeUnavailable, "release_catalog_unavailable")
	}
	response := &releasemanagementv1.GetRolloutResponse{Channel: channel}
	pending, err := devicedb.New(s.pool).GetPendingReleaseRollout(ctx, req.Msg.GetRing())
	if err == nil {
		response.PendingRequestId = pending.String()
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, mapErr(err)
	}
	return noStore(response), nil
}

// SetRollout first commits the authorized intent and audit. Publication is a
// separately fenced external effect; a failed/crashed call leaves a truthful
// pending intent. Retrying the same actor/request ID reconciles the signed
// publication token, never claims that a database flag proves publication.
func (s *Service) SetRollout(ctx context.Context, req *connect.Request[releasemanagementv1.SetRolloutRequest]) (*connect.Response[releasemanagementv1.SetRolloutResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	actor, err := s.requireUnrestricted(ctx, identity.PermissionManageReleaseUpdates)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_rollout_request")
	}
	if s.releasePublisher == nil {
		return nil, rpcError(connect.CodeFailedPrecondition, "release_publisher_unconfigured")
	}
	digest, err := actionDigest(req.Msg)
	if err != nil {
		return nil, mapErr(err)
	}
	id, _ := uuid.Parse(req.Msg.GetRequestId())
	err = s.withinUnrestrictedAuthorization(ctx, actor, identity.PermissionManageReleaseUpdates, func(ctx context.Context, q *devicedb.Queries) error {
		if err := q.LockReleaseControl(ctx); err != nil {
			return err
		}
		row, err := q.GetReleaseRollout(ctx, id)
		if err == nil {
			if row.ActorID != actor.ID || !digestEqual(row.RequestDigest, digest) {
				return errIdempotencyConflict
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if _, err := q.GetPendingReleaseRollout(ctx, req.Msg.GetRing()); err == nil {
			return rpcError(connect.CodeAborted, "release_rollout_pending")
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		channel, err := s.releasePublisher.Channel(ctx, req.Msg.GetRing())
		if err != nil {
			return rpcError(connect.CodeUnavailable, "release_catalog_unavailable")
		}
		if channel.GetGeneration() != req.Msg.GetExpectedGeneration() {
			return rpcError(connect.CodeAborted, "release_generation_conflict")
		}
		if err := q.InsertReleaseRollout(ctx, devicedb.InsertReleaseRolloutParams{RequestID: id, ActorID: actor.ID, RequestDigest: digest, Ring: req.Msg.GetRing(), ExpectedGeneration: int64(req.Msg.GetExpectedGeneration()), Paused: req.Msg.GetPaused(), EligiblePercentage: int32(req.Msg.GetEligiblePercentage()), Reason: req.Msg.GetReason()}); err != nil {
			return err
		}
		return insertAudit(ctx, q, &actor.ID, "release.rollout.request", id.String(), req.Msg.GetReason())
	})
	if err != nil {
		return nil, mapErr(err)
	}
	var published *updatev1.AgentUpdateChannel
	err = s.withinUnrestrictedAuthorization(ctx, actor, identity.PermissionManageReleaseUpdates, func(ctx context.Context, q *devicedb.Queries) error {
		if err := q.LockReleaseControl(ctx); err != nil {
			return err
		}
		row, err := q.GetReleaseRollout(ctx, id)
		if err != nil {
			return err
		}
		if row.ActorID != actor.ID || !digestEqual(row.RequestDigest, digest) {
			return errIdempotencyConflict
		}
		if row.PublishedChannel != nil {
			published = new(updatev1.AgentUpdateChannel)
			return proto.Unmarshal(row.PublishedChannel, published)
		}
		published, err = s.releasePublisher.SetRolloutRequest(ctx, row.Ring, row.Paused, uint32(row.EligiblePercentage), uint64(row.ExpectedGeneration), row.RequestID.String())
		if err != nil {
			return rpcError(connect.CodeUnavailable, "release_publication_pending")
		}
		encoded, err := proto.Marshal(published)
		if err != nil {
			return err
		}
		if err := q.CompleteReleaseRollout(ctx, devicedb.CompleteReleaseRolloutParams{RequestID: id, PublishedChannel: encoded}); err != nil {
			return err
		}
		return insertAudit(ctx, q, &actor.ID, "release.rollout.published", id.String(), row.Reason)
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return noStore(&releasemanagementv1.SetRolloutResponse{Channel: published}), nil
}
