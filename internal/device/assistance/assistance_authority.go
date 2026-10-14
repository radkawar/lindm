// SPDX-License-Identifier: Apache-2.0

package assistance

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

// The external identity observation precedes every SQL lock. The device sync
// then fences identity before device/session state; polling alone is not authority.
func (s *Service) observeAssistanceAuthority(ctx context.Context, deviceID uuid.UUID) (uuid.UUID, *identity.Authorization, error) {
	row, err := devicedb.New(s.Pool).GetOpenAssistanceSession(ctx, deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, nil, nil
	}
	if err != nil {
		return uuid.Nil, nil, err
	}
	if s.Identity == nil {
		return row.ID, nil, nil
	}
	authorization, err := s.Identity.AuthorizeFresh(ctx, row.OperatorID, identity.PermissionViewRemoteAssistance)
	if err != nil {
		// Missing or unavailable authority ends the observed session. Never
		// renew it based on a cached operator/browser observation.
		return row.ID, nil, nil
	}
	return row.ID, authorization, nil
}

func (s *Service) refreshAssistanceAuthority(ctx context.Context, q *devicedb.Queries, deviceID, observedID uuid.UUID, authorization *identity.Authorization, now time.Time, revoked *assistanceRevocations) error {
	row, err := q.LockOpenAssistanceSession(ctx, deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if observedID == uuid.Nil || row.ID != observedID {
		// Create won the device lock after the observation. Neither a missing
		// observation nor another session's authority can end or renew it.
		// Sync enforces its existing lease separately; the next sync observes
		// this session afresh.
		return nil
	}
	reason := ""
	switch {
	case authorization == nil || row.OperatorID != authorization.ActorID() || !now.Before(authorization.ExpiresAt()):
		reason = "operator_authorization_lost"
	case !now.Before(row.AuthorizedUntil.Time):
		// A gap cannot resurrect an old portal grant, even if authority returns.
		reason = "operator_authorization_expired"
	default:
		effective := decodeAssistancePolicy(row.EffectiveCapabilities)
		if err := scopeAssistanceCapabilities(ctx, q, authorization.Principal(), deviceID, agentv1.AssistanceMode(row.Mode), effective); err != nil {
			reason = "operator_scope_lost"
		} else {
			policy, err := loadAssistancePolicy(ctx, q, deviceID)
			if err != nil {
				return err
			}
			if !proto.Equal(effective, intersectAssistancePolicy(effective, intersectAssistancePolicy(policy, s.AssistanceCeiling))) {
				reason = "policy_changed"
			}
		}
	}
	if reason != "" {
		return endAssistance(ctx, q, &row, now, nil, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, reason, false, revoked)
	}
	return q.AuthorizeAssistanceSession(ctx, devicedb.AuthorizeAssistanceSessionParams{ID: row.ID, AuthorizedUntil: core.Timestamptz(authorization.ExpiresAt())})
}
