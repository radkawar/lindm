// SPDX-License-Identifier: Apache-2.0

package targeting

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"

	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/targeting/targetingdb"
)

// RecordExecutionHealth derives health exclusively from accepted native evidence
// for the current assignment and generation. Old-head results cannot overwrite a
// newer campaign. Take the fence before acquiring device/action locks; recording
// rollout health requires an exclusive fence. Healthy evidence
// retains the oldest underlying verification receipt rather than being refreshed
// by reading it, receiving a duplicate result, or updating another resource.
func (s *Store) RecordExecutionHealth(ctx context.Context, tx pgx.Tx, fence DispatchFence, device, generation, assignmentID uuid.UUID) error {
	if err := fence.held(tx); err != nil {
		return err
	}
	q := targetingdb.New(tx)
	row, err := q.GetTargetPreview(ctx, assignmentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if row.DeviceID != device {
		return ErrConflict
	}
	preview := new(policyv1.TargetPreview)
	if err := proto.Unmarshal(row.Document, preview); err != nil {
		return err
	}
	if preview.GenerationId != generation.String() {
		return ErrConflict
	}
	if rolloutBound(preview) && !fence.exclusive {
		return ErrDispatchFence
	}
	seen := make(map[string]bool)
	for _, candidate := range preview.Candidates {
		if candidate.Match != included || candidate.Assignment.RolloutId == nil {
			continue
		}
		campaign := *candidate.Assignment.RolloutId
		if seen[campaign] {
			continue
		}
		seen[campaign] = true
		id := uuid.MustParse(campaign)
		state, err := s.rolloutState(ctx, q, id)
		if err != nil {
			return err
		}
		ring := state.Rollout.Rings[state.RingIndex]
		now, err := q.TargetingClock(ctx)
		if err != nil {
			return err
		}
		health, err := q.CurrentExecutionHealth(ctx, targetingdb.CurrentExecutionHealthParams{AssignmentID: assignmentID, DeviceID: device, GenerationID: generation, FreshAfter: pgtype.Timestamptz{Time: now.Time.Add(-time.Duration(ring.HealthMaxAgeSeconds) * time.Second), Valid: true}})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		received := now
		validUntil := now
		if health.Health == int16(policyv1.RolloutHealth_ROLLOUT_HEALTH_HEALTHY) {
			received = health.OldestVerifiedAt
			validUntil = pgtype.Timestamptz{Time: received.Time.Add(time.Duration(ring.HealthMaxAgeSeconds) * time.Second), Valid: true}
			if health.NativeValidUntil.Valid && health.NativeValidUntil.Time.Before(validUntil.Time) {
				validUntil = health.NativeValidUntil
			}
		}
		if _, err := q.UpdateRolloutExecutionHealth(ctx, targetingdb.UpdateRolloutExecutionHealthParams{RolloutID: id, RingIndex: int32(state.RingIndex), DeviceID: device, GenerationID: &generation, Health: health.Health, ReceivedAt: received, HealthValidUntil: validUntil, EvidenceAssignmentID: &assignmentID}); err != nil {
			return err
		}
		if _, err := s.RefreshRollout(ctx, tx, id); err != nil {
			return err
		}
	}
	return nil
}
