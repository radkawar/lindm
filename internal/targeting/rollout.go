package targeting

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/identity"
	"lindm/internal/targeting/targetingdb"
)

// The durable GetSyncState heartbeat runs every 60 seconds with 10% jitter.
// Allow two maximum intervals plus request/network margin before declaring a
// member unavailable. This floor never extends native verification validity.
const rolloutAvailabilityMinAge = 3 * time.Minute

// Bucket binds immutable UUID bytes and a fixed-length salt, not generation,
// display names, database row order or mutable campaign revision.
func Bucket(campaign uuid.UUID, salt []byte, device uuid.UUID) uint32 {
	h := sha256.New()
	_, _ = h.Write([]byte("lindm.rollout.bucket.v1\x00"))
	_, _ = h.Write(campaign[:])
	_, _ = h.Write(salt)
	_, _ = h.Write(device[:])
	sum := h.Sum(nil)
	var bucket uint32
	for _, b := range sum {
		bucket = (bucket*256 + uint32(b)) % 10000
	}
	return bucket
}
func (s *Store) rolloutState(ctx context.Context, q *targetingdb.Queries, id uuid.UUID) (*adminv1.RolloutState, error) {
	row, err := q.GetRollout(ctx, id)
	if err != nil {
		return nil, err
	}
	spec := new(policyv1.RolloutSpec)
	if err := proto.Unmarshal(row.Definition, spec); err != nil {
		return nil, err
	}
	stage, err := q.GetRolloutStage(ctx, targetingdb.GetRolloutStageParams{RolloutID: id, RingIndex: row.RingIndex})
	if err != nil {
		return nil, err
	}
	counts, now, err := s.rolloutHealth(ctx, q, row, spec.Rings[row.RingIndex])
	if err != nil {
		return nil, err
	}
	ready, reason := assessRolloutGate(spec.Rings[row.RingIndex], counts, row.StageStartedAt.Time, now)
	state := &adminv1.RolloutState{
		Rollout: spec, Revision: uint64(row.Revision), RingIndex: uint32(row.RingIndex),
		Paused: row.Paused, PauseReason: row.PauseReason, SelectedCount: uint32(stage.SelectedCount),
		PendingCount: uint32(stage.PendingCount), ExcludedCount: uint32(stage.ExcludedCount),
		StageStartedAt: timestamppb.New(row.StageStartedAt.Time),
		HealthyCount:   uint32(counts.Healthy), FailedCount: uint32(counts.Failed),
		UnknownCount:     uint32(counts.Targeted - counts.Healthy - counts.Failed - counts.Unavailable),
		UnavailableCount: uint32(counts.Unavailable), GateReason: reason,
	}
	ring := spec.Rings[row.RingIndex]
	if !row.Paused && !ring.ManualPromotion && int(row.RingIndex)+1 < len(spec.Rings) {
		state.NextPromotionAt = timestamppb.New(row.StageStartedAt.Time.Add(time.Duration(ring.SoakSeconds) * time.Second))
		state.PromotionReady = ready
	}
	return state, nil
}
func (s *Store) PutRollout(ctx context.Context, tx pgx.Tx, p identity.Principal, perm identity.Permission, r *adminv1.PutRolloutRequest) (*adminv1.PutRolloutResponse, error) {
	if err := s.validate(r); err != nil {
		return nil, err
	}
	for i, ring := range r.Rollout.Rings {
		if i > 0 && ring.CumulativeBasisPoints < r.Rollout.Rings[i-1].CumulativeBasisPoints {
			return nil, ErrRejected
		}
	}
	q, err := begin(ctx, tx, p, perm, true)
	if err != nil {
		return nil, err
	}
	out := new(adminv1.PutRolloutResponse)
	if ok, err := receipt(ctx, q, p, r.RequestId, "targeting.rollout.put", r, out); ok || err != nil {
		return out, err
	}
	for _, ring := range r.Rollout.Rings {
		if err := checkTarget(ctx, q, ring.Cohort); err != nil {
			return nil, err
		}
	}
	b, err := encodedCatalog(r.Rollout)
	if err != nil {
		return nil, err
	}
	now, err := s.rolloutClock(ctx, q)
	if err != nil {
		return nil, err
	}
	id := uuid.MustParse(r.Rollout.RolloutId)
	count, err := q.InsertRollout(ctx, targetingdb.InsertRolloutParams{ID: id, Definition: b, CreatorID: p.ID, StageStartedAt: pgtype.Timestamptz{Time: now, Valid: true}})
	if err != nil {
		return nil, err
	}
	if count != 1 {
		return nil, ErrConflict
	}
	if err := s.freezeStage(ctx, q, p, perm, r.Rollout, 0); err != nil {
		return nil, err
	}
	out.Rollout, err = s.rolloutState(ctx, q, id)
	if err != nil {
		return nil, err
	}
	return out, saveReceipt(ctx, q, p, r.RequestId, "targeting.rollout.put", id.String(), r.Reason, "", r, out)
}

type member struct {
	id         uuid.UUID
	generation *uuid.UUID
	bucket     uint32
	match      policyv1.TargetMatch
}

func (s *Store) freezeStage(ctx context.Context, q *targetingdb.Queries, p identity.Principal, perm identity.Permission, spec *policyv1.RolloutSpec, index int32) error {
	ring := spec.Rings[index]
	id := uuid.MustParse(spec.RolloutId)
	after := uuid.Nil
	members := make([]member, 0)
	var excludedCount int32
	for {
		ids, err := q.ListTargetingDevices(ctx, after)
		if err != nil {
			return err
		}
		for _, deviceID := range ids {
			e, err := loadEvaluation(ctx, q, p, perm, deviceID)
			if err != nil {
				return err
			}
			match, err := e.target(ctx, ring.Cohort)
			if err != nil {
				return err
			}
			if match == unknown {
				return ErrNotReady
			}
			if match == excluded || e.input.Device.State != "active" {
				excludedCount++
				match = excluded
			} else {
				match = unknown
			}
			members = append(members, member{id: deviceID, generation: e.input.Device.CurrentGenerationID, bucket: Bucket(id, spec.Salt, deviceID), match: match})
			if len(members) > 10000 {
				return ErrCapacity
			}
			after = deviceID
		}
		if len(ids) < 200 {
			break
		}
	}
	slices.SortFunc(members, func(a, b member) int {
		if a.bucket < b.bucket {
			return -1
		}
		if a.bucket > b.bucket {
			return 1
		}
		return slices.Compare(a.id[:], b.id[:])
	})
	var selected int32
	for i := range members {
		if members[i].match == excluded {
			continue
		}
		if members[i].bucket < ring.CumulativeBasisPoints || selected < int32(ring.MinimumCanaries) {
			members[i].match = included
			selected++
		}
	}
	// Empty and undersized cohorts are explicit failures, not a successful canary.
	if selected < int32(ring.MinimumCanaries) || selected < int32(ring.MinimumObserved) {
		return ErrNotReady
	}
	if err := q.InsertRolloutStage(ctx, targetingdb.InsertRolloutStageParams{RolloutID: id, RingIndex: index, SelectedCount: selected, PendingCount: int32(len(members)) - selected - excludedCount, ExcludedCount: excludedCount}); err != nil {
		return err
	}
	for _, m := range members {
		if err := q.InsertRolloutMember(ctx, targetingdb.InsertRolloutMemberParams{RolloutID: id, RingIndex: index, DeviceID: m.id, GenerationID: m.generation, Bucket: int32(m.bucket), Membership: int16(m.match)}); err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) assess(ctx context.Context, q *targetingdb.Queries, id uuid.UUID) (bool, string, error) {
	row, err := q.GetRollout(ctx, id)
	if err != nil {
		return false, "", err
	}
	spec := new(policyv1.RolloutSpec)
	if err := proto.Unmarshal(row.Definition, spec); err != nil {
		return false, "", err
	}
	counts, now, err := s.rolloutHealth(ctx, q, row, spec.Rings[row.RingIndex])
	if err != nil {
		return false, "", err
	}
	ready, reason := assessRolloutGate(spec.Rings[row.RingIndex], counts, row.StageStartedAt.Time, now)
	return ready, reason, nil
}

// Database time is shared across replicas. A constructor-injected clock makes
// gate boundaries deterministic in tests without weakening production HA time.
func (s *Store) rolloutClock(ctx context.Context, q *targetingdb.Queries) (time.Time, error) {
	if s.clock != nil {
		return s.clock(), nil
	}
	now, err := q.TargetingClock(ctx)
	return now.Time, err
}

func (s *Store) rolloutHealth(ctx context.Context, q *targetingdb.Queries, row targetingdb.ResourceRollout, ring *policyv1.RolloutRing) (targetingdb.RolloutHealthCountsRow, time.Time, error) {
	now, err := s.rolloutClock(ctx, q)
	if err != nil {
		return targetingdb.RolloutHealthCountsRow{}, time.Time{}, err
	}
	proofMaxAge := time.Duration(ring.HealthMaxAgeSeconds) * time.Second
	availabilityMaxAge := max(proofMaxAge, rolloutAvailabilityMinAge)
	counts, err := q.RolloutHealthCounts(ctx, targetingdb.RolloutHealthCountsParams{
		RolloutID: row.ID, RingIndex: row.RingIndex,
		FreshAfter:        pgtype.Timestamptz{Time: now.Add(-proofMaxAge), Valid: true},
		AvailabilityAfter: pgtype.Timestamptz{Time: now.Add(-availabilityMaxAge), Valid: true},
		AssessedAt:        pgtype.Timestamptz{Time: now, Valid: true},
	})
	return counts, now, err
}

func assessRolloutGate(ring *policyv1.RolloutRing, counts targetingdb.RolloutHealthCountsRow, started, now time.Time) (bool, string) {
	unknownCount := counts.Targeted - counts.Healthy - counts.Failed - counts.Unavailable
	soaked := !now.Before(started.Add(time.Duration(ring.SoakSeconds) * time.Second))
	reason := ""
	if counts.Failed*10000 > counts.Targeted*int64(ring.FailureBasisPoints) {
		reason = "failure_threshold"
	} else if counts.Unavailable*10000 > counts.Targeted*int64(ring.UnavailableBasisPoints) {
		reason = "unavailable_threshold"
	} else if soaked && unknownCount*10000 > counts.Targeted*int64(ring.UnknownBasisPoints) {
		reason = "unknown_threshold"
	}
	return soaked && counts.CurrentHealthy >= int64(ring.MinimumObserved) && reason == "", reason
}

// RefreshRollout evaluates native receipt freshness separately from authenticated
// contact availability over cumulative admitted devices, deduplicated by latest
// selected stage. Promotion additionally requires the current ring's own observed
// minimum. Unknown budget begins after initial soak. The caller MUST commit an
// automatic pause even when denying a subsequent grant.
func (s *Store) RefreshRollout(ctx context.Context, tx pgx.Tx, id uuid.UUID) (bool, error) {
	q := targetingdb.New(tx)
	if err := q.LockTargeting(ctx); err != nil {
		return false, err
	}
	row, err := q.GetRollout(ctx, id)
	if err != nil {
		return false, err
	}
	if row.Paused {
		return false, nil
	}
	ready, reason, err := s.assess(ctx, q, id)
	if err != nil {
		return false, err
	}
	if reason == "" {
		return ready, nil
	}
	return false, pauseRollout(ctx, q, row, reason)
}
func (s *Store) ControlRollout(ctx context.Context, tx pgx.Tx, p identity.Principal, perm identity.Permission, r *adminv1.ControlRolloutRequest) (*adminv1.ControlRolloutResponse, error) {
	return s.controlRollout(ctx, tx, p, perm, r, false)
}

func (s *Store) controlRollout(ctx context.Context, tx pgx.Tx, p identity.Principal, perm identity.Permission, r *adminv1.ControlRolloutRequest, automatic bool) (*adminv1.ControlRolloutResponse, error) {
	auditReason, auditContext := r.GetReason(), ""
	if automatic {
		auditReason, auditContext = "", r.GetReason()
	}
	if err := s.validate(r); err != nil {
		return nil, err
	}
	q, err := begin(ctx, tx, p, perm, true)
	if err != nil {
		return nil, err
	}
	out := new(adminv1.ControlRolloutResponse)
	if ok, err := receipt(ctx, q, p, r.RequestId, "targeting.rollout.control", r, out); ok || err != nil {
		return out, err
	}
	id := uuid.MustParse(r.RolloutId)
	row, err := q.GetRollout(ctx, id)
	if err != nil {
		return nil, err
	}
	if uint64(row.Revision) != r.ExpectedRevision {
		return nil, ErrConflict
	}
	spec := new(policyv1.RolloutSpec)
	if err := proto.Unmarshal(row.Definition, spec); err != nil {
		return nil, err
	}
	paused, reason, index, started := row.Paused, row.PauseReason, row.RingIndex, row.StageStartedAt
	switch r.Operation {
	case adminv1.ControlRolloutRequest_OPERATION_PAUSE:
		paused = true
		reason = r.Reason
	case adminv1.ControlRolloutRequest_OPERATION_RESUME:
		_, why, err := s.assess(ctx, q, id)
		if err != nil {
			return nil, err
		}
		if why != "" {
			return nil, ErrNotReady
		}
		paused = false
		reason = ""
	case adminv1.ControlRolloutRequest_OPERATION_PROMOTE:
		if paused {
			return nil, ErrPaused
		}
		ready, why, err := s.assess(ctx, q, id)
		if err != nil {
			return nil, err
		}
		if why != "" {
			if _, err := s.RefreshRollout(ctx, tx, id); err != nil {
				return nil, err
			}
			out.Rollout, err = s.rolloutState(ctx, q, id)
			if err != nil {
				return nil, err
			}
			return out, saveReceipt(ctx, q, p, r.RequestId, "targeting.rollout.control", id.String(), auditReason, auditContext, r, out)
		}
		if !ready {
			return nil, ErrNotReady
		}
		if int(index)+1 >= len(spec.Rings) {
			return nil, ErrNotReady
		}
		index++
		if err := s.freezeStage(ctx, q, p, perm, spec, index); err != nil {
			return nil, err
		}
		now, err := s.rolloutClock(ctx, q)
		if err != nil {
			return nil, err
		}
		started = pgtype.Timestamptz{Time: now, Valid: true}
	default:
		return nil, ErrRejected
	}
	count, err := q.UpdateRollout(ctx, targetingdb.UpdateRolloutParams{ID: id, RingIndex: index, Paused: paused, PauseReason: reason, StageStartedAt: started, ExpectedRevision: row.Revision})
	if err != nil {
		return nil, err
	}
	if count != 1 {
		return nil, ErrConflict
	}
	actor := p.ID
	if err = q.InsertRolloutEvent(ctx, targetingdb.InsertRolloutEventParams{ID: uuid.New(), RolloutID: id, Revision: row.Revision + 1, ActorID: &actor, Reason: r.Reason}); err != nil {
		return nil, err
	}
	out.Rollout, err = s.rolloutState(ctx, q, id)
	if err != nil {
		return nil, err
	}
	return out, saveReceipt(ctx, q, p, r.RequestId, "targeting.rollout.control", id.String(), auditReason, auditContext, r, out)
}
func (s *Store) ListRollouts(ctx context.Context, tx pgx.Tx, p identity.Principal, perm identity.Permission, r *adminv1.ListRolloutsRequest) (*adminv1.ListRolloutsResponse, error) {
	if err := s.validate(r); err != nil {
		return nil, err
	}
	q, err := beginRead(tx, p, perm, true)
	if err != nil {
		return nil, err
	}
	after := uuid.Nil
	if r.AfterId != nil {
		after = uuid.MustParse(*r.AfterId)
	}
	ids, err := q.ListRollouts(ctx, targetingdb.ListRolloutsParams{AfterID: after, RowLimit: int32(r.PageSize)})
	if err != nil {
		return nil, err
	}
	out := new(adminv1.ListRolloutsResponse)
	for _, id := range ids {
		state, err := s.rolloutState(ctx, q, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		out.Rollouts = append(out.Rollouts, state)
	}
	return out, nil
}

// PromoteAutomatic shares the same CAS, frozen-cohort and audit path as manual
// promotion. A caller must obtain fresh campaign authority before invoking it.
func (s *Store) PromoteAutomatic(ctx context.Context, tx pgx.Tx, p identity.Principal, perm identity.Permission, id uuid.UUID) (*adminv1.RolloutState, error) {
	q, err := begin(ctx, tx, p, perm, true)
	if err != nil {
		return nil, err
	}
	state, err := s.rolloutState(ctx, q, id)
	if err != nil {
		return nil, err
	}
	if state.Rollout.Rings[state.RingIndex].ManualPromotion {
		return nil, ErrNotReady
	}
	out, err := s.controlRollout(ctx, tx, p, perm, &adminv1.ControlRolloutRequest{RequestId: uuid.NewString(), RolloutId: id.String(), ExpectedRevision: state.Revision, Operation: adminv1.ControlRolloutRequest_OPERATION_PROMOTE, Reason: "Automatic promotion after verified health and soak"}, true)
	if err != nil {
		return nil, err
	}
	return out.Rollout, nil
}
