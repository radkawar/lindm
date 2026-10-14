// SPDX-License-Identifier: Apache-2.0

package targeting

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/auditkind"
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
	// A rollout awaiting approval has no frozen stage yet.
	stage, err := q.GetRolloutStage(ctx, targetingdb.GetRolloutStageParams{RolloutID: id, RingIndex: row.RingIndex})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
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
	if !row.Paused && int(row.RingIndex)+1 < len(spec.Rings) {
		state.PromotionReady = ready
	}
	if !row.Paused && !ring.ManualPromotion && int(row.RingIndex)+1 < len(spec.Rings) {
		state.NextPromotionAt = timestamppb.New(row.StageStartedAt.Time.Add(time.Duration(ring.SoakSeconds) * time.Second))
	}
	if err := planState(ctx, q, row, state); err != nil {
		return nil, err
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
	if ok, err := receipt(ctx, q, p, r.RequestId, auditkind.TargetingRolloutPut, r, out); ok || err != nil {
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
	count, err := q.InsertRollout(ctx, targetingdb.InsertRolloutParams{ID: id, Definition: b, CreatorID: p.ID, StageStartedAt: pgtype.Timestamptz{Time: now, Valid: true}, Name: rolloutName(r.Rollout)})
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
	return out, saveReceipt(ctx, q, p, r.RequestId, auditkind.TargetingRolloutPut, id.String(), r.Reason, "", r, out)
}

type member struct {
	id         uuid.UUID
	generation *uuid.UUID
	bucket     uint32
	match      policyv1.TargetMatch
}

func (s *Store) freezeStage(ctx context.Context, q *targetingdb.Queries, p identity.Principal, perm identity.Permission, spec *policyv1.RolloutSpec, index int32) error {
	if err := unrestricted(p, perm); err != nil {
		return err
	}
	ring := spec.Rings[index]
	id := uuid.MustParse(spec.RolloutId)
	members, excludedCount, err := s.collectStageMembers(ctx, q, spec, index)
	if err != nil {
		return err
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
	batch := make([]targetingdb.InsertRolloutMemberParams, 0, 200)
	for _, m := range members {
		batch = append(batch, targetingdb.InsertRolloutMemberParams{RolloutID: id, RingIndex: index, DeviceID: m.id, GenerationID: m.generation, Bucket: int32(m.bucket), Membership: int16(m.match)})
		if len(batch) == cap(batch) {
			if _, err := q.InsertRolloutMember(ctx, batch); err != nil {
				return err
			}
			batch = batch[:0]
		}
	}
	if len(batch) > 0 {
		if _, err := q.InsertRolloutMember(ctx, batch); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) collectStageMembers(ctx context.Context, q *targetingdb.Queries, spec *policyv1.RolloutSpec, index int32) ([]member, int32, error) {
	ring := spec.Rings[index]
	if ring.Cohort.GetDynamicGroupId() == "" {
		return collectDirectStageMembers(ctx, q, spec, ring.Cohort)
	}
	id := uuid.MustParse(spec.RolloutId)
	after := uuid.Nil
	members := make([]member, 0)
	var excludedCount int32
	for {
		devices, err := q.ListRolloutDevicePage(ctx, after)
		if err != nil {
			return nil, 0, err
		}
		// Dynamic membership retains the clock and every inventory input.
		now, err := q.TargetingClock(ctx)
		if err != nil {
			return nil, 0, err
		}
		for _, device := range devices {
			e, err := evaluationFromDevice(q, targetingdb.TargetingDeviceRow(device), now.Time)
			if err != nil {
				return nil, 0, err
			}
			match, err := e.target(ctx, ring.Cohort)
			if err != nil {
				return nil, 0, err
			}
			if match == unknown {
				return nil, 0, ErrNotReady
			}
			if match == excluded || e.input.Device.State != "active" {
				excludedCount++
				match = excluded
			} else {
				match = unknown
			}
			members = append(members, member{id: device.ID, generation: e.input.Device.CurrentGenerationID, bucket: Bucket(id, spec.Salt, device.ID), match: match})
			if len(members) > 10000 {
				return nil, 0, ErrCapacity
			}
			after = device.ID
		}
		if len(devices) < 200 {
			break
		}
	}
	return members, excludedCount, nil
}

// Direct device/static-group membership depends only on identity, state and the
// static membership relation, not metadata or observation freshness. The caller
// still requires unrestricted authority and retains every excluded fleet row.
func collectDirectStageMembers(ctx context.Context, q *targetingdb.Queries, spec *policyv1.RolloutSpec, cohort *policyv1.TargetRef) ([]member, int32, error) {
	id := uuid.MustParse(spec.RolloutId)
	params := targetingdb.ListRolloutMembershipPageParams{AfterID: uuid.Nil, DeviceTarget: cohort.GetDeviceId() != ""}
	if params.DeviceTarget {
		params.DeviceID = uuid.MustParse(cohort.GetDeviceId())
	} else {
		params.GroupID = uuid.MustParse(cohort.GetStaticGroupId())
	}
	members := make([]member, 0)
	var excludedCount int32
	for {
		devices, err := q.ListRolloutMembershipPage(ctx, params)
		if err != nil {
			return nil, 0, err
		}
		for _, device := range devices {
			match := unknown
			if !device.Eligible {
				match = excluded
				excludedCount++
			}
			members = append(members, member{id: device.ID, generation: device.CurrentGenerationID, bucket: Bucket(id, spec.Salt, device.ID), match: match})
			if len(members) > 10000 {
				return nil, 0, ErrCapacity
			}
			params.AfterID = device.ID
		}
		if len(devices) < 200 {
			break
		}
	}
	return members, excludedCount, nil
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
	if ok, err := receipt(ctx, q, p, r.RequestId, auditkind.TargetingRolloutControl, r, out); ok || err != nil {
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
	if err := planControlAllowed(ctx, q, id); err != nil {
		return nil, err
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
			return out, saveReceipt(ctx, q, p, r.RequestId, auditkind.TargetingRolloutControl, id.String(), auditReason, auditContext, r, out)
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
	return out, saveReceipt(ctx, q, p, r.RequestId, auditkind.TargetingRolloutControl, id.String(), auditReason, auditContext, r, out)
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
	ids, err := q.ListRollouts(ctx, targetingdb.ListRolloutsParams{AfterID: after, NameSearch: r.NameSearch, RowLimit: int32(r.PageSize)})
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

// rolloutName is the rollout's searchable name, as the console shows it: its
// own name, or for an unnamed rollout its ring names in order. Ring names are
// required and unique, so it is never empty.
func rolloutName(spec *policyv1.RolloutSpec) string {
	if spec.GetName() != "" {
		return spec.GetName()
	}
	names := make([]string, len(spec.GetRings()))
	for i, ring := range spec.GetRings() {
		names[i] = ring.GetName()
	}
	return strings.Join(names, ", ")
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
