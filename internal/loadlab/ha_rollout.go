// SPDX-License-Identifier: Apache-2.0

package loadlab

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/devlab"
)

const (
	haRolloutJobKey            = int64(0x6c696e646d000005)
	haRolloutSoak              = 3 * time.Second
	haAutomaticPromotionReason = "Automatic promotion after verified health and soak"
)

// HARolloutSummary qualifies automatic progress independently of list traffic.
// Only health is synthetic; cohort freezing, soak time, leadership, promotion,
// mutation receipts and audit events come from the running replicas/database.
type HARolloutSummary struct {
	HealthSource string                   `json:"health_source"`
	Leader       string                   `json:"leader_before_kill"`
	Successor    string                   `json:"successor"`
	KilledAt     time.Time                `json:"killed_at"`
	RecoveredAt  time.Time                `json:"recovered_at"`
	SeededAt     []time.Time              `json:"fixture_health_seeded_at"`
	BeforeLoss   devlab.HARolloutEvidence `json:"before_leader_loss"`
	Final        devlab.HARolloutEvidence `json:"final"`
	StableUntil  time.Time                `json:"stable_until"`
}

// rolloutFailover never calls ListRollouts or ControlRollout. Unknown health is
// allowed by the explicit fixture policy, but minimum_observed=1 prevents any
// advancement until that stage's current-generation health has been seeded.
func (h *haRun) rolloutFailover(ctx context.Context, result *HAResult) error {
	return h.phase(ctx, result, "rollout-promoter-failover", 0, func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		summary := &result.Rollout
		summary.HealthSource = "fixture-seeded healthy cohort rows bound to real current assignment heads; availability from simulated authenticated device traffic; real elapsed soak; no native execution claim"
		leader, err := h.waitRolloutLeader(ctx, "")
		if err != nil {
			return err
		}
		summary.Leader = leader
		salt := make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return err
		}
		id := uuid.NewString()
		spec := &policyv1.RolloutSpec{RolloutId: id, Salt: salt}
		for i := range 3 {
			spec.Rings = append(spec.Rings, &policyv1.RolloutRing{
				Name: fmt.Sprintf("ha-%d", i), Cohort: &policyv1.TargetRef{Target: &policyv1.TargetRef_DeviceId{DeviceId: h.devices[0].id}},
				CumulativeBasisPoints: 10000, MinimumCanaries: 1, MinimumObserved: 1,
				SoakSeconds: uint32(haRolloutSoak / time.Second), UnknownBasisPoints: 10000, HealthMaxAgeSeconds: 600,
			})
		}
		if _, err := h.owner.Admin.PutRollout(ctx, connect.NewRequest(&adminv1.PutRolloutRequest{RequestId: uuid.NewString(), Rollout: spec, Reason: "HA automatic rollout leader failover qualification"})); err != nil {
			return fmt.Errorf("create HA rollout: %w", err)
		}
		if err := h.seedRolloutHealth(ctx, summary, id, 0); err != nil {
			return err
		}
		if summary.BeforeLoss, err = h.waitRolloutRing(ctx, id, 1); err != nil {
			return err
		}
		// Stage one has no healthy observation. It cannot complete while we
		// identify and kill the actual lock holder, even if a scan races us.
		current, err := h.waitRolloutLeader(ctx, "")
		if err != nil {
			return err
		}
		if current != leader {
			return errors.New("rollout leader changed before the deliberate fault")
		}
		if err := h.fixture.KillHAInstance(leader); err != nil {
			return err
		}
		summary.KilledAt = time.Now().UTC()
		h.event("kill", leader, "SIGKILL actual rollout-promoter lock holder after first automatic promotion")
		if summary.Successor, err = h.waitRolloutLeader(ctx, leader); err != nil {
			return err
		}
		summary.RecoveredAt = time.Now().UTC()
		if err := h.seedRolloutHealth(ctx, summary, id, 1); err != nil {
			return err
		}
		if summary.Final, err = h.waitRolloutRing(ctx, id, 2); err != nil {
			return err
		}
		if err := h.seedRolloutHealth(ctx, summary, id, 2); err != nil {
			return err
		}
		if err := h.fixture.StartHAInstance(ctx, leader, h.options.UpgradeBinary); err != nil {
			return err
		}
		h.event("start", leader, "rejoin after rollout-promoter failover")
		// Observe both contenders for two normal promoter scan intervals.
		deadline := time.Now().Add(20 * time.Second)
		for {
			summary.Final, err = h.fixture.ReadHARolloutEvidence(ctx, id)
			if err != nil {
				return err
			}
			if err := validateHARolloutPromotions(summary.Final, 2); err != nil {
				return err
			}
			summary.StableUntil = time.Now().UTC()
			if !summary.StableUntil.Before(deadline) {
				return nil
			}
			if err := waitHARolloutPoll(ctx); err != nil {
				return err
			}
		}
	})
}

func (h *haRun) seedRolloutHealth(ctx context.Context, summary *HARolloutSummary, id string, ring int32) error {
	at, err := h.fixture.SeedHARolloutHealth(ctx, id, ring)
	if err != nil {
		return err
	}
	summary.SeededAt = append(summary.SeededAt, at)
	h.event("fixture-health", id, fmt.Sprintf("ring %d synthetic healthy proof; real assignment/generation and heartbeat; soak clock unchanged", ring))
	return nil
}

func waitHARolloutPoll(ctx context.Context) error {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (h *haRun) waitRolloutRing(ctx context.Context, id string, ring int32) (devlab.HARolloutEvidence, error) {
	ctx, cancel := context.WithTimeout(ctx, maxLeadershipGap)
	defer cancel()
	for {
		evidence, err := h.fixture.ReadHARolloutEvidence(ctx, id)
		if err != nil {
			return evidence, err
		}
		if evidence.Paused || evidence.Ring > ring {
			return evidence, fmt.Errorf("unexpected rollout state: ring=%d paused=%t reason=%s", evidence.Ring, evidence.Paused, evidence.Reason)
		}
		if evidence.Ring == ring {
			return evidence, validateHARolloutPromotions(evidence, ring)
		}
		if err := waitHARolloutPoll(ctx); err != nil {
			return evidence, fmt.Errorf("wait automatic promotion to ring %d without list traffic: %w", ring, err)
		}
	}
}

func (h *haRun) waitRolloutLeader(ctx context.Context, excluded string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, maxLeadershipGap)
	defer cancel()
	for {
		holders, err := h.fixture.HALockHolders(ctx)
		if err != nil {
			return "", err
		}
		owner, err := haRolloutLeader(holders, h.fixture.HAInstances())
		if err != nil {
			return "", err
		}
		if owner != "" && owner != excluded {
			return owner, nil
		}
		if err := waitHARolloutPoll(ctx); err != nil {
			return "", fmt.Errorf("wait rollout-promoter leader: %w", err)
		}
	}
}

func haRolloutLeader(holders []devlab.HALockHolder, instances []devlab.HAInstanceState) (string, error) {
	owner := ""
	for _, holder := range holders {
		if holder.Key != haRolloutJobKey {
			continue
		}
		if owner != "" {
			return "", errors.New("multiple rollout-promoter lock holders")
		}
		for _, instance := range instances {
			if strings.HasSuffix(holder.ApplicationName, " pid "+strconv.Itoa(instance.PID)) {
				// SIGKILL and PostgreSQL observing the closed coordination
				// socket are not atomic. Keep polling this known dead holder.
				if !instance.Running {
					return "", nil
				}
				owner = instance.Name
				break
			}
		}
		if owner == "" {
			return "", errors.New("rollout-promoter holder is not a running replica")
		}
	}
	return owner, nil
}

// Validate each stage, not just the total: a duplicate receipt for ring one must
// not conceal a missing receipt for ring two. Audit context proves these were
// automatic transitions, rather than operator promotions with similar results.
func validateHARolloutPromotions(e devlab.HARolloutEvidence, ring int32) error {
	if e.ID == "" || e.Creator == "" || e.Paused || e.Ring != ring || e.Revision != int64(ring)+1 || len(e.Stages) != int(ring)+1 || len(e.Events) != int(ring) || len(e.Audits) != int(ring) || len(e.Receipts) != int(ring) {
		return errors.New("rollout stage/event/audit/receipt cardinality mismatch")
	}
	for i, stage := range e.Stages {
		if stage.Ring != int32(i) || stage.Selected != 1 || stage.Started.IsZero() {
			return errors.New("rollout frozen cohort mismatch")
		}
		if i == 0 {
			continue
		}
		if stage.Started.Sub(e.Stages[i-1].Started) < haRolloutSoak {
			return errors.New("rollout advanced before real soak elapsed")
		}
		event, audit := e.Events[i-1], e.Audits[i-1]
		if event.ID == "" || event.Revision != int64(i)+1 || event.Actor != e.Creator || event.Reason != haAutomaticPromotionReason || event.At.Before(stage.Started) || audit.ID == "" || audit.Actor != e.Creator || audit.Reason != "" || audit.Context != haAutomaticPromotionReason || audit.At.Before(event.At) {
			return errors.New("rollout promotion lacks creator-attributed automatic audit evidence")
		}
		if i < int(ring) && !audit.At.Before(e.Stages[i+1].Started) {
			return errors.New("rollout audit belongs to a later stage")
		}
		count := 0
		for _, receipt := range e.Receipts {
			if receipt.Ring == uint32(i) && receipt.Revision == uint64(i)+1 && receipt.Actor == e.Creator && receipt.Request != "" {
				count++
			}
		}
		if count != 1 {
			return fmt.Errorf("rollout ring %d has %d promotion receipts", i, count)
		}
	}
	return nil
}

func (h *haRun) checkRollout(result *HAResult) {
	s := result.Rollout
	beforeErr, finalErr := validateHARolloutPromotions(s.BeforeLoss, 1), validateHARolloutPromotions(s.Final, 2)
	progress := beforeErr == nil && finalErr == nil && s.BeforeLoss.ID == s.Final.ID && s.BeforeLoss.Creator == s.Final.Creator && len(s.SeededAt) == 3 && s.HealthSource != ""
	if progress {
		progress = !s.BeforeLoss.Events[0].At.After(s.KilledAt) && s.Final.Events[1].At.After(s.RecoveredAt) && s.SeededAt[1].After(s.RecoveredAt)
		for i, at := range s.SeededAt {
			progress = progress && !at.Before(s.Final.Stages[i].Started)
			if i < 2 {
				progress = progress && s.Final.Events[i].At.After(at)
			}
		}
	}
	result.Checks = append(result.Checks,
		HACheck{Name: "rollout_automatic_without_list", Passed: progress, Detail: fmt.Sprintf("SQL-only observation; before-loss=%v final=%v; health source: %s", beforeErr, finalErr, s.HealthSource)},
		HACheck{Name: "rollout_promoter_leader_failover", Passed: progress && s.Leader != "" && s.Successor != "" && s.Leader != s.Successor && !s.KilledAt.IsZero() && !s.RecoveredAt.Before(s.KilledAt) && s.RecoveredAt.Sub(s.KilledAt) <= maxLeadershipGap, Detail: fmt.Sprintf("killed holder %s; successor %s acquired after %s; stage two advanced after acquisition", s.Leader, s.Successor, s.RecoveredAt.Sub(s.KilledAt))},
		HACheck{Name: "rollout_exactly_once_per_stage", Passed: finalErr == nil && !s.StableUntil.IsZero() && s.StableUntil.Sub(s.Final.Stages[2].Started) >= 20*time.Second, Detail: fmt.Sprintf("%d frozen stages; %d events, %d audits, %d decoded receipts; one per promoted stage; observed through %s", len(s.Final.Stages), len(s.Final.Events), len(s.Final.Audits), len(s.Final.Receipts), s.StableUntil.Format(time.RFC3339Nano))},
	)
}
