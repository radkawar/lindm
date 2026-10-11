package loadlab

import (
	"testing"
	"time"

	"lindm/internal/devlab"
)

func haRolloutEvidenceFixture() devlab.HARolloutEvidence {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e := devlab.HARolloutEvidence{ID: "campaign", Creator: "creator", Ring: 2, Revision: 3}
	for i := range 3 {
		started := at.Add(time.Duration(i) * 10 * time.Second)
		e.Stages = append(e.Stages, devlab.HARolloutStage{Ring: int32(i), Started: started, Selected: 1})
		if i == 0 {
			continue
		}
		e.Events = append(e.Events, devlab.HARolloutEvent{ID: "event", Revision: int64(i) + 1, Actor: e.Creator, Reason: haAutomaticPromotionReason, At: started.Add(time.Millisecond)})
		e.Audits = append(e.Audits, devlab.HARolloutAudit{ID: "audit", Actor: e.Creator, Context: haAutomaticPromotionReason, At: started.Add(2 * time.Millisecond)})
		e.Receipts = append(e.Receipts, devlab.HARolloutReceipt{Request: "request", Actor: e.Creator, Ring: uint32(i), Revision: uint64(i) + 1})
	}
	return e
}

// These mutations model false-positive qualification: totals alone can hide a
// duplicate stage, missing receipt, manual promotion or fabricated soak age.
func TestHARolloutEvidenceRequiresExactlyOneAutomaticPromotionPerStage(t *testing.T) {
	if err := validateHARolloutPromotions(haRolloutEvidenceFixture(), 2); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*devlab.HARolloutEvidence)
	}{
		{"duplicate_receipt_same_total", func(e *devlab.HARolloutEvidence) { e.Receipts[1] = e.Receipts[0] }},
		{"duplicate_event_revision", func(e *devlab.HARolloutEvidence) { e.Events[1].Revision = 2 }},
		{"duplicate_stage", func(e *devlab.HARolloutEvidence) { e.Stages[2].Ring = 1 }},
		{"missing_audit", func(e *devlab.HARolloutEvidence) { e.Audits = e.Audits[:1] }},
		{"extra_event", func(e *devlab.HARolloutEvidence) { e.Events = append(e.Events, e.Events[0]) }},
		{"wrong_creator", func(e *devlab.HARolloutEvidence) { e.Events[0].Actor = "reader" }},
		{"wrong_receipt_actor", func(e *devlab.HARolloutEvidence) { e.Receipts[0].Actor = "reader" }},
		{"manual_audit_reason", func(e *devlab.HARolloutEvidence) { e.Audits[0].Reason = "operator promotion" }},
		{"missing_automatic_context", func(e *devlab.HARolloutEvidence) { e.Audits[0].Context = "" }},
		{"audit_for_later_stage", func(e *devlab.HARolloutEvidence) { e.Audits[0].At = e.Stages[2].Started }},
		{"soak_not_elapsed", func(e *devlab.HARolloutEvidence) { e.Stages[1].Started = e.Stages[0].Started.Add(time.Second) }},
		{"empty_cohort", func(e *devlab.HARolloutEvidence) { e.Stages[0].Selected = 0 }},
		{"paused", func(e *devlab.HARolloutEvidence) { e.Paused = true }},
		{"missing_ring_zero", func(e *devlab.HARolloutEvidence) { e.Stages = e.Stages[1:] }},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := haRolloutEvidenceFixture()
			test.mutate(&e)
			if err := validateHARolloutPromotions(e, 2); err == nil {
				t.Fatal("incorrectly qualified incomplete or duplicate promotion evidence")
			}
		})
	}
}

func TestHARolloutLeaderRequiresExactRunningReplicaAndJob(t *testing.T) {
	instances := []devlab.HAInstanceState{{Name: "a", PID: 123, Running: true}, {Name: "b", PID: 456, Running: true}}
	for _, test := range []struct {
		name    string
		holders []devlab.HALockHolder
		want    string
		wantErr bool
	}{
		{"leader", []devlab.HALockHolder{{Key: haRolloutJobKey, ApplicationName: "lindmd pid 123"}}, "a", false},
		{"successor", []devlab.HALockHolder{{Key: haRolloutJobKey, ApplicationName: "lindmd pid 456"}}, "b", false},
		{"unheld", nil, "", false},
		{"other_job", []devlab.HALockHolder{{Key: haRolloutJobKey - 1, ApplicationName: "lindmd pid 123"}}, "", false},
		{"pid_suffix_collision", []devlab.HALockHolder{{Key: haRolloutJobKey, ApplicationName: "lindmd pid 9123"}}, "", true},
		{"unknown_process", []devlab.HALockHolder{{Key: haRolloutJobKey, ApplicationName: "lindmd pid 789"}}, "", true},
		{"duplicate_holders", []devlab.HALockHolder{{Key: haRolloutJobKey, ApplicationName: "lindmd pid 123"}, {Key: haRolloutJobKey, ApplicationName: "lindmd pid 456"}}, "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := haRolloutLeader(test.holders, instances)
			if got != test.want || (err != nil) != test.wantErr {
				t.Fatalf("owner=%q error=%v want=%q error=%t", got, err, test.want, test.wantErr)
			}
		})
	}
	instances[0].Running = false
	if owner, err := haRolloutLeader([]devlab.HALockHolder{{Key: haRolloutJobKey, ApplicationName: "lindmd pid 123"}}, instances); owner != "" || err != nil {
		t.Fatalf("dead holder awaiting database release should keep polling: owner=%q err=%v", owner, err)
	}
}

func TestHARolloutChecksRejectMissingEvidenceWithoutPanic(t *testing.T) {
	h := new(haRun)
	result := new(HAResult)
	h.checkRollout(result)
	if len(result.Checks) != 3 {
		t.Fatalf("got %d rollout checks", len(result.Checks))
	}
	for _, check := range result.Checks {
		if check.Passed {
			t.Fatalf("missing evidence passed %s", check.Name)
		}
	}
}

func TestHARolloutChecksRequireProgressAcrossActualLeaderLoss(t *testing.T) {
	final := haRolloutEvidenceFixture()
	before := haRolloutEvidenceFixture()
	before.Ring, before.Revision = 1, 2
	before.Stages, before.Events = before.Stages[:2], before.Events[:1]
	before.Audits, before.Receipts = before.Audits[:1], before.Receipts[:1]
	killed := final.Stages[1].Started.Add(time.Second)
	baseline := HARolloutSummary{
		HealthSource: "fixture-seeded", Leader: "a", Successor: "b",
		KilledAt: killed, RecoveredAt: killed.Add(time.Second),
		BeforeLoss: before, Final: final, StableUntil: final.Stages[2].Started.Add(30 * time.Second),
		SeededAt: []time.Time{final.Stages[0].Started.Add(time.Second), killed.Add(3 * time.Second), final.Stages[2].Started.Add(time.Second)},
	}
	for _, test := range []struct {
		name   string
		mutate func(*HARolloutSummary)
		want   bool
	}{
		{"success", func(*HARolloutSummary) {}, true},
		{"same_leader", func(s *HARolloutSummary) { s.Successor = s.Leader }, false},
		{"promotion_before_recovery", func(s *HARolloutSummary) { s.RecoveredAt = s.Final.Events[1].At.Add(time.Second) }, false},
		{"no_observation_after_rejoin", func(s *HARolloutSummary) { s.StableUntil = s.Final.Stages[2].Started }, false},
		{"different_campaign", func(s *HARolloutSummary) { s.BeforeLoss.ID = "other" }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := &HAResult{Rollout: baseline}
			test.mutate(&result.Rollout)
			new(haRun).checkRollout(result)
			passed := true
			for _, check := range result.Checks {
				passed = passed && check.Passed
			}
			if passed != test.want {
				t.Fatalf("checks passed=%t want=%t: %+v", passed, test.want, result.Checks)
			}
		})
	}
}
