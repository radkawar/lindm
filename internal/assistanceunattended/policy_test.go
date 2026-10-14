// SPDX-License-Identifier: Apache-2.0

package assistanceunattended

import (
	"errors"
	"testing"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestIntersectNeverWidensOrInventsLimits(t *testing.T) {
	a := &agentv1.AssistanceUnattendedPolicy{MaxApprovalSeconds: 86400, MaxEnrollmentDays: 30, MaxSessionSeconds: 1800}
	b := &agentv1.AssistanceUnattendedPolicy{MaxApprovalSeconds: 3600, MaxEnrollmentDays: 90, MaxSessionSeconds: 600}
	got := Intersect(a, b)
	if got.GetMaxApprovalSeconds() != 3600 || got.GetMaxEnrollmentDays() != 30 || got.GetMaxSessionSeconds() != 600 {
		t.Fatalf("intersection = %v", got)
	}
	if Intersect(a, nil) != nil || Intersect(nil, b) != nil {
		t.Fatal("an absent side enabled unattended access")
	}
	if Intersect(a, &agentv1.AssistanceUnattendedPolicy{MaxApprovalSeconds: 60, MaxEnrollmentDays: 1, MaxSessionSeconds: 60}) != nil {
		t.Fatal("a bound below the minimum enabled unattended access")
	}
}

func window(weekday, start, minutes uint32) *agentv1.AssistanceUnattendedWindow {
	return &agentv1.AssistanceUnattendedWindow{Weekday: weekday, StartMinute: start, DurationMinutes: minutes}
}

func TestScheduleOnlyUnderOnAndNeverOverlapping(t *testing.T) {
	on, limited := agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
	weekly := &agentv1.AssistanceUnattendedSchedule{TimeZone: "Europe/London", Windows: []*agentv1.AssistanceUnattendedWindow{window(1, 9*60, 480), window(3, 9*60, 480)}}
	if err := CheckSchedule(on, weekly); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(CheckSchedule(on, nil), ErrScheduleRequired) {
		t.Fatal("ON accepted a grant without its approved schedule")
	}
	if !errors.Is(CheckSchedule(limited, weekly), ErrScheduleRefused) {
		t.Fatal("LIMITED accepted a recurring schedule")
	}
	for name, schedule := range map[string]*agentv1.AssistanceUnattendedSchedule{
		"unknown zone": {TimeZone: "Mars/Olympus", Windows: []*agentv1.AssistanceUnattendedWindow{window(1, 0, 60)}},
		"overlap":      {TimeZone: "UTC", Windows: []*agentv1.AssistanceUnattendedWindow{window(1, 600, 120), window(1, 660, 30)}},
		"week wrap":    {TimeZone: "UTC", Windows: []*agentv1.AssistanceUnattendedWindow{window(6, 23*60, 120), window(0, 30, 30)}},
		"too long":     {TimeZone: "UTC", Windows: []*agentv1.AssistanceUnattendedWindow{window(2, 0, 721)}},
	} {
		if !errors.Is(CheckSchedule(on, schedule), ErrScheduleInvalid) {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestWindowRefusesOutsideApprovalAndSchedule(t *testing.T) {
	// Monday 2026-10-12 10:00 UTC.
	now := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)
	notBefore, notAfter := now.Add(-time.Hour), now.Add(48*time.Hour)
	if end, err := Window(notBefore, notAfter, nil, now); err != nil || !end.Equal(notAfter) {
		t.Fatalf("time-bounded approval: %v %v", end, err)
	}
	if _, err := Window(now.Add(time.Minute), notAfter, nil, now); !errors.Is(err, ErrOutsideApproval) {
		t.Fatal("a future approval admitted a connection")
	}
	if _, err := Window(notBefore, now, nil, now); !errors.Is(err, ErrOutsideApproval) {
		t.Fatal("an expired approval admitted a connection")
	}
	schedule := &agentv1.AssistanceUnattendedSchedule{TimeZone: "UTC", Windows: []*agentv1.AssistanceUnattendedWindow{window(1, 9*60, 120)}}
	end, err := Window(notBefore, notAfter, schedule, now)
	if err != nil || !end.Equal(time.Date(2026, 10, 12, 11, 0, 0, 0, time.UTC)) {
		t.Fatalf("scheduled window end = %v, %v", end, err)
	}
	if _, err := Window(notBefore, notAfter, schedule, now.Add(2*time.Hour)); !errors.Is(err, ErrOutsideSchedule) {
		t.Fatal("a connection outside the schedule was admitted")
	}
	// A Sunday-night window continues past midnight into Monday.
	overnight := &agentv1.AssistanceUnattendedSchedule{TimeZone: "UTC", Windows: []*agentv1.AssistanceUnattendedWindow{window(0, 23*60, 720)}}
	end, err = Window(notBefore, notAfter, overnight, now)
	if err != nil || !end.Equal(time.Date(2026, 10, 12, 11, 0, 0, 0, time.UTC)) {
		t.Fatalf("overnight window end = %v, %v", end, err)
	}
	// The approval end clips a longer schedule window.
	if end, err := Window(notBefore, now.Add(10*time.Minute), schedule, now); err != nil || !end.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("approval did not clip the window: %v %v", end, err)
	}
	// Windows are evaluated in the schedule's zone.
	tokyo := &agentv1.AssistanceUnattendedSchedule{TimeZone: "Asia/Tokyo", Windows: []*agentv1.AssistanceUnattendedWindow{window(1, 18*60, 120)}}
	if _, err := Window(notBefore, notAfter, tokyo, now); err != nil {
		t.Fatalf("19:00 Tokyo Monday is inside its window: %v", err)
	}
}
