// SPDX-License-Identifier: Apache-2.0

//go:build linux

package osupdate

import (
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func TestRebootInstantDeadlineAndWindowEdges(t *testing.T) {
	parse := func(value string) time.Time {
		t.Helper()
		at, err := time.Parse(time.RFC3339, value)
		if err != nil {
			t.Fatal(err)
		}
		return at
	}
	for _, tc := range []struct {
		name                     string
		window                   *resourcev1.MaintenanceWindow
		earliest, deadline, want string
	}{
		{"exact deadline permitted", nil, "2026-10-12T10:00:00Z", "2026-10-12T10:00:00Z", "2026-10-12T10:00:00Z"},
		{"after deadline denied", nil, "2026-10-12T10:00:01Z", "2026-10-12T10:00:00Z", ""},
		{"separate later window", window("UTC", 11*60, 60, resourcev1.Weekday_WEEKDAY_MONDAY), "2026-10-12T10:00:00Z", "2026-10-12T12:00:00Z", "2026-10-12T11:00:00Z"},
		{"window end excluded", window("UTC", 11*60, 60, resourcev1.Weekday_WEEKDAY_MONDAY), "2026-10-12T12:00:00Z", "2026-10-12T13:00:00Z", ""},
		{"deadline cannot override window", window("UTC", 11*60, 60, resourcev1.Weekday_WEEKDAY_MONDAY), "2026-10-12T10:00:00Z", "2026-10-12T10:59:59Z", ""},
		{"cross midnight", window("UTC", 23*60+30, 120, resourcev1.Weekday_WEEKDAY_MONDAY), "2026-10-13T00:45:00Z", "2026-10-13T01:00:00Z", "2026-10-13T00:45:00Z"},
		{"spring gap skips date", window("Europe/Berlin", 150, 60, resourcev1.Weekday_WEEKDAY_SUNDAY), "2026-03-29T00:00:00Z", "2026-03-29T04:00:00Z", ""},
		{"fall fold first occurrence", window("Europe/Berlin", 150, 60, resourcev1.Weekday_WEEKDAY_SUNDAY), "2026-10-25T00:00:00Z", "2026-10-25T03:00:00Z", "2026-10-25T00:30:00Z"},
		{"fall fold does not reopen", window("Europe/Berlin", 150, 30, resourcev1.Weekday_WEEKDAY_SUNDAY), "2026-10-25T01:30:00Z", "2026-10-25T03:00:00Z", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := rebootInstant(tc.window, parse(tc.earliest), parse(tc.deadline))
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == "" {
				if !got.IsZero() {
					t.Fatalf("unauthorized instant %s", got)
				}
				return
			}
			if !got.Equal(parse(tc.want)) {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestRebootDeferralCannotExtendDeadlineOrCount(t *testing.T) {
	now := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)
	state := &agentv1.OSUpdateRebootState{
		Policy:       &resourcev1.OSUpdateRebootPolicy{EmployeeDeferral: &resourcev1.OSUpdateRebootDeferral{MaxDeferrals: 2, DelayMinutes: 15}},
		ScheduledFor: timestamppb.New(now.Add(5 * time.Minute)), Deadline: timestamppb.New(now.Add(20 * time.Minute)),
	}
	at, reason, err := rebootDeferral(state, now)
	if err != nil || reason != "" || !at.Equal(state.GetDeadline().AsTime()) {
		t.Fatalf("exact deadline: %s %s %v", at, reason, err)
	}
	state.ScheduledFor = timestamppb.New(at)
	if at, reason, err = rebootDeferral(state, now); err != nil || !at.IsZero() || reason != "no_window_before_deadline" {
		t.Fatalf("deadline escaped: %s %s %v", at, reason, err)
	}
	state.DeferralsUsed = 2
	if at, reason, err = rebootDeferral(state, now); err != nil || !at.IsZero() || reason != "deferral_limit_reached" {
		t.Fatalf("count escaped: %s %s %v", at, reason, err)
	}
	state.DeferralsUsed = 0
	if at, reason, err = rebootDeferral(state, state.GetScheduledFor().AsTime()); err != nil || !at.IsZero() || reason != "reboot_already_due" {
		t.Fatalf("due reboot changed: %s %s %v", at, reason, err)
	}
}

func TestRebootPolicySchemaBounds(t *testing.T) {
	validator, err := protovalidate.New()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name         string
		mode         resourcev1.OSUpdateRebootMode
		count, delay uint32
		valid        bool
	}{
		{"bounded", resourcev1.OSUpdateRebootMode_OS_UPDATE_REBOOT_MODE_SCHEDULED, 2, 15, true},
		{"unbounded count", resourcev1.OSUpdateRebootMode_OS_UPDATE_REBOOT_MODE_SCHEDULED, 11, 15, false},
		{"zero count", resourcev1.OSUpdateRebootMode_OS_UPDATE_REBOOT_MODE_SCHEDULED, 0, 15, false},
		{"too short", resourcev1.OSUpdateRebootMode_OS_UPDATE_REBOOT_MODE_SCHEDULED, 1, 4, false},
		{"too long", resourcev1.OSUpdateRebootMode_OS_UPDATE_REBOOT_MODE_SCHEDULED, 1, 1441, false},
		{"never carries deferral", resourcev1.OSUpdateRebootMode_OS_UPDATE_REBOOT_MODE_NEVER, 1, 15, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := &resourcev1.OSUpdateRebootPolicy{Mode: tc.mode, MaxDelayMinutes: 60, EmployeeDeferral: &resourcev1.OSUpdateRebootDeferral{MaxDeferrals: tc.count, DelayMinutes: tc.delay}}
			if got := validator.Validate(policy) == nil; got != tc.valid {
				t.Fatalf("valid=%t want=%t", got, tc.valid)
			}
		})
	}
}
