// SPDX-License-Identifier: Apache-2.0

//go:build linux

package osupdate

import (
	"context"
	"errors"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

type rebootPowerReply struct {
	power powerState
	err   error
}

type rebootAttemptBus struct {
	replies  []rebootPowerReply
	calls    int
	schedule func(time.Time) error
}

func (b *rebootAttemptBus) power(context.Context) (powerState, error) {
	reply := b.replies[0]
	b.replies = b.replies[1:]
	return reply.power, reply.err
}

func (b *rebootAttemptBus) scheduleReboot(_ context.Context, _ string, at time.Time) error {
	b.calls++
	return b.schedule(at)
}

func rebootAttemptFixture() (*agentv1.OSUpdateRebootState, *agentv1.OSUpdateRebootAttempt) {
	now := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)
	state := rebootCycle(nil, &resourcev1.OSUpdateRebootPolicy{
		Mode:             resourcev1.OSUpdateRebootMode_OS_UPDATE_REBOOT_MODE_SCHEDULED,
		MaxDelayMinutes:  120,
		EmployeeDeferral: &resourcev1.OSUpdateRebootDeferral{MaxDeferrals: 2, DelayMinutes: 5},
	}, "b03e57c0-48b5-4fca-b164-4d51406c8eb2", now)
	state.ScheduledFor = timestamppb.New(now.Add(5 * time.Minute))
	attempt := &agentv1.OSUpdateRebootAttempt{RequestId: "79965e07-ea48-4820-b62e-3d34f49d1d16", ScheduledFor: timestamppb.New(now.Add(10 * time.Minute)), EmployeeDeferral: true}
	return state, attempt
}

func TestRebootAttemptNativeFailuresPreserveAcceptedSchedule(t *testing.T) {
	failure := errors.New("injected native or storage failure")
	for _, tc := range []struct {
		name                                                                                         string
		beforeError, afterError, callError, inhibited, preparing, foreign, accepted, invalidateError bool
		persistFailure                                                                               int
		wantCalls                                                                                    int
		wantPending, wantError                                                                       bool
	}{
		{name: "accepted", accepted: true, wantCalls: 1},
		{name: "lost reply accepted", accepted: true, callError: true, wantCalls: 1},
		{name: "native rejection", callError: true, wantCalls: 1, wantError: true},
		{name: "native no effect", wantCalls: 1, wantError: true},
		{name: "fresh power unavailable", beforeError: true, wantError: true},
		{name: "new inhibitor", inhibited: true, wantError: true},
		{name: "preparing shutdown", preparing: true, wantError: true},
		{name: "foreign schedule", foreign: true, wantError: true},
		{name: "ambiguous reply", callError: true, afterError: true, wantCalls: 1, wantPending: true, wantError: true},
		{name: "accepted observation unavailable", accepted: true, afterError: true, wantCalls: 1, wantPending: true, wantError: true},
		{name: "intent write failed", persistFailure: 1, wantError: true},
		{name: "commit write failed", accepted: true, persistFailure: 2, wantCalls: 1, wantPending: true, wantError: true},
		{name: "cache invalidation failed", invalidateError: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, attempt := rebootAttemptFixture()
			original := proto.CloneOf(state)
			durable := proto.CloneOf(state)
			oldPower := powerState{pending: true, kind: "reboot", scheduled: state.GetScheduledFor().AsTime()}
			before := oldPower
			before.inhibited, before.preparing = tc.inhibited, tc.preparing
			if tc.foreign {
				before.scheduled = before.scheduled.Add(time.Minute)
			}
			after := oldPower
			if tc.accepted {
				after.scheduled = attempt.GetScheduledFor().AsTime()
			}
			replies := []rebootPowerReply{{power: before}, {power: after}}
			if tc.beforeError {
				replies[0].err = failure
			}
			if tc.afterError {
				replies[1].err = failure
			}
			invalidated := false
			bus := &rebootAttemptBus{replies: replies, schedule: func(at time.Time) error {
				if !invalidated || durable.GetPendingAttempt() == nil || durable.GetDeferralsUsed() != 0 || !proto.Equal(durable.GetScheduledFor(), original.GetScheduledFor()) {
					t.Fatal("native effect preceded durable intent/cache invalidation or overwrote accepted authority")
				}
				if !at.Equal(attempt.GetScheduledFor().AsTime()) {
					t.Fatal("wrong native target")
				}
				if tc.callError {
					return failure
				}
				return nil
			}}
			writes := 0
			persist := func() error {
				writes++
				if writes == tc.persistFailure {
					return failure
				}
				if err := protovalidate.Validate(state); err != nil {
					t.Fatal(err)
				}
				durable = proto.CloneOf(state)
				return nil
			}
			err := performRebootAttempt(t.Context(), state, attempt, bus, "notice", persist, func() error {
				if tc.invalidateError {
					return failure
				}
				invalidated = true
				return nil
			})
			if (err != nil) != tc.wantError || bus.calls != tc.wantCalls || (durable.GetPendingAttempt() != nil) != tc.wantPending {
				t.Fatalf("err=%v calls=%d pending=%v", err, bus.calls, durable.GetPendingAttempt())
			}
			if !proto.Equal(durable.GetDeadline(), original.GetDeadline()) {
				t.Fatal("attempt changed deadline")
			}
			if tc.accepted && !tc.wantPending {
				if durable.GetDeferralsUsed() != 1 || !proto.Equal(durable.GetScheduledFor(), attempt.GetScheduledFor()) {
					t.Fatal("accepted attempt not committed")
				}
			} else if durable.GetDeferralsUsed() != 0 || !proto.Equal(durable.GetScheduledFor(), original.GetScheduledFor()) {
				t.Fatal("unconfirmed attempt replaced accepted schedule or consumed count")
			}
			if tc.wantPending {
				// Simulate an executor restart from only the persisted bytes.
				if !reconcileRebootAttempt(durable, after) || durable.GetPendingAttempt() != nil {
					t.Fatal("pending attempt not reconciled after restart")
				}
				if tc.accepted {
					if durable.GetDeferralsUsed() != 1 || !proto.Equal(durable.GetScheduledFor(), attempt.GetScheduledFor()) {
						t.Fatal("lost accepted outcome")
					}
				} else if durable.GetDeferralsUsed() != 0 || !proto.Equal(durable.GetScheduledFor(), original.GetScheduledFor()) {
					t.Fatal("rejected attempt lost original notice")
				}
				if reconcileRebootAttempt(durable, after) {
					t.Fatal("replayed completed attempt")
				}
				if durable.GetLastRequestId() != attempt.GetRequestId() {
					t.Fatal("retry identity lost")
				}
			}
		})
	}
}

func TestRebootCyclePreservesAcceptedDeadlineAndPolicy(t *testing.T) {
	state, _ := rebootAttemptFixture()
	state.DeferralsUsed = 1
	deadline, policy := proto.CloneOf(state.GetDeadline()), proto.CloneOf(state.GetPolicy())
	shorter := &resourcev1.OSUpdateRebootPolicy{Mode: resourcev1.OSUpdateRebootMode_OS_UPDATE_REBOOT_MODE_SCHEDULED, MaxDelayMinutes: 5}
	later := state.GetScheduledFor().AsTime().Add(time.Minute)
	for _, next := range []*resourcev1.OSUpdateRebootPolicy{shorter, policy, shorter} {
		got := rebootCycle(state, next, state.GetBootId(), later)
		if got != state || !proto.Equal(got.GetDeadline(), deadline) || !proto.Equal(got.GetPolicy(), policy) || got.GetDeferralsUsed() != 1 || got.GetScheduledFor().AsTime().After(got.GetDeadline().AsTime()) {
			t.Fatal("later policy rewrote outstanding reboot authority")
		}
	}
	fresh := rebootCycle(state, shorter, "1e37a98f-753d-429a-b849-f263e34cd9c7", later)
	if fresh == state || fresh.GetDeferralsUsed() != 0 || fresh.GetScheduleId() == state.GetScheduleId() || !fresh.GetDeadline().AsTime().Equal(later.Add(5*time.Minute)) {
		t.Fatal("new boot reused old schedule authority")
	}
}

func TestRebootInitialAttemptDoesNotConsumeEmployeeBudget(t *testing.T) {
	state, attempt := rebootAttemptFixture()
	state.ScheduledFor = timestamppb.New(time.Unix(0, 0))
	attempt.EmployeeDeferral = false
	bus := &rebootAttemptBus{
		replies:  []rebootPowerReply{{}, {power: powerState{pending: true, kind: "reboot", scheduled: attempt.GetScheduledFor().AsTime()}}},
		schedule: func(time.Time) error { return nil },
	}
	persist := func() error { return protovalidate.Validate(state) }
	if err := performRebootAttempt(t.Context(), state, attempt, bus, "notice", persist, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if state.GetDeferralsUsed() != 0 || state.GetPendingAttempt() != nil || !proto.Equal(state.GetScheduledFor(), attempt.GetScheduledFor()) {
		t.Fatal("initial native acceptance consumed employee authority")
	}
}

func TestRetriedRebootCycleRetainsGraphicalNotificationRoute(t *testing.T) {
	for _, originallyEmployee := range []bool{false, true} {
		state, attempt := rebootAttemptFixture()
		if !originallyEmployee {
			state.Policy.EmployeeDeferral = nil
		}
		state.ScheduledFor = timestamppb.New(time.Unix(0, 0))
		attempt.EmployeeDeferral = false
		persist := func() error { return protovalidate.Validate(state) }
		inhibited := &rebootAttemptBus{replies: []rebootPowerReply{{power: powerState{inhibited: true}}}}
		if err := performRebootAttempt(t.Context(), state, attempt, inhibited, "notice", persist, func() error { return nil }); err == nil {
			t.Fatal("inhibited first attempt unexpectedly scheduled")
		}
		incoming := proto.CloneOf(state.GetPolicy())
		if originallyEmployee {
			incoming.EmployeeDeferral = nil
		} else {
			incoming.EmployeeDeferral = &resourcev1.OSUpdateRebootDeferral{MaxDeferrals: 1, DelayMinutes: 5}
		}
		state = rebootCycle(state, incoming, state.GetBootId(), attempt.GetScheduledFor().AsTime().Add(-time.Minute))
		retry := proto.CloneOf(attempt)
		retry.RequestId = "0c9da7bd-9e27-4c88-b5b5-7f8e0efda21d"
		accepted := &rebootAttemptBus{
			replies:  []rebootPowerReply{{}, {power: powerState{pending: true, kind: "reboot", scheduled: retry.GetScheduledFor().AsTime()}}},
			schedule: func(time.Time) error { return nil },
		}
		if err := performRebootAttempt(t.Context(), state, retry, accepted, "notice", persist, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		if employeeRebootNotice(state) != originallyEmployee || employeeRebootNotice(state) == (incoming.GetEmployeeDeferral() != nil) {
			t.Fatal("graphical notification followed incoming policy instead of the accepted reboot authority")
		}
	}
}
