// SPDX-License-Identifier: Apache-2.0

//go:build linux

package osupdate

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
)

func rebootCycle(previous *agentv1.OSUpdateRebootState, policy *resourcev1.OSUpdateRebootPolicy, boot string, now time.Time) *agentv1.OSUpdateRebootState {
	if previous != nil && previous.GetBootId() == boot {
		return previous
	}
	return &agentv1.OSUpdateRebootState{
		ScheduleId: uuid.NewString(), BootId: boot, Policy: policy,
		Deadline:     timestamppb.New(now.Add(time.Duration(policy.GetMaxDelayMinutes()) * time.Minute)),
		ScheduledFor: timestamppb.New(time.Unix(0, 0)),
	}
}

// Both graphical routes use the policy retained by this reboot cycle, never
// the policy of a later update that merely retries scheduling.
func employeeRebootNotice(state *agentv1.OSUpdateRebootState) bool {
	return state.GetPolicy().GetEmployeeDeferral() != nil
}

// rebootNative is the existing logind boundary. Tests inject native failures,
// never claim that the injected bus qualifies an actual reboot.
type rebootNative interface {
	power(context.Context) (powerState, error)
	scheduleReboot(context.Context, string, time.Time) error
}

func ownsRebootSchedule(state *agentv1.OSUpdateRebootState, power powerState) bool {
	return power.pending && power.kind == "reboot" && power.scheduled.Equal(state.GetScheduledFor().AsTime())
}

// reconcileRebootAttempt never replays a native mutation. Observing the exact
// target commits it; observing any other native state records non-acceptance and
// retains the previous accepted schedule. A failed observation leaves it pending.
func reconcileRebootAttempt(state *agentv1.OSUpdateRebootState, power powerState) bool {
	attempt := state.GetPendingAttempt()
	if attempt == nil {
		return false
	}
	state.LastRequestId = attempt.GetRequestId()
	state.LastRequestReason = "deferral_not_applied"
	if power.kind == "reboot" && power.scheduled.Equal(attempt.GetScheduledFor().AsTime()) {
		state.ScheduledFor = attempt.GetScheduledFor()
		if attempt.GetEmployeeDeferral() {
			state.DeferralsUsed++
		}
		state.LastRequestReason = ""
	} else if !ownsRebootSchedule(state, power) {
		state.LastRequestReason = "native_schedule_changed"
	}
	state.PendingAttempt = nil
	return true
}

func rejectRebootAttempt(state *agentv1.OSUpdateRebootState, reason string) {
	state.LastRequestId = state.GetPendingAttempt().GetRequestId()
	state.LastRequestReason = reason
	state.PendingAttempt = nil
}

// performRebootAttempt preserves the accepted schedule while a durable attempt
// is unresolved. persist and invalidate are the root store's real I/O boundary.
// A known pre-call failure consumes only the request identity, not the deferral.
func performRebootAttempt(ctx context.Context, state *agentv1.OSUpdateRebootState, attempt *agentv1.OSUpdateRebootAttempt, bus rebootNative, wall string, persist, invalidate func() error) error {
	if state.GetPendingAttempt() != nil {
		return errors.New("reboot_attempt_unresolved")
	}
	if err := invalidate(); err != nil {
		return err
	}
	state.PendingAttempt = attempt
	if err := persist(); err != nil {
		state.PendingAttempt = nil
		return err
	}
	power, err := bus.power(ctx)
	if err != nil {
		rejectRebootAttempt(state, "native_power_unavailable")
		return errors.Join(err, persist())
	}
	reason := ""
	switch {
	case power.preparing:
		reason = "reboot_already_due"
	case power.inhibited:
		reason = "native_power_inhibited"
	case attempt.GetEmployeeDeferral() && !ownsRebootSchedule(state, power):
		reason = "native_schedule_changed"
	case !attempt.GetEmployeeDeferral() && power.pending:
		reason = "native_power_already_pending"
	}
	if reason != "" {
		rejectRebootAttempt(state, reason)
		return errors.Join(errors.New(reason), persist())
	}
	callErr := bus.scheduleReboot(ctx, wall, attempt.GetScheduledFor().AsTime())
	observed, err := bus.power(ctx)
	if err != nil {
		// Even a lost reply may mean logind accepted the target. Retain the
		// durable attempt so the next read can establish either outcome.
		return errors.Join(callErr, err)
	}
	reconcileRebootAttempt(state, observed)
	if err := persist(); err != nil {
		return errors.Join(callErr, err)
	}
	if state.GetLastRequestReason() != "" {
		return errors.Join(callErr, errors.New(state.GetLastRequestReason()))
	}
	return nil
}

func invalidateRebootStatus() error {
	if err := os.Remove(resource.OSUpdateStatusPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (r *Runner) reconcileRebootState(state *agentv1.OSUpdateRunState, power powerState) error {
	if !reconcileRebootAttempt(state.GetReboot(), power) {
		return nil
	}
	if err := invalidateRebootStatus(); err != nil {
		return err
	}
	return r.writeRunState(state)
}

func (r *Runner) reconcilePendingReboot(ctx context.Context, state *agentv1.OSUpdateRunState) (err error) {
	if state.GetReboot().GetPendingAttempt() == nil || state.GetReboot().GetBootId() != bootID() {
		return nil
	}
	bus, err := openLogind(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, bus.close()) }()
	power, err := bus.power(ctx)
	if err != nil {
		return err
	}
	return r.reconcileRebootState(state, power)
}
