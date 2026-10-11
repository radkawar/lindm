//go:build linux

package osupdate

import (
	"context"
	"errors"
	"io/fs"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
)

// rebootInstant finds the first permitted instant, including an exact deadline.
// Window ends are exclusive. Calendar starts use the same gap/fold semantics as
// update starts; elapsed durations, not wall-clock arithmetic, bound the window.
func rebootInstant(window *resourcev1.MaintenanceWindow, earliest, deadline time.Time) (time.Time, error) {
	if earliest.After(deadline) {
		return time.Time{}, nil
	}
	if window == nil {
		return earliest, nil
	}
	loc, err := time.LoadLocation(window.GetTimeZone())
	if err != nil {
		return time.Time{}, err
	}
	if _, open, err := openWindow(window, loc, earliest); err != nil || open {
		return earliest, err
	}
	local := earliest.In(loc)
	// The signed deadline is at most seven days away. Include the eighth
	// local date because offset changes can cross an additional midnight.
	for offset := 0; offset <= 8; offset++ {
		day := time.Date(local.Year(), local.Month(), local.Day()+offset, 12, 0, 0, 0, loc)
		for _, weekday := range window.GetWeekdays() {
			match, _ := goWeekday(weekday)
			if match != day.Weekday() {
				continue
			}
			start, exists := windowStart(day, int(window.GetLocalStartMinute()), loc)
			if exists && !start.Before(earliest) && !start.After(deadline) {
				return start, nil
			}
		}
	}
	return time.Time{}, nil
}

func rebootDeferral(state *agentv1.OSUpdateRebootState, now time.Time) (time.Time, string, error) {
	policy := state.GetPolicy().GetEmployeeDeferral()
	switch {
	case policy == nil:
		return time.Time{}, "deferral_disabled", nil
	case state.GetDeferralsUsed() >= policy.GetMaxDeferrals():
		return time.Time{}, "deferral_limit_reached", nil
	case !now.Before(state.GetScheduledFor().AsTime()):
		return time.Time{}, "reboot_already_due", nil
	}
	earliest := state.GetScheduledFor().AsTime().Add(time.Duration(policy.GetDelayMinutes()) * time.Minute)
	at, err := rebootInstant(state.GetPolicy().GetRebootWindow(), earliest, state.GetDeadline().AsTime())
	if err != nil {
		return time.Time{}, "reboot_window_unavailable", err
	}
	if at.IsZero() {
		return time.Time{}, "no_window_before_deadline", nil
	}
	return at, "", nil
}

// SessionReboot is called only after SO_PEERCRED/logind session authorization.
// It shares the runner lock, so an employee cannot race an update transaction or
// another employee. A missing, foreign or cross-boot schedule grants no authority.
func (r *Runner) SessionReboot(ctx context.Context, request *agentv1.OSUpdateRebootDeferralRequest) (_ *agentv1.OSUpdateRebootNotice, err error) {
	held, err := acquireLock(ctx, resource.OSUpdateLockPath, 0)
	// An idle poll may omit a busy schedule; a submitted action must remain
	// unacknowledged so the helper retains its exact request for retry.
	if (request == nil && errors.Is(err, ErrRunInProgress)) || errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, held.release()) }()
	state, err := r.loadRunState()
	if err != nil {
		return nil, err
	}
	reboot := state.GetReboot()
	if !employeeRebootNotice(reboot) || reboot.GetBootId() != bootID() {
		return nil, nil
	}
	bus, err := openLogind(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, bus.close()) }()
	power, err := bus.power(ctx)
	if err != nil {
		return nil, err
	}
	if err := r.reconcileRebootState(state, power); err != nil {
		return nil, err
	}
	if power.preparing || !ownsRebootSchedule(reboot, power) {
		return nil, nil
	}
	at, reason, err := rebootDeferral(reboot, r.now())
	if err != nil {
		return nil, err
	}
	if power.inhibited {
		at, reason = time.Time{}, "native_power_inhibited"
	}
	if request != nil && request.GetRequestId() != reboot.GetLastRequestId() {
		switch {
		case request.GetScheduleId() != reboot.GetScheduleId() || !request.GetScheduledFor().AsTime().Equal(reboot.GetScheduledFor().AsTime()):
			reason = "stale_reboot_notice"
		case at.IsZero():
		default:
			zone := time.Local
			if window := reboot.GetPolicy().GetRebootWindow(); window != nil {
				zone, err = time.LoadLocation(window.GetTimeZone())
				if err != nil {
					return nil, err
				}
			}
			attempt := &agentv1.OSUpdateRebootAttempt{RequestId: request.GetRequestId(), ScheduledFor: timestamppb.New(at), EmployeeDeferral: true}
			if err := performRebootAttempt(ctx, reboot, attempt, bus, rebootMessage(reboot.GetPolicy().GetNotice(), at, zone), func() error { return r.writeRunState(state) }, invalidateRebootStatus); err != nil {
				return nil, err
			}
			at, reason, err = rebootDeferral(reboot, r.now())
			if err != nil {
				return nil, err
			}
		}
	}
	if reboot.GetLastRequestReason() != "" {
		reason = reboot.GetLastRequestReason()
	}
	notice := &agentv1.OSUpdateRebootNotice{
		ScheduleId: reboot.GetScheduleId(), ScheduledFor: proto.CloneOf(reboot.GetScheduledFor()),
		Deadline: proto.CloneOf(reboot.GetDeadline()), Notice: reboot.GetPolicy().GetNotice(), Reason: reason,
		DeferralsRemaining: reboot.GetPolicy().GetEmployeeDeferral().GetMaxDeferrals() - min(reboot.GetDeferralsUsed(), reboot.GetPolicy().GetEmployeeDeferral().GetMaxDeferrals()),
	}
	if !at.IsZero() {
		notice.DeferUntil = timestamppb.New(at)
	}
	return notice, nil
}
