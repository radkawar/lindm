// SPDX-License-Identifier: Apache-2.0

// Package assistanceunattended holds the unattended-access bounds and schedule
// evaluation shared by the server, the console contract and the session
// helper. It decides only whether an instant lies inside an approved window;
// approval, local opt-in, lock state and the persistent banner are enforced by
// their owners. It never handles portal restore tokens.
package assistanceunattended

import (
	"errors"
	"time"

	// The server evaluates IANA zones without relying on host tzdata.
	_ "time/tzdata"

	agentv1 "lindm/gen/lindm/agent/v1"
)

const (
	MinApprovalSeconds = 300
	MaxApprovalSeconds = 30 * 24 * 60 * 60
	MaxEnrollmentDays  = 90
	MinSessionSeconds  = 60
	MaxSessionSeconds  = 1800
)

var (
	ErrScheduleInvalid  = errors.New("unattended_schedule_invalid")
	ErrOutsideSchedule  = errors.New("unattended_outside_schedule")
	ErrOutsideApproval  = errors.New("unattended_outside_approval")
	ErrScheduleRequired = errors.New("unattended_schedule_required")
	ErrScheduleRefused  = errors.New("unattended_schedule_not_permitted")
)

// Intersect is the stricter of two unattended bounds. An absent or zero side
// never enables unattended access.
func Intersect(a, b *agentv1.AssistanceUnattendedPolicy) *agentv1.AssistanceUnattendedPolicy {
	if a.GetMaxApprovalSeconds() < MinApprovalSeconds || b.GetMaxApprovalSeconds() < MinApprovalSeconds ||
		a.GetMaxEnrollmentDays() == 0 || b.GetMaxEnrollmentDays() == 0 ||
		a.GetMaxSessionSeconds() < MinSessionSeconds || b.GetMaxSessionSeconds() < MinSessionSeconds {
		return nil
	}
	return &agentv1.AssistanceUnattendedPolicy{
		MaxApprovalSeconds: min(a.GetMaxApprovalSeconds(), b.GetMaxApprovalSeconds(), MaxApprovalSeconds),
		MaxEnrollmentDays:  min(a.GetMaxEnrollmentDays(), b.GetMaxEnrollmentDays(), MaxEnrollmentDays),
		MaxSessionSeconds:  min(a.GetMaxSessionSeconds(), b.GetMaxSessionSeconds(), MaxSessionSeconds),
	}
}

// CheckSchedule requires a schedule exactly under ON policy and a loadable
// zone with non-overlapping windows.
func CheckSchedule(mode agentv1.AssistancePolicyMode, schedule *agentv1.AssistanceUnattendedSchedule) error {
	switch {
	case mode == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON && schedule == nil:
		return ErrScheduleRequired
	case mode != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON && schedule != nil:
		return ErrScheduleRefused
	case schedule == nil:
		return nil
	}
	if _, err := time.LoadLocation(schedule.GetTimeZone()); err != nil {
		return ErrScheduleInvalid
	}
	windows := schedule.GetWindows()
	if len(windows) == 0 || len(windows) > 7 {
		return ErrScheduleInvalid
	}
	const week = 7 * 24 * 60
	for i, a := range windows {
		if a.GetWeekday() > 6 || a.GetStartMinute() > 1439 || a.GetDurationMinutes() < 15 || a.GetDurationMinutes() > 720 {
			return ErrScheduleInvalid
		}
		startA := a.GetWeekday()*1440 + a.GetStartMinute()
		for _, b := range windows[i+1:] {
			startB := b.GetWeekday()*1440 + b.GetStartMinute()
			// Compare on the weekly circle in both directions.
			if (startB+week-startA)%week < a.GetDurationMinutes() || (startA+week-startB)%week < b.GetDurationMinutes() {
				return ErrScheduleInvalid
			}
		}
	}
	return nil
}

// Window returns the end of the approved window containing now: the grant's
// not_after, clipped to the end of the current schedule window when a
// schedule exists. It refuses instants outside the approval or schedule.
func Window(notBefore, notAfter time.Time, schedule *agentv1.AssistanceUnattendedSchedule, now time.Time) (time.Time, error) {
	if now.Before(notBefore) || !now.Before(notAfter) {
		return time.Time{}, ErrOutsideApproval
	}
	if schedule == nil {
		return notAfter, nil
	}
	location, err := time.LoadLocation(schedule.GetTimeZone())
	if err != nil {
		return time.Time{}, ErrScheduleInvalid
	}
	local := now.In(location)
	for _, window := range schedule.GetWindows() {
		// A window may have started on the previous day and run past midnight.
		for back := range 2 {
			day := local.AddDate(0, 0, -back)
			if int(day.Weekday()) != int(window.GetWeekday()) {
				continue
			}
			start := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, location).Add(time.Duration(window.GetStartMinute()) * time.Minute)
			end := start.Add(time.Duration(window.GetDurationMinutes()) * time.Minute)
			if !now.Before(start) && now.Before(end) {
				if end.After(notAfter) {
					end = notAfter
				}
				return end, nil
			}
		}
	}
	return time.Time{}, ErrOutsideSchedule
}
