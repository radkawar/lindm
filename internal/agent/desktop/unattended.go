// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"context"
	"errors"
	"fmt"
	"html"
	"slices"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
)

const (
	actionAllowUnattended  = "allow_unattended"
	actionUnattendedOff    = "unattended_off"
	unattendedRestoreLimit = 20 * time.Second
)

// Enrollment is the employee's local unattended opt-in. The restore token
// is the desktop's persistent grant; it never leaves this user's state.
type Enrollment struct {
	ID           string
	Mode         agentv1.AssistanceMode
	ExpiresAt    time.Time
	RestoreToken string
}

// EnrollmentStore keeps the opt-in in the user's own private state.
type EnrollmentStore interface {
	Load() (Enrollment, error)
	Save(Enrollment) error
	Remove() error
}

var errEnrollmentMissing = errors.New("unattended_enrollment_missing")

// unattendedConsentText discloses the opt-in in the attended prompt.
func unattendedConsentText(policy *agentv1.AssistancePolicy, offer *agentv1.AssistanceUnattendedEnrollmentOffer) string {
	if !policyEnabled(policy.GetUnattended()) || offer == nil {
		return ""
	}
	until := offer.GetExpiresAt().AsTime().Local().Format("2 Jan 2006")
	return fmt.Sprintf("\nUnattended access (optional): choose \"Allow and enable unattended\" to also let your organization's approved operators connect to this account later without asking each time, until %s. Each connection needs a second person's approval, shows a banner naming the operator with Stop, and never reaches a locked or signed-out screen. You can turn it off from that banner.", until)
}

// unattendedPrompt is the persistent banner of an unattended connection. It
// is shown before any capture and stays for the whole connection.
func (s *session) unattendedNotification(markup bool, connected bool) Notification {
	authority := s.invitation.GetUnattended()
	operator, approver, reason := s.invitation.GetOperatorDisplay(), authority.GetApproverDisplay(), s.invitation.GetReason()
	if markup {
		operator, approver, reason = html.EscapeString(operator), html.EscapeString(approver), html.EscapeString(reason)
	}
	until := authority.GetApprovedUntil().AsTime().Local().Format("15:04")
	s.mu.Lock()
	control, elevation := s.control, policyEnabled(s.granted.GetPolicy().GetElevation())
	s.mu.Unlock()
	activity := "is connecting to"
	if connected {
		activity = "can see"
		if control {
			activity = "can see and control"
		}
	}
	body := fmt.Sprintf("%s %s this session without asking, approved by %s until %s.\nReason: %s\nChoose Stop to end it now, or turn unattended access off entirely.", operator, activity, approver, until, reason)
	if policyEnabled(consentedPolicy(s.invitation).GetAnnotation()) {
		body += "\nThe operator may show a pointer on your screen."
	}
	if s.invitation.GetRecording().GetRequired() {
		body += "\nThis connection is recorded; your organization keeps the encrypted recording for review."
	}
	actions := []NotificationAction{{Key: actionStop, Label: "Stop"}, {Key: actionUnattendedOff, Label: "Stop and turn off unattended"}}
	if connected && elevation {
		actions = append(actions, NotificationAction{Key: actionElevationPause, Label: "Pause for password"})
	}
	summary := "Unattended remote assistance — " + s.invitation.GetOperatorDisplay()
	if markup {
		summary = html.EscapeString(summary)
	}
	return Notification{Summary: summary, Body: body, Actions: actions, Critical: true, Persistent: true}
}

// openUnattended runs the unattended connection's local gates in order: the
// employee's own opt-in, a banner that can persist, and the desktop's
// persistent grant restored without any dialog. Any missing piece refuses.
func (s *session) openUnattended(ctx context.Context, r *sessionResources, capabilities []string, request PortalRequest) (Grant, error) {
	authority := s.invitation.GetUnattended()
	if s.deps.enrollments == nil || s.deps.unattendedUnavailableReason != "" {
		return nil, &EndError{Cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, Detail: cmpString(s.deps.unattendedUnavailableReason, "unattended_unavailable")}
	}
	enrollment, err := s.deps.enrollments.Load()
	switch {
	case err != nil, enrollment.ID != authority.GetEnrollmentId():
		return nil, &EndError{Cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, Detail: errEnrollmentMissing.Error(), Err: err}
	case !s.deps.clock().Before(enrollment.ExpiresAt), enrollment.Mode != s.invitation.GetMode(), enrollment.RestoreToken == "":
		s.logIfErr("remove expired enrollment", s.deps.enrollments.Remove())
		return nil, &EndError{Cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, Detail: errEnrollmentMissing.Error()}
	}
	if !slices.Contains(capabilities, "persistence") {
		return nil, &EndError{Cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, Detail: "unattended_banner_unavailable"}
	}
	banner, err := s.deps.notifier.Notify(ctx, s.unattendedNotification(r.markup, false))
	if err != nil {
		return nil, unavailable("unattended_banner_failed", err)
	}
	r.prompt = banner
	s.advance(agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED)
	s.logger.Info("remote assistance unattended banner shown", "mode", s.invitation.GetMode().String())
	request.RestoreToken = enrollment.RestoreToken
	restore, cancel := context.WithTimeout(ctx, s.deps.unattendedRestore)
	grant, err := s.deps.portal.Open(restore, request)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return nil, err
		}
		// A dialog in place of a restore, or a refused restore, means the
		// desktop no longer holds the persistent grant: never ask an
		// unattended screen, and drop the stale opt-in.
		s.logIfErr("remove stale enrollment", s.deps.enrollments.Remove())
		return nil, &EndError{Cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, Detail: "unattended_portal_grant_missing", Err: err}
	}
	if token := grant.RestoreToken(); token != "" {
		enrollment.RestoreToken = token
		if err := s.deps.enrollments.Save(enrollment); err != nil {
			s.logger.Warn("remote assistance unattended token not stored", "err", err)
		}
	}
	select {
	case action := <-banner.Result():
		r.prompt = nil
		closing, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.deps.callTimeout)
		s.logIfErr("close portal session", grant.Close(closing))
		cancel()
		return nil, s.unattendedStopped(action)
	default:
	}
	return grant, nil
}

// unattendedStopped maps the employee's banner action to the end cause.
func (s *session) unattendedStopped(action string) error {
	if action == actionUnattendedOff {
		s.logIfErr("remove enrollment", s.deps.enrollments.Remove())
		return &EndError{Cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED, Detail: "unattended_turned_off"}
	}
	return &EndError{Cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED, Detail: "local_stop"}
}

// enrollUnattended stores the opt-in after the desktop granted persistence
// and returns the report for the server.
func (s *session) enrollUnattended(grant Grant, granted *agentv1.AssistanceCapabilities, chosen bool) *agentv1.AssistanceUnattendedReport {
	offer := s.invitation.GetUnattendedEnrollment()
	if offer == nil {
		return nil
	}
	report := &agentv1.AssistanceUnattendedReport{EnrollmentId: offer.GetEnrollmentId(), State: agentv1.AssistanceUnattendedEnrollmentState_ASSISTANCE_UNATTENDED_ENROLLMENT_STATE_DECLINED}
	decline := func(reason string) *agentv1.AssistanceUnattendedReport {
		granted.Policy.Unattended, granted.Policy.UnattendedLimits = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF, nil
		granted.UnattendedReason, report.Reason = reason, reason
		return report
	}
	switch {
	case !policyEnabled(granted.GetPolicy().GetUnattended()):
		return decline(cmpString(granted.GetUnattendedReason(), "not_requested_or_allowed"))
	case !chosen:
		return decline("user_declined")
	case grant.RestoreToken() == "":
		// The employee cleared the dialog's remember choice.
		return decline("portal_persist_not_granted")
	}
	err := s.deps.enrollments.Save(Enrollment{ID: offer.GetEnrollmentId(), Mode: s.invitation.GetMode(), ExpiresAt: offer.GetExpiresAt().AsTime(), RestoreToken: grant.RestoreToken()})
	if err != nil {
		s.logger.Warn("remote assistance unattended opt-in not stored", "err", err)
		return decline("enrollment_store_failed")
	}
	report.State = agentv1.AssistanceUnattendedEnrollmentState_ASSISTANCE_UNATTENDED_ENROLLMENT_STATE_ENROLLED
	return report
}

func cmpString(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
