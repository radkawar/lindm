// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/assistancefiles"
	"lindm/internal/assistancereconnect"
	"lindm/internal/assistancerecording"
	"lindm/internal/assistanceunattended"
)

func policyEnabled(mode agentv1.AssistancePolicyMode) bool {
	return mode == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED || mode == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON
}

func consentedPolicy(invitation *agentv1.AssistanceInvitation) *agentv1.AssistancePolicy {
	requested, effective := invitation.GetRequestedCapabilities(), invitation.GetEffectiveCapabilities()
	intersect := func(a, b agentv1.AssistancePolicyMode) agentv1.AssistancePolicyMode {
		if !policyEnabled(a) || !policyEnabled(b) {
			return agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
		}
		return min(a, b)
	}
	policy := &agentv1.AssistancePolicy{
		Clipboard:        intersect(requested.GetClipboard(), effective.GetClipboard()),
		Keyboard:         intersect(requested.GetKeyboard(), effective.GetKeyboard()),
		Display:          intersect(requested.GetDisplay(), effective.GetDisplay()),
		Messages:         intersect(requested.GetMessages(), effective.GetMessages()),
		Files:            intersect(requested.GetFiles(), effective.GetFiles()),
		FileLimits:       assistancefiles.Intersect(requested.GetFileLimits(), effective.GetFileLimits()),
		Reconnect:        intersect(requested.GetReconnect(), effective.GetReconnect()),
		Recording:        intersect(requested.GetRecording(), effective.GetRecording()),
		ReconnectLimits:  assistancereconnect.Intersect(requested.GetReconnectLimits(), effective.GetReconnectLimits()),
		RecordingLimits:  assistancerecording.Intersect(requested.GetRecordingLimits(), effective.GetRecordingLimits()),
		Unattended:       intersect(requested.GetUnattended(), effective.GetUnattended()),
		UnattendedLimits: assistanceunattended.Intersect(requested.GetUnattendedLimits(), effective.GetUnattendedLimits()),
		Elevation:        intersect(requested.GetElevation(), effective.GetElevation()),
		Annotation:       intersect(requested.GetAnnotation(), effective.GetAnnotation()),
		Audio:            intersect(requested.GetAudio(), effective.GetAudio()),
		// Desktop admission gates are device policy only; an operator never
		// requests a desktop.
		KdePlasma: intersect(effective.GetKdePlasma(), effective.GetKdePlasma()),
		X11:       intersect(effective.GetX11(), effective.GetX11()),
	}
	if policy.UnattendedLimits == nil || !policyEnabled(policy.Unattended) || invitation.GetUnattendedEnrollment() == nil || invitation.GetUnattended() != nil {
		// The opt-in is offered only with the server's enrollment offer, and
		// never on an unattended connection itself.
		policy.Unattended, policy.UnattendedLimits = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF, nil
	}
	if policy.FileLimits == nil || !policyEnabled(policy.Files) {
		policy.Files, policy.FileLimits = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF, nil
	}
	if policy.ReconnectLimits == nil || !policyEnabled(policy.Reconnect) {
		policy.Reconnect, policy.ReconnectLimits = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF, nil
	}
	if policy.RecordingLimits == nil || !policyEnabled(policy.Recording) || invitation.GetRecording() == nil {
		// Recording is offered only with the server's immutable authority.
		policy.Recording, policy.RecordingLimits = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF, nil
	}
	return policy
}

// recordingOffer describes the recording named in the consent prompt. A
// required recording is never offered as optional and vice versa.
type recordingOffer struct {
	offered  bool
	required bool
	days     uint32
}

func offerRecording(invitation *agentv1.AssistanceInvitation, policy *agentv1.AssistancePolicy) (recordingOffer, error) {
	authority := invitation.GetRecording()
	mode := policy.GetRecording()
	switch {
	case authority == nil:
		return recordingOffer{}, nil
	case authority.GetRequired() && mode != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON:
		return recordingOffer{}, &EndError{Cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_RECORDING_FAILED, Detail: "recording_not_permitted"}
	case !authority.GetRequired() && mode == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON:
		return recordingOffer{}, &EndError{Cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_RECORDING_FAILED, Detail: "recording_authority_invalid"}
	case !policyEnabled(mode):
		return recordingOffer{}, nil
	}
	return recordingOffer{offered: true, required: authority.GetRequired(), days: authority.GetRetentionDays()}, nil
}

func grantedCapabilities(policy *agentv1.AssistancePolicy, grant Grant) *agentv1.AssistanceCapabilities {
	p := proto.CloneOf(policy)
	out := &agentv1.AssistanceCapabilities{Policy: p, CursorHidden: grant.CursorHidden()}
	if !policyEnabled(p.Clipboard) {
		out.ClipboardReason = "not_requested_or_allowed"
	} else if !grant.ClipboardGranted() {
		p.Clipboard, out.ClipboardReason = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF, "portal_clipboard_not_granted"
		if reason := grant.ClipboardReason(); reason != "" {
			out.ClipboardReason = reason
		}
	}
	if !policyEnabled(p.Keyboard) {
		out.KeyboardReason = "not_requested_or_allowed"
	} else if !grant.ControlGranted() || !grant.KeyboardGranted() {
		p.Keyboard, out.KeyboardReason = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF, "portal_control_not_granted"
	}
	if !policyEnabled(p.Display) {
		out.DisplayReason = "not_requested_or_allowed"
	} else if p.Display == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON && len(grant.Streams()) < 2 {
		p.Display, out.DisplayReason = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED, "only_one_monitor_granted"
	}
	if !policyEnabled(p.Messages) {
		out.MessagesReason = "not_requested_or_allowed"
	}
	if !policyEnabled(p.Files) {
		out.FilesReason = "not_requested_or_allowed"
	}
	if !policyEnabled(p.Reconnect) {
		out.ReconnectReason = "not_requested_or_allowed"
	}
	if !policyEnabled(p.Recording) {
		out.RecordingReason = "not_requested_or_allowed"
	}
	if !policyEnabled(p.Unattended) {
		out.UnattendedReason = "not_requested_or_allowed"
	}
	if !policyEnabled(p.Elevation) {
		out.ElevationReason = "not_requested_or_allowed"
	}
	if !policyEnabled(p.Annotation) {
		out.AnnotationReason = "not_requested_or_allowed"
	}
	if !policyEnabled(p.Audio) {
		out.AudioReason = "not_requested_or_allowed"
	}
	return out
}

// withholdRecording removes recording from a grant with an exact reason.
func withholdRecording(capabilities *agentv1.AssistanceCapabilities, reason string) {
	capabilities.Policy.Recording, capabilities.Policy.RecordingLimits = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF, nil
	capabilities.RecordingReason = reason
}

func capabilityConsentText(policy *agentv1.AssistancePolicy) string {
	var body strings.Builder
	switch policy.GetClipboard() {
	case agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED:
		body.WriteString("\nClipboard: allow the operator to send plain text to your clipboard, but not read it.")
	case agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON:
		body.WriteString("\nClipboard: allow the operator to send plain text to your clipboard and explicitly read your clipboard text.")
	}
	switch policy.GetKeyboard() {
	case agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED:
		body.WriteString("\nKeyboard: allow printable text symbols only; shortcuts are not allowed.")
	case agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON:
		body.WriteString("\nKeyboard: allow text symbols, physical keys and special-key shortcuts.")
	}
	if policy.GetDisplay() == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON {
		body.WriteString("\nDisplays: allow switching among the monitors you select in the system dialog.")
	}
	if policyEnabled(policy.GetMessages()) {
		body.WriteString("\nMessages: allow plain-text operator notifications during this session.")
	}
	switch policy.GetFiles() {
	case agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED:
		body.WriteString("\nFiles: allow the operator to offer files for your Downloads folder. You must approve each file locally; remote input and clipboard access are paused during approval.")
	case agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON:
		body.WriteString("\nFiles: allow approved files into Downloads and files you select locally to be sent to the operator. Remote input and clipboard access are paused during every local approval or file picker.")
	}
	if policyEnabled(policy.GetElevation()) {
		body.WriteString("\nPassword prompts: the operator may ask you to enter a password yourself. Remote control and clipboard pause until you choose Resume; the operator never types your password.")
	}
	switch policy.GetAnnotation() {
	case agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED:
		body.WriteString("\nPointer: the operator may show a pointer on the shared screen. It cannot click or type, and you can hide it.")
	case agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON:
		body.WriteString("\nPointer and drawing: the operator may point and draw short-lived marks on the shared screen. They cannot click or type, and you can clear or hide them.")
	}
	switch policy.GetAudio() {
	case agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED:
		body.WriteString("\nSound: you may choose to share the sound of one output. You choose the output next and can mute or stop it.")
	case agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON:
		body.WriteString("\nSound: you may choose to share the sound of one output, and separately your microphone. You choose next and can mute or stop it.")
	}
	if limits := policy.GetReconnectLimits(); policyEnabled(policy.GetReconnect()) {
		minutes := max(limits.GetWindowSeconds()/60, 1)
		if policy.GetReconnect() == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON {
			fmt.Fprintf(&body, "\nReconnect: if you sign out, restart or lock, a new request may be sent automatically for %d minutes. You will be asked again; nothing you allow now carries over.", minutes)
		} else {
			fmt.Fprintf(&body, "\nReconnect: if you sign out, restart or lock, the operator may send a new request for %d minutes. You will be asked again; nothing you allow now carries over.", minutes)
		}
	}
	return body.String()
}

// recordingConsentText discloses capture and the organization's later access
// before anything is captured.
func recordingConsentText(offer recordingOffer) string {
	if !offer.offered {
		return ""
	}
	retention := fmt.Sprintf("Your organization keeps the encrypted recording for up to %d days; people it authorizes can play it back later. Recordings contain the screen only, never sound.", offer.days)
	if offer.required {
		return "\nRecording: this session will be recorded and cannot start without recording. " + retention + " You are shown when recording is active. Declining ends the request."
	}
	return "\nRecording: the operator asks to record this session. It is recorded only if you choose Allow and record. " + retention + " You can stop recording at any time."
}
