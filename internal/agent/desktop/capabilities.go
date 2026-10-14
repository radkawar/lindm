// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"strings"

	agentv1 "lindm/gen/lindm/agent/v1"
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
	return &agentv1.AssistancePolicy{
		Clipboard: intersect(requested.GetClipboard(), effective.GetClipboard()),
		Keyboard:  intersect(requested.GetKeyboard(), effective.GetKeyboard()),
		Display:   intersect(requested.GetDisplay(), effective.GetDisplay()),
		Messages:  intersect(requested.GetMessages(), effective.GetMessages()),
	}
}

func grantedCapabilities(policy *agentv1.AssistancePolicy, grant Grant) *agentv1.AssistanceCapabilities {
	p := &agentv1.AssistancePolicy{Clipboard: policy.GetClipboard(), Keyboard: policy.GetKeyboard(), Display: policy.GetDisplay(), Messages: policy.GetMessages()}
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
	return out
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
	return body.String()
}
