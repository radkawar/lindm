// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"crypto/sha256"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func assistancePolicyMode(mode agentv1.AssistancePolicyMode) agentv1.AssistancePolicyMode {
	if mode != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED && mode != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON {
		return agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
	}
	return mode
}

func assistancePolicyIntersection(a, b *agentv1.AssistancePolicy) *agentv1.AssistancePolicy {
	return &agentv1.AssistancePolicy{
		Clipboard: min(assistancePolicyMode(a.GetClipboard()), assistancePolicyMode(b.GetClipboard())),
		Keyboard:  min(assistancePolicyMode(a.GetKeyboard()), assistancePolicyMode(b.GetKeyboard())),
		Display:   min(assistancePolicyMode(a.GetDisplay()), assistancePolicyMode(b.GetDisplay())),
		Messages:  min(assistancePolicyMode(a.GetMessages()), assistancePolicyMode(b.GetMessages())),
	}
}

func cloneAssistanceDisplays(in []*agentv1.AssistanceDisplay) []*agentv1.AssistanceDisplay {
	out := make([]*agentv1.AssistanceDisplay, len(in))
	for i, display := range in {
		out[i] = proto.CloneOf(display)
	}
	return out
}

func (b *assistanceBroker) helperDirective(session *assistanceSession) *agentv1.AssistanceDirective {
	invitation := proto.CloneOf(session.invitation)
	invitation.EffectiveCapabilities = assistancePolicyIntersection(invitation.GetEffectiveCapabilities(), b.ceiling)
	return &agentv1.AssistanceDirective{Invitation: invitation, AnswerSdp: session.answerSDP, Command: proto.CloneOf(session.command), AuthorizedUntil: timestamppb.New(session.authorizedUntil)}
}

func (b *assistanceBroker) applyCapabilities(session *assistanceSession, report *agentv1.SessionAssistanceReport) bool {
	grant := report.GetGrantedCapabilities().GetPolicy()
	effective := assistancePolicyIntersection(session.invitation.GetEffectiveCapabilities(), b.ceiling)
	if !proto.Equal(assistancePolicyIntersection(report.GetRequestedCapabilities(), report.GetRequestedCapabilities()), assistancePolicyIntersection(session.invitation.GetRequestedCapabilities(), session.invitation.GetRequestedCapabilities())) || !proto.Equal(assistancePolicyIntersection(report.GetEffectiveCapabilities(), report.GetEffectiveCapabilities()), effective) {
		return false
	}
	if !proto.Equal(assistancePolicyIntersection(grant, grant), assistancePolicyIntersection(grant, effective)) {
		return false
	}
	if assistancePolicyMode(grant.GetKeyboard()) > agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF && (!report.GetControlGranted() || session.invitation.GetMode() != agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL) {
		return false
	}
	if assistancePolicyMode(grant.GetClipboard()) > agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF && session.invitation.GetMode() != agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL {
		return false
	}
	seen := make(map[string]bool, len(report.GetDisplays()))
	for _, display := range report.GetDisplays() {
		if seen[display.GetId()] {
			return false
		}
		seen[display.GetId()] = true
	}
	if len(seen) == 0 {
		if report.GetSelectedDisplayId() != "" || report.GetDisplayGeneration() != 0 {
			return false
		}
	} else if !seen[report.GetSelectedDisplayId()] || report.GetDisplayGeneration() == 0 {
		return false
	}
	if len(seen) > 1 && grant.GetDisplay() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON {
		return false
	}
	frame := report.GetDisplayFrame()
	if frame != nil && (frame.GetDisplayId() != report.GetSelectedDisplayId() || frame.GetGeneration() != report.GetDisplayGeneration()) {
		return false
	}
	if session.capabilitiesSet {
		if !proto.Equal(assistancePolicyIntersection(session.granted.GetPolicy(), session.granted.GetPolicy()), assistancePolicyIntersection(grant, grant)) || len(session.displays) != len(report.GetDisplays()) {
			return false
		}
		for i, display := range session.displays {
			if !proto.Equal(display, report.GetDisplays()[i]) {
				return false
			}
		}
		if session.selectedDisplayID != report.GetSelectedDisplayId() || session.displayGeneration != report.GetDisplayGeneration() {
			command, result := session.command, report.GetCommandResult()
			if command.GetKind() != agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SELECT_DISPLAY || command.GetDisplayId() != report.GetSelectedDisplayId() || command.GetRequestId() != result.GetRequestId() || result.GetStatus() != agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED || session.displayGeneration == ^uint32(0) || session.displayGeneration+1 != report.GetDisplayGeneration() {
				return false
			}
			session.displayFrame = nil
		} else if frame != nil && session.displayFrame != nil && !proto.Equal(frame, session.displayFrame) {
			return false
		}
	} else {
		session.granted = proto.CloneOf(report.GetGrantedCapabilities())
		session.displays = cloneAssistanceDisplays(report.GetDisplays())
		session.capabilitiesSet = true
	}
	if frame != nil {
		session.displayFrame = proto.CloneOf(frame)
	}
	session.selectedDisplayID, session.displayGeneration = report.GetSelectedDisplayId(), report.GetDisplayGeneration()
	return true
}

func assistanceBrokerCommandAllowed(session *assistanceSession, command *agentv1.AssistanceCommand) bool {
	policy := session.granted.GetPolicy()
	on := agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON
	switch command.GetKind() {
	case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_WRITE:
		return policy.GetClipboard() >= agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
	case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ:
		return policy.GetClipboard() == on
	case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SPECIAL_KEYS:
		return session.controlGranted && policy.GetKeyboard() == on
	case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE:
		return policy.GetMessages() >= agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
	case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SELECT_DISPLAY:
		if policy.GetDisplay() != on {
			return false
		}
		for _, display := range session.displays {
			if display.GetId() == command.GetDisplayId() {
				return true
			}
		}
	}
	return false
}

func (b *assistanceBroker) applyCommand(now time.Time, session *assistanceSession, command *agentv1.AssistanceCommand) {
	if session.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED {
		return
	}
	if command == nil {
		// Removal acknowledges a result or cancels the operation. A helper
		// must not execute a command absent from this complete snapshot.
		session.command, session.commandResult = nil, nil
		if session.commandTimer != nil {
			session.commandTimer.Stop()
		}
		return
	}
	if session.command != nil && session.command.GetRequestId() == command.GetRequestId() {
		if !proto.Equal(session.command, command) {
			b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "command_identity_changed")
		}
		return
	}
	encoded, err := proto.Marshal(command)
	if err != nil {
		b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "command_invalid")
		return
	}
	digest := sha256.Sum256(encoded)
	if old, seen := session.commandDigests[command.GetRequestId()]; seen {
		if old != digest {
			b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "command_identity_changed")
		}
		return
	}
	if len(session.commandDigests) >= 256 {
		b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "command_capacity")
		return
	}
	if session.phase != agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE || !assistanceBrokerCommandAllowed(session, command) || !now.Before(command.GetDeadline().AsTime()) || command.GetDeadline().AsTime().After(session.invitation.GetEndsAt().AsTime()) || command.GetDeadline().AsTime().After(now.Add(assistanceReauthorization)) {
		b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "command_not_authorized")
		return
	}
	if session.command != nil && session.commandResult == nil {
		b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "command_overlap")
		return
	}
	if session.commandDigests == nil {
		session.commandDigests = make(map[string][32]byte)
	}
	session.commandDigests[command.GetRequestId()] = digest
	session.command = proto.CloneOf(command)
	session.commandResult = nil
	session.commandDeadline = command.GetDeadline().AsTime()
	if session.commandTimer != nil {
		session.commandTimer.Stop()
	}
	accepted, deadline := session.command, session.commandDeadline
	// Expire plaintext even when both the network process and helper exit.
	session.commandTimer = time.AfterFunc(deadline.Sub(now), func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if session.command == accepted || session.commandResult.GetRequestId() == accepted.GetRequestId() {
			expireAssistanceCommand(session, deadline)
		}
	})
}

func (b *assistanceBroker) applyCommandResult(now time.Time, session *assistanceSession, result *agentv1.AssistanceCommandResult) {
	if result == nil {
		return
	}
	if session.commandResult != nil && result.GetRequestId() == session.commandResult.GetRequestId() {
		// The server's complete snapshot may have already acknowledged this.
		return
	}
	command := session.command
	if _, seen := session.commandDigests[result.GetRequestId()]; seen && command.GetRequestId() != result.GetRequestId() {
		return
	}
	if command == nil || command.GetRequestId() != result.GetRequestId() || command.GetKind() != result.GetKind() || session.phase != agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE || result.GetStatus() == agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_PENDING || !now.Before(command.GetDeadline().AsTime()) {
		b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "command_result_invalid")
		return
	}
	session.commandResult = proto.CloneOf(result)
}
