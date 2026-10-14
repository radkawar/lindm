// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func elevationPaused(state *agentv1.AssistanceInputState) bool {
	return state.GetPaused() && state.GetPause() == agentv1.AssistanceInputPause_ASSISTANCE_INPUT_PAUSE_ELEVATION
}

// elevationTransition admits an input epoch advance outside a file transfer:
// only a granted elevation pause, or the local resume that ends one.
func elevationTransition(session *assistanceSession, prior, input *agentv1.AssistanceInputState) bool {
	if assistancePolicyMode(session.granted.GetPolicy().GetElevation()) == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF {
		return false
	}
	return elevationPaused(input) || (elevationPaused(prior) && !input.GetPaused())
}

func audioLive(state agentv1.AssistanceAudioState) bool {
	return state == agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_SHARING || state == agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_MUTED
}

// applyGuidanceReport keeps the helper's audio, overlay and opt-in
// observations within the session's grant. Local decisions never regress:
// stopped sound does not restart, a hidden overlay does not reappear and the
// opt-in names only this invitation's offer or connection.
func applyGuidanceReport(session *assistanceSession, report *agentv1.SessionAssistanceReport) bool {
	grant := session.granted.GetPolicy()
	if elevationPaused(report.GetInputState()) && assistancePolicyMode(grant.GetElevation()) == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF {
		return false
	}
	audio := report.GetAudio()
	switch {
	case audio == nil && session.audio != nil:
		return false
	case audio == nil:
	case audioLive(audio.GetState()) && assistancePolicyMode(grant.GetAudio()) == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF:
		return false
	case audio.GetMicrophoneSource() != "" && grant.GetAudio() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON:
		return false
	case session.audio != nil && !audioLive(session.audio.GetState()) && audioLive(audio.GetState()):
		return false
	}
	annotation := report.GetAnnotation()
	if (annotation.GetEnabled() && assistancePolicyMode(grant.GetAnnotation()) == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF) ||
		(session.annotation.GetHidden() && !annotation.GetHidden()) || annotation.GetClears() < session.annotation.GetClears() {
		return false
	}
	if unattended := report.GetUnattended(); unattended != nil {
		offer, connection := session.invitation.GetUnattendedEnrollment().GetEnrollmentId(), session.invitation.GetUnattended().GetEnrollmentId()
		id := unattended.GetEnrollmentId()
		switch unattended.GetState() {
		case agentv1.AssistanceUnattendedEnrollmentState_ASSISTANCE_UNATTENDED_ENROLLMENT_STATE_ENROLLED:
			if offer == "" || id != offer || assistancePolicyMode(grant.GetUnattended()) == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF {
				return false
			}
		case agentv1.AssistanceUnattendedEnrollmentState_ASSISTANCE_UNATTENDED_ENROLLMENT_STATE_DECLINED:
			if offer == "" || id != offer {
				return false
			}
		default:
			if id != offer && id != connection {
				return false
			}
		}
		session.unattended = proto.CloneOf(unattended)
	}
	session.audio, session.annotation = proto.CloneOf(audio), proto.CloneOf(annotation)
	return true
}
