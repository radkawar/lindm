// SPDX-License-Identifier: Apache-2.0

package assistance

import (
	"context"
	"strconv"

	"github.com/google/uuid"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/auditkind"
	"lindm/internal/device/devicedb"
)

func elevationPaused(state *agentv1.AssistanceInputState) bool {
	return state.GetPaused() && state.GetPause() == agentv1.AssistanceInputPause_ASSISTANCE_INPUT_PAUSE_ELEVATION
}

func audioLive(state agentv1.AssistanceAudioState) bool {
	return state == agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_SHARING || state == agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_MUTED
}

// auditAssistanceGuidance checks device-observed elevation pause, audio and
// annotation state against the session grant and audits each transition. It
// returns a non-empty detail for a report that exceeds the grant or regresses
// a local decision. Audits never carry samples, drawing content or input.
func auditAssistanceGuidance(ctx context.Context, q *devicedb.Queries, row devicedb.AssistanceSession, previous, report *agentv1.AssistanceReport, grant *agentv1.AssistancePolicy) (string, error) {
	audit := func(action auditkind.Kind, pairs ...string) error {
		return recordAssistanceAudit(ctx, q, nil, action, row, "", pairs...)
	}
	input, before := report.GetInputState(), previous.GetInputState()
	switch {
	case elevationPaused(input) && !policyEnabled(grant.GetElevation()):
		return "elevation_without_grant", nil
	case elevationPaused(input) && !elevationPaused(before):
		if err := audit(auditkind.AssistanceElevationPause, "epoch", strconv.FormatUint(uint64(input.GetEpoch()), 10), "result", "paused"); err != nil {
			return "", err
		}
	case elevationPaused(before) && !elevationPaused(input):
		// Only the employee's local resume ends an elevation pause.
		if err := audit(auditkind.AssistanceElevationResume, "epoch", strconv.FormatUint(uint64(input.GetEpoch()), 10), "result", "resumed", "source", "local"); err != nil {
			return "", err
		}
	}

	audio, was := report.GetAudio(), previous.GetAudio()
	switch {
	case audio == nil && was != nil:
		return "audio_report_missing", nil
	case audio == nil:
	case audioLive(audio.GetState()) && !policyEnabled(grant.GetAudio()):
		return "audio_without_grant", nil
	case audio.GetMicrophoneSource() != "" && grant.GetAudio() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON:
		return "microphone_without_grant", nil
	case was != nil && !audioLive(was.GetState()) && audioLive(audio.GetState()):
		// Declined or stopped sound never restarts in the same session.
		return "audio_restarted", nil
	case was == nil:
		result := "declined"
		if audioLive(audio.GetState()) {
			result = "shared"
		}
		if err := audit(auditkind.AssistanceAudioConsent, "result", result, "output_source", audio.GetOutputSource(), "microphone", boolText(audio.GetMicrophoneSource() != ""), "microphone_source", audio.GetMicrophoneSource()); err != nil {
			return "", err
		}
	default:
		if audioLive(audio.GetState()) && (was.GetOutputSource() != audio.GetOutputSource() || was.GetMicrophoneSource() != audio.GetMicrophoneSource()) {
			if err := audit(auditkind.AssistanceAudioSource, "output_source", audio.GetOutputSource(), "microphone", boolText(audio.GetMicrophoneSource() != ""), "microphone_source", audio.GetMicrophoneSource(), "source", "local"); err != nil {
				return "", err
			}
		}
		muted := audio.GetState() == agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_MUTED
		if audioLive(audio.GetState()) && muted != (was.GetState() == agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_MUTED) {
			if err := audit(auditkind.AssistanceAudioMute, "muted", boolText(muted), "source", "local"); err != nil {
				return "", err
			}
		}
		if audioLive(was.GetState()) && audio.GetState() == agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_STOPPED {
			if err := audit(auditkind.AssistanceAudioStop, "reason", "local_stop"); err != nil {
				return "", err
			}
		}
	}

	annotation, shown := report.GetAnnotation(), previous.GetAnnotation()
	switch {
	case annotation.GetEnabled() && !policyEnabled(grant.GetAnnotation()):
		return "annotation_without_grant", nil
	case shown.GetHidden() && !annotation.GetHidden():
		return "annotation_unhidden", nil
	case annotation.GetClears() < shown.GetClears():
		return "annotation_clears_regressed", nil
	}
	if annotation.GetHidden() && !shown.GetHidden() {
		if err := audit(auditkind.AssistanceAnnotationDisable, "source", "local_hide"); err != nil {
			return "", err
		}
	}
	if annotation.GetClears() > shown.GetClears() {
		if err := audit(auditkind.AssistanceAnnotationClear, "source", "local", "clears", strconv.FormatUint(uint64(annotation.GetClears()), 10)); err != nil {
			return "", err
		}
	}
	return "", nil
}

// recordAssistanceMediaEnd audits audio that was still shared when the
// session ended; the helper stops capture with the session.
func recordAssistanceMediaEnd(ctx context.Context, q *devicedb.Queries, row devicedb.AssistanceSession, actor *uuid.UUID) error {
	if !audioLive(assistanceProjection(row).GetAudio().GetState()) {
		return nil
	}
	return recordAssistanceAudit(ctx, q, actor, auditkind.AssistanceAudioStop, row, "", "reason", "session_ended")
}
