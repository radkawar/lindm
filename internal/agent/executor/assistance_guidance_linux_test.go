// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func tierThreePolicy(elevation agentv1.AssistancePolicyMode) *agentv1.AssistancePolicy {
	return &agentv1.AssistancePolicy{
		Keyboard:   agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON,
		Elevation:  elevation,
		Annotation: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON,
		Audio:      agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED,
	}
}

// activeTierThree brings a CONTROL session with the given grant to ACTIVE.
func activeTierThree(t *testing.T, granted *agentv1.AssistancePolicy, offer *agentv1.AssistanceUnattendedEnrollmentOffer) (*assistanceFixture, *agentv1.AssistanceDirective, *agentv1.SessionAssistanceReport) {
	t.Helper()
	f := newAssistanceFixture(t, true)
	policy := tierThreePolicy(agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED)
	if offer != nil {
		policy.Unattended = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
		policy.UnattendedLimits = &agentv1.AssistanceUnattendedPolicy{MaxApprovalSeconds: 3600, MaxEnrollmentDays: 30, MaxSessionSeconds: 1800}
	}
	f.broker.ceiling = proto.CloneOf(policy)
	directive := &agentv1.AssistanceDirective{Invitation: f.invitation(agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, "")}
	directive.Invitation.RequestedCapabilities, directive.Invitation.EffectiveCapabilities = proto.CloneOf(policy), proto.CloneOf(policy)
	directive.Invitation.UnattendedEnrollment = offer
	id := directive.GetInvitation().GetSessionId()
	f.network(directive)
	f.mustHelper(1000, report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED))
	observation := report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED)
	observation.ControlGranted = true
	observation.RequestedCapabilities, observation.EffectiveCapabilities = proto.CloneOf(policy), proto.CloneOf(policy)
	observation.GrantedCapabilities = &agentv1.AssistanceCapabilities{Policy: granted}
	observation.Displays = []*agentv1.AssistanceDisplay{{Id: "monitor-1", Label: "First display", Width: 1920, Height: 1080}}
	observation.SelectedDisplayId, observation.DisplayGeneration = "monitor-1", 1
	f.mustHelper(1000, observation)
	directive.AnswerSdp = "answer"
	f.network(directive)
	observation.Phase = agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE
	f.mustHelper(1000, observation)
	if state := f.network(directive)[id]; state.GetPhase() != agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE {
		t.Fatalf("session did not activate: %v", state)
	}
	return f, directive, observation
}

func TestBrokerRelaysOnlyGrantedElevationPauses(t *testing.T) {
	f, directive, observation := activeTierThree(t, tierThreePolicy(agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED), nil)
	id := directive.GetInvitation().GetSessionId()
	paused := proto.CloneOf(observation)
	paused.InputState = &agentv1.AssistanceInputState{Epoch: 2, Paused: true, Pause: agentv1.AssistanceInputPause_ASSISTANCE_INPUT_PAUSE_ELEVATION}
	f.mustHelper(1000, paused)
	state := f.network(directive)[id]
	if state.GetPhase() != agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE || state.GetInputState().GetPause() != agentv1.AssistanceInputPause_ASSISTANCE_INPUT_PAUSE_ELEVATION {
		t.Fatalf("granted elevation pause = %v", state)
	}
	resumed := proto.CloneOf(observation)
	resumed.InputState = &agentv1.AssistanceInputState{Epoch: 3}
	f.mustHelper(1000, resumed)
	if state := f.network(directive)[id]; state.GetPhase() != agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE || state.GetInputState().GetEpoch() != 3 || state.GetInputState().GetPaused() {
		t.Fatalf("local resume = %v", state)
	}

	g, other, base := activeTierThree(t, tierThreePolicy(agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF), nil)
	forged := proto.CloneOf(base)
	forged.InputState = &agentv1.AssistanceInputState{Epoch: 2, Paused: true, Pause: agentv1.AssistanceInputPause_ASSISTANCE_INPUT_PAUSE_ELEVATION}
	g.mustHelper(1000, forged)
	wantEnded(t, g.network(other)[other.GetInvitation().GetSessionId()], agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST)
}

func TestBrokerRefusesGuidanceReportsBeyondTheGrant(t *testing.T) {
	granted := tierThreePolicy(agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED)
	sharing := agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_SHARING
	stopped := agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_STOPPED
	for name, steps := range map[string][]func(*agentv1.SessionAssistanceReport){
		"microphone under limited": {func(r *agentv1.SessionAssistanceReport) {
			r.Audio = &agentv1.AssistanceAudioReport{State: sharing, OutputSource: "Speakers", MicrophoneSource: "Microphone"}
		}},
		"stopped sound restarts": {
			func(r *agentv1.SessionAssistanceReport) { r.Audio = &agentv1.AssistanceAudioReport{State: stopped} },
			func(r *agentv1.SessionAssistanceReport) {
				r.Audio = &agentv1.AssistanceAudioReport{State: sharing, OutputSource: "Speakers"}
			},
		},
		"hidden overlay reappears": {
			func(r *agentv1.SessionAssistanceReport) {
				r.Annotation = &agentv1.AssistanceAnnotationReport{Hidden: true, Clears: 1}
			},
			func(r *agentv1.SessionAssistanceReport) {
				r.Annotation = &agentv1.AssistanceAnnotationReport{Enabled: true, Clears: 1}
			},
		},
		"opt-in without an offer": {func(r *agentv1.SessionAssistanceReport) {
			r.Unattended = &agentv1.AssistanceUnattendedReport{EnrollmentId: "5e1f3a44-7d7b-4f0e-9c8e-1d2a3b4c5d6e", State: agentv1.AssistanceUnattendedEnrollmentState_ASSISTANCE_UNATTENDED_ENROLLMENT_STATE_ENROLLED}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			f, directive, observation := activeTierThree(t, proto.CloneOf(granted), nil)
			for _, step := range steps {
				step(observation)
				f.mustHelper(1000, observation)
			}
			wantEnded(t, f.network(directive)[directive.GetInvitation().GetSessionId()], agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST)
		})
	}
}

func TestBrokerRelaysTheOfferedOptInOnly(t *testing.T) {
	offer := &agentv1.AssistanceUnattendedEnrollmentOffer{EnrollmentId: "5e1f3a44-7d7b-4f0e-9c8e-1d2a3b4c5d6e", ExpiresAt: timestamppb.New(time.Now().Add(24 * time.Hour))}
	granted := tierThreePolicy(agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED)
	granted.Unattended = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
	granted.UnattendedLimits = &agentv1.AssistanceUnattendedPolicy{MaxApprovalSeconds: 3600, MaxEnrollmentDays: 30, MaxSessionSeconds: 1800}
	f, directive, observation := activeTierThree(t, granted, offer)
	observation.Unattended = &agentv1.AssistanceUnattendedReport{EnrollmentId: offer.GetEnrollmentId(), State: agentv1.AssistanceUnattendedEnrollmentState_ASSISTANCE_UNATTENDED_ENROLLMENT_STATE_ENROLLED}
	f.mustHelper(1000, observation)
	state := f.network(directive)[directive.GetInvitation().GetSessionId()]
	if state.GetPhase() != agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE || !proto.Equal(state.GetUnattended(), observation.GetUnattended()) {
		t.Fatalf("relayed opt-in = %v", state.GetUnattended())
	}
	observation.Unattended = &agentv1.AssistanceUnattendedReport{EnrollmentId: "00000000-0000-4000-8000-000000000001", State: agentv1.AssistanceUnattendedEnrollmentState_ASSISTANCE_UNATTENDED_ENROLLMENT_STATE_ENROLLED}
	f.mustHelper(1000, observation)
	wantEnded(t, f.network(directive)[directive.GetInvitation().GetSessionId()], agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST)
}
