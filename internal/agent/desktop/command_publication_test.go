package desktop

import (
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestDisplayProjectionPublishesOnlyWithSuccessfulCompletion(t *testing.T) {
	for _, success := range []bool{false, true} {
		h := newHarness(t)
		inv := tierOneInvitation(modeControl)
		s := &session{deps: h.helper.deps, invitation: inv, phase: agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE,
			offer: testOffer, selected: "monitor-1", generation: 1}
		// Capture and pointer fencing have already switched, but the helper's
		// externally visible report must still describe the prior selection.
		input := newInputControl(&fakeGrant{control: true}, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, "monitor-2")
		input.generation = 2
		input.paused = true
		s.frame = DisplayFrame{Display: "monitor-2", Generation: 2, RTPTimestamp: 0}
		before, _ := s.report()
		if before.GetSelectedDisplayId() != "monitor-1" || before.GetDisplayGeneration() != 1 || before.GetCommandResult() != nil {
			t.Fatal("native switch leaked before completion")
		}
		if before.GetDisplayFrame() != nil {
			t.Fatal("new-source frame leaked before atomic selection publication")
		}
		command := newTestCommand(h, 1, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SELECT_DISPLAY)
		command.DisplayId = "monitor-2"
		status := agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_EXPIRED
		reason := "command_deadline_reached"
		if success {
			status, reason = agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED, "display_selected"
		}
		result := commandResult(command, status, reason, h.clock.Now())
		_, incomplete := s.publishCommand(command, result, input)
		if input.paused == success {
			t.Fatal("input pause was not committed with the command outcome")
		}
		after, _ := s.report()
		if after.GetCommandResult().GetStatus() != status {
			t.Fatal("completion missing from projection snapshot")
		}
		if success {
			if incomplete || after.GetSelectedDisplayId() != "monitor-2" || after.GetDisplayGeneration() != 2 {
				t.Fatal("successful switch not atomically published")
			}
			frame := after.GetDisplayFrame()
			if frame == nil || frame.GetDisplayId() != "monitor-2" || frame.GetGeneration() != 2 || frame.GetRtpTimestamp() != 0 {
				t.Fatal("selection/result lost the exact wrapped frame witness")
			}
		} else if !incomplete || after.GetSelectedDisplayId() != "monitor-1" || after.GetDisplayGeneration() != 1 {
			t.Fatal("expired native switch was published instead of requiring terminal teardown")
		} else if after.GetDisplayFrame() != nil {
			t.Fatal("failed switch exposed a new-source frame")
		}
	}
}
