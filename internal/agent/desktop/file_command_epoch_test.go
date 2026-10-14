// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"context"
	"testing"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestPrequeuedCommandsCannotReplayAcrossNativeModalEpoch(t *testing.T) {
	for _, kind := range []agentv1.AssistanceCommandKind{agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_WRITE, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SPECIAL_KEYS, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SELECT_DISPLAY} {
		t.Run(kind.String(), func(t *testing.T) {
			h := newHarness(t)
			grant := &fakeGrant{control: true, clipboard: true}
			input := newInputControl(grant, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, "monitor-1")
			s := &session{deps: h.helper.deps, invitation: filesInvitation(), phase: agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE, control: true, granted: grantedCapabilities(filesInvitation().RequestedCapabilities, grant), commands: make(chan *agentv1.AssistanceCommand, 1), commandHistory: make(map[string][32]byte), inputState: &agentv1.AssistanceInputState{Epoch: 1}, selected: "monitor-1", generation: 1}
			r := &sessionResources{grant: grant, input: input, commandDone: make(chan struct{})}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			r.modalMu.Lock()
			command := newTestCommand(h, 1, kind)
			switch kind {
			case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_WRITE:
				command.Text = "must be discarded"
			case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SPECIAL_KEYS:
				command.SpecialKey = agentv1.AssistanceSpecialKey_ASSISTANCE_SPECIAL_KEY_SWITCH_WINDOW
			case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SELECT_DISPLAY:
				command.DisplayId = "monitor-1"
			}
			s.applyCommand(command)
			go s.commandLoop(ctx, r)
			if _, err := input.pauseModal(ctx); err != nil {
				t.Fatal(err)
			}
			epoch, err := input.resumeModal()
			if err != nil {
				t.Fatal(err)
			}
			s.mu.Lock()
			s.inputState = &agentv1.AssistanceInputState{Epoch: epoch}
			s.mu.Unlock()
			r.modalMu.Unlock()
			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()
			deadline := time.NewTimer(time.Second)
			defer deadline.Stop()
			for {
				report, _ := s.report()
				if result := report.GetCommandResult(); result != nil {
					if result.GetStatus() != agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_CANCELLED {
						t.Fatal("prequeued operation replayed after local dialog")
					}
					break
				}
				select {
				case <-ticker.C:
				case <-deadline.C:
					t.Fatal("queued command not discarded")
				}
			}
			cancel()
			<-r.commandDone
			if events, _ := grant.snapshot(); len(events) != 0 {
				t.Fatal("queued input reached native grant")
			}
			if grant.writes != 0 {
				t.Fatal("queued clipboard reached native grant")
			}
		})
	}
}
