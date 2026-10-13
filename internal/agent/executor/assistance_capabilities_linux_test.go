//go:build linux

package executor

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func assistanceAllCapabilities() *agentv1.AssistancePolicy {
	on := agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON
	return &agentv1.AssistancePolicy{Clipboard: on, Keyboard: on, Display: on, Messages: on}
}

func activeCapabilitiesFixture(t *testing.T) (*assistanceFixture, *agentv1.AssistanceDirective, *agentv1.SessionAssistanceReport) {
	t.Helper()
	f := newAssistanceFixture(t, true)
	f.broker.ceiling = assistanceAllCapabilities()
	directive := &agentv1.AssistanceDirective{Invitation: f.invitation(agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, "")}
	directive.Invitation.RequestedCapabilities, directive.Invitation.EffectiveCapabilities = assistanceAllCapabilities(), assistanceAllCapabilities()
	id := directive.GetInvitation().GetSessionId()
	f.network(directive)
	f.mustHelper(1000, report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED))
	observation := report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED)
	observation.ControlGranted = true
	observation.RequestedCapabilities, observation.EffectiveCapabilities = assistanceAllCapabilities(), assistanceAllCapabilities()
	observation.GrantedCapabilities = &agentv1.AssistanceCapabilities{Policy: assistanceAllCapabilities()}
	observation.Displays = []*agentv1.AssistanceDisplay{{Id: "monitor-1", Label: "First display", Width: 1920, Height: 1080}, {Id: "monitor-2", Label: "Second display", Width: 1280, Height: 720}}
	observation.SelectedDisplayId, observation.DisplayGeneration = "monitor-1", 1
	f.mustHelper(1000, observation)
	directive.AnswerSdp = "answer"
	f.network(directive)
	observation.Phase = agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE
	f.mustHelper(1000, observation)
	if state := f.network(directive)[id]; state.GetPhase() != agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE || state.GetGrantedCapabilities().GetPolicy().GetClipboard() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON {
		t.Fatal("negotiated capabilities did not reach network consumer")
	}
	return f, directive, observation
}

func TestAssistanceBrokerPropagatesBoundCommandAndCompletion(t *testing.T) {
	f, directive, observation := activeCapabilitiesFixture(t)
	id := directive.GetInvitation().GetSessionId()
	command := &agentv1.AssistanceCommand{RequestId: uuid.NewString(), Kind: agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ, Deadline: timestamppb.New(f.clock().Add(5 * time.Second))}
	directive.Command = command
	f.network(directive)
	if got := f.mustHelper(1000, observation)[id].GetCommand(); !proto.Equal(got, command) {
		t.Fatal("bound helper did not receive operation")
	}
	if got := f.mustHelper(1001); len(got) != 0 {
		t.Fatal("other UID received operation")
	}
	observation.CommandResult = &agentv1.AssistanceCommandResult{RequestId: command.GetRequestId(), Kind: command.GetKind(), Status: agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED, Text: "private clipboard", CompletedAt: timestamppb.New(f.clock())}
	f.mustHelper(1000, observation)
	if got := f.network(directive)[id].GetCommandResult(); got.GetText() != "private clipboard" {
		t.Fatal("completion did not propagate")
	}
	directive.Command = nil
	f.network(directive)
	if got := f.mustHelper(1000, observation)[id].GetCommand(); got != nil {
		t.Fatal("acknowledged operation remained executable")
	}
	directive.Command = command
	f.network(directive)
	if got := f.mustHelper(1000, observation)[id].GetCommand(); got != nil {
		t.Fatal("completed operation replayed after acknowledgement")
	}
	f.advance(5 * time.Second)
	state := f.network(directive)[id]
	if state.GetCommandResult().GetText() != "" || state.GetCommandResult().GetStatus() == agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED {
		t.Fatal("expired read became a successful empty clipboard")
	}
}

func TestAssistanceBrokerRejectsChangedCommandIdentity(t *testing.T) {
	f, directive, observation := activeCapabilitiesFixture(t)
	id := directive.GetInvitation().GetSessionId()
	directive.Command = &agentv1.AssistanceCommand{RequestId: uuid.NewString(), Kind: agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE, Text: "first", Deadline: timestamppb.New(f.clock().Add(5 * time.Second))}
	f.network(directive)
	f.mustHelper(1000, observation)
	directive.Command.Text = "different"
	state := f.network(directive)[id]
	wantEnded(t, state, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST)
	if state.GetCommandResult() != nil {
		t.Fatal("ended session retained content")
	}
}

func TestAssistanceBrokerNeverExtendsOperatorAuthorityFromPolling(t *testing.T) {
	f, directive, _ := activeCapabilitiesFixture(t)
	id := directive.GetInvitation().GetSessionId()
	directive.AuthorizedUntil = timestamppb.New(f.clock().Add(time.Second))
	if _, err := f.broker.syncNetwork(t.Context(), &agentv1.SyncAssistanceRequest{Directives: []*agentv1.AssistanceDirective{directive}}); err != nil {
		t.Fatal(err)
	}
	f.advance(time.Second)
	response, err := f.broker.syncNetwork(t.Context(), &agentv1.SyncAssistanceRequest{Directives: []*agentv1.AssistanceDirective{directive}})
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range response.GetReports() {
		if state.GetSessionId() == id {
			wantEnded(t, state, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST)
			return
		}
	}
	t.Fatal("expired session vanished instead of reporting termination")
}

func TestAssistanceBrokerDeviceCeilingAndUnsupportedGrant(t *testing.T) {
	f := newAssistanceFixture(t, true)
	f.broker.ceiling = &agentv1.AssistancePolicy{Clipboard: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED}
	directive := &agentv1.AssistanceDirective{Invitation: f.invitation(agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, "")}
	directive.Invitation.RequestedCapabilities, directive.Invitation.EffectiveCapabilities = assistanceAllCapabilities(), assistanceAllCapabilities()
	id := directive.GetInvitation().GetSessionId()
	f.network(directive)
	delivered := f.mustHelper(1000)[id].GetInvitation()
	if delivered.GetEffectiveCapabilities().GetClipboard() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED || delivered.GetEffectiveCapabilities().GetMessages() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF {
		t.Fatal("device ceiling did not constrain local prompt")
	}
	f.mustHelper(1000, report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED))
	observation := report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED)
	observation.ControlGranted = true
	observation.RequestedCapabilities = assistanceAllCapabilities()
	observation.EffectiveCapabilities = proto.CloneOf(delivered.GetEffectiveCapabilities())
	observation.GrantedCapabilities = &agentv1.AssistanceCapabilities{Policy: assistanceAllCapabilities()}
	f.mustHelper(1000, observation)
	wantEnded(t, f.network(directive)[id], agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST)
}

func TestAssistanceBrokerDisplayCompletionFencesSelection(t *testing.T) {
	f, directive, observation := activeCapabilitiesFixture(t)
	id := directive.GetInvitation().GetSessionId()
	observation.DisplayFrame = &agentv1.AssistanceDisplayFrame{DisplayId: "monitor-1", Generation: 1, RtpTimestamp: ^uint32(0)}
	f.mustHelper(1000, observation)
	directive.Command = &agentv1.AssistanceCommand{RequestId: uuid.NewString(), Kind: agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SELECT_DISPLAY, DisplayId: "monitor-2", Deadline: timestamppb.New(f.clock().Add(5 * time.Second))}
	f.network(directive)
	observation.SelectedDisplayId, observation.DisplayGeneration = "monitor-2", 2
	observation.DisplayFrame = &agentv1.AssistanceDisplayFrame{DisplayId: "monitor-2", Generation: 2, RtpTimestamp: 0}
	observation.CommandResult = &agentv1.AssistanceCommandResult{RequestId: directive.Command.GetRequestId(), Kind: directive.Command.GetKind(), Status: agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED, CompletedAt: timestamppb.New(f.clock())}
	f.mustHelper(1000, observation)
	state := f.network(directive)[id]
	if state.GetSelectedDisplayId() != "monitor-2" || state.GetDisplayGeneration() != 2 || state.GetCommandResult().GetStatus() != agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED {
		t.Fatal("display completion lost its coordinate fence")
	}
	if !proto.Equal(state.GetDisplayFrame(), observation.GetDisplayFrame()) {
		t.Fatal("display completion lost its emitted frame identity")
	}
	observation.SelectedDisplayId, observation.DisplayGeneration = "monitor-1", 3
	observation.DisplayFrame = &agentv1.AssistanceDisplayFrame{DisplayId: "monitor-1", Generation: 3, RtpTimestamp: 1}
	f.mustHelper(1000, observation)
	wantEnded(t, f.network(directive)[id], agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST)
}

func TestAssistanceBrokerBoundsFullSnapshots(t *testing.T) {
	f, directive, observation := activeCapabilitiesFixture(t)
	directive.Command = &agentv1.AssistanceCommand{RequestId: uuid.NewString(), Kind: agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_WRITE, Text: strings.Repeat("x", 16384), Deadline: timestamppb.New(f.clock().Add(5 * time.Second))}
	f.network(directive)
	response, err := f.helper(1000, observation)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := proto.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > 256<<10 {
		t.Fatal("session snapshot exceeded socket limit")
	}
	directive.Terminate = true
	directive.TerminateCause = agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED
	f.network(directive)
	response, err = f.helper(1000, observation)
	if err != nil {
		t.Fatal(err)
	}
	for _, stop := range response.GetDirectives() {
		if stop.GetCommand() != nil {
			t.Fatal("termination retained plaintext command")
		}
	}
}

func TestAssistanceBrokerFrameIdentityCannotChangeWithinGeneration(t *testing.T) {
	f, directive, observation := activeCapabilitiesFixture(t)
	id := directive.GetInvitation().GetSessionId()
	frame := &agentv1.AssistanceDisplayFrame{DisplayId: "monitor-1", Generation: 1, RtpTimestamp: 0}
	observation.DisplayFrame = proto.CloneOf(frame)
	f.mustHelper(1000, observation)
	if !proto.Equal(f.network(directive)[id].GetDisplayFrame(), frame) {
		t.Fatal("zero RTP timestamp was lost")
	}
	observation.DisplayFrame = nil
	f.mustHelper(1000, observation)
	if !proto.Equal(f.network(directive)[id].GetDisplayFrame(), frame) {
		t.Fatal("omission erased immutable first-frame identity")
	}
	observation.DisplayFrame = proto.CloneOf(frame)
	observation.DisplayFrame.RtpTimestamp = 1
	f.mustHelper(1000, observation)
	state := f.network(directive)[id]
	wantEnded(t, state, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST)
	if state.GetDisplayFrame() != nil {
		t.Fatal("ended session retained a live frame witness")
	}
}
