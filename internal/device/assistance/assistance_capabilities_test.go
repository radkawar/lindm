// SPDX-License-Identifier: Apache-2.0

package assistance

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
)

func allAssistanceCapabilities() *agentv1.AssistancePolicy {
	on := agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON
	return &agentv1.AssistancePolicy{Clipboard: on, Keyboard: on, Display: on, Messages: on}
}

func TestAssistancePolicyIntersectionDeniesUnconfiguredFeatures(t *testing.T) {
	on := allAssistanceCapabilities()
	if got := intersectAssistancePolicy(on, nil); got.GetClipboard() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF || got.GetKeyboard() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF || got.GetDisplay() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF || got.GetMessages() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF {
		t.Fatal("absent ceiling enabled a feature")
	}
	limited := &agentv1.AssistancePolicy{Clipboard: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED}
	got := intersectAssistancePolicy(on, limited)
	if got.GetClipboard() != limited.GetClipboard() || got.GetMessages() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF {
		t.Fatal("independent policy modes widened")
	}
	if !proto.Equal(decodeAssistancePolicy([]byte{0xff}), assistancePolicy(nil)) {
		t.Fatal("corrupt persisted policy did not fail closed")
	}
}

func TestAssistanceCommandsRequireActualConsentedCapability(t *testing.T) {
	effective, err := proto.Marshal(allAssistanceCapabilities())
	if err != nil {
		t.Fatal(err)
	}
	row := devicedb.AssistanceSession{Mode: int16(agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL), ControlGranted: true, EffectiveCapabilities: effective}
	command := &agentv1.AssistanceCommand{Kind: agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_WRITE}
	if assistanceCommandAllowed(row, command) {
		t.Fatal("requested capability substituted for local grant")
	}
	projection := &agentv1.AssistanceReport{GrantedCapabilities: &agentv1.AssistanceCapabilities{Policy: &agentv1.AssistancePolicy{Clipboard: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED}, KeyboardReason: "unsupported"}}
	row.CapabilityProjection, err = proto.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	if !assistanceCommandAllowed(row, command) {
		t.Fatal("limited clipboard should allow operator to user")
	}
	command.Kind = agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ
	if assistanceCommandAllowed(row, command) {
		t.Fatal("limited clipboard leaked local contents")
	}
	command.Kind = agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SPECIAL_KEYS
	if assistanceCommandAllowed(row, command) {
		t.Fatal("unsupported keyboard accepted shortcut")
	}
	projection.GrantedCapabilities.Policy = allAssistanceCapabilities()
	projection.Displays = []*agentv1.AssistanceDisplay{{Id: "monitor-1", Label: "Display", Width: 1920, Height: 1080}}
	row.CapabilityProjection, err = proto.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	command.Kind, command.DisplayId = agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SELECT_DISPLAY, "monitor-2"
	if assistanceCommandAllowed(row, command) {
		t.Fatal("selected unconsented monitor")
	}
	command.DisplayId = "monitor-1"
	if !assistanceCommandAllowed(row, command) {
		t.Fatal("consented monitor unavailable")
	}
}

func TestAssistanceCommandSchemaProtectsPayloadAndAuthority(t *testing.T) {
	validator, err := protovalidate.New(protovalidate.WithMessages(&adminv1.RunAssistanceCommandRequest{}, &adminv1.AnswerAssistanceSessionRequest{}, &agentv1.AssistanceDirective{}, &agentv1.AssistanceCommandResult{}, &agentv1.AssistanceDisplay{}), protovalidate.WithDisableLazy())
	if err != nil {
		t.Fatal(err)
	}
	base := &adminv1.RunAssistanceCommandRequest{SessionId: uuid.NewString(), Command: &agentv1.AssistanceCommand{RequestId: uuid.NewString(), Kind: agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE, Text: "plain notification"}}
	for _, test := range []struct {
		name   string
		change func(*adminv1.RunAssistanceCommandRequest)
		valid  bool
	}{
		{"plain", func(*adminv1.RunAssistanceCommandRequest) {}, true},
		{"caller deadline", func(r *adminv1.RunAssistanceCommandRequest) {
			r.Command.Deadline = timestamppb.New(time.Now().Add(time.Hour))
		}, false},
		{"message bytes", func(r *adminv1.RunAssistanceCommandRequest) { r.Command.Text = strings.Repeat("é", 1025) }, false},
		{"clipboard bound", func(r *adminv1.RunAssistanceCommandRequest) {
			r.Command.Kind = agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_WRITE
			r.Command.Text = strings.Repeat("a", 16385)
		}, false},
		{"read input content", func(r *adminv1.RunAssistanceCommandRequest) {
			r.Command.Kind = agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ
		}, false},
		{"arbitrary special key", func(r *adminv1.RunAssistanceCommandRequest) {
			r.Command.Kind = agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SPECIAL_KEYS
			r.Command.Text = ""
			r.Command.SpecialKey = agentv1.AssistanceSpecialKey(99)
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := proto.CloneOf(base)
			test.change(request)
			if (validator.Validate(request) == nil) != test.valid {
				t.Fatal("unexpected schema admission")
			}
		})
	}
	result := &agentv1.AssistanceCommandResult{RequestId: uuid.NewString(), Kind: agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE, Status: agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED, Text: "must not echo notification", CompletedAt: timestamppb.Now()}
	if validator.Validate(result) == nil {
		t.Fatal("non-clipboard result admitted text")
	}
	display := &agentv1.AssistanceDisplay{Id: "monitor-1", Label: strings.Repeat("é", 65), Width: 1920, Height: 1080}
	if validator.Validate(display) == nil {
		t.Fatal("display label exceeded byte budget")
	}
	answer := &adminv1.AnswerAssistanceSessionRequest{SessionId: uuid.NewString(), AnswerSdp: strings.Repeat("a", 16384)}
	if err := validator.Validate(answer); err != nil {
		t.Fatalf("bounded SDP rejected by wire schema: %v", err)
	}
	answer.AnswerSdp = strings.Repeat("é", 8193)
	if validator.Validate(answer) == nil {
		t.Fatal("SDP character limit allowed oversized UTF8 payload")
	}
}

func TestAssistanceOperationAuditWhitelistsContentFreeMetadata(t *testing.T) {
	policy, err := proto.Marshal(allAssistanceCapabilities())
	if err != nil {
		t.Fatal(err)
	}
	row := devicedb.AssistanceSession{ID: uuid.New(), DeviceID: uuid.New(), EffectiveCapabilities: policy}
	secret := "do-not-audit-秘密"
	digest := sha256.Sum256([]byte(secret))
	for _, tc := range []struct {
		name     string
		command  *agentv1.AssistanceCommand
		expected map[string]string
	}{
		{"clipboard write", &agentv1.AssistanceCommand{Kind: agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_WRITE, Text: secret}, map[string]string{"direction": "operator_to_user", "bytes": strconv.Itoa(len(secret))}},
		{"clipboard read", &agentv1.AssistanceCommand{Kind: agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ}, map[string]string{"direction": "user_to_operator"}},
		{"named chord", &agentv1.AssistanceCommand{Kind: agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SPECIAL_KEYS, SpecialKey: agentv1.AssistanceSpecialKey_ASSISTANCE_SPECIAL_KEY_OPEN_TERMINAL}, map[string]string{"chord": "open_terminal"}},
		{"display", &agentv1.AssistanceCommand{Kind: agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SELECT_DISPLAY, DisplayId: strings.Repeat("x", 64)}, map[string]string{"display": strings.Repeat("x", 64)}},
		{"message", &agentv1.AssistanceCommand{Kind: agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE, Text: secret}, map[string]string{"bytes": strconv.Itoa(len(secret))}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.command.RequestId = uuid.NewString()
			operation := assistanceOperationMetadata(row, uuid.New(), tc.command)
			operation.RequestDigest = digest[:]
			got := core.AuditDetails(assistanceOperationAudit(operation, "denied", "capability_not_granted")...)
			for key, value := range map[string]string{"request": tc.command.GetRequestId(), "result": "denied", "reason": "capability_not_granted", "clipboard": "on", "keyboard": "on", "display_policy": "on", "messages": "on"} {
				tc.expected[key] = value
			}
			for key, expected := range tc.expected {
				if got[key] != expected {
					t.Fatalf("metadata %s = %q, want %q", key, got[key], expected)
				}
			}
			for key, value := range got {
				if strings.Contains(value, secret) || strings.Contains(value, hex.EncodeToString(digest[:])) {
					t.Fatalf("plaintext or low-entropy digest disclosed in audit field %s", key)
				}
			}
			if _, duplicated := got["device"]; duplicated {
				t.Fatal("device identity belongs in typed target_device_id")
			}
			if len(got) > 32 {
				t.Fatal("audit exceeds structured field bound")
			}
		})
	}
}

func TestAssistanceDisplayFrameSchemaBindsGrantedSelection(t *testing.T) {
	validator, err := protovalidate.New(protovalidate.WithMessages(&agentv1.AssistanceReport{}, &agentv1.SessionAssistanceReport{}, &adminv1.AssistanceSession{}), protovalidate.WithDisableLazy())
	if err != nil {
		t.Fatal(err)
	}
	base := &agentv1.AssistanceReport{
		SessionId: uuid.NewString(), Phase: agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE, OfferSdp: "offer",
		Displays:          []*agentv1.AssistanceDisplay{{Id: "monitor-1", Label: "Display", Width: 1920, Height: 1080}},
		SelectedDisplayId: "monitor-1", DisplayGeneration: 1,
		DisplayFrame: &agentv1.AssistanceDisplayFrame{DisplayId: "monitor-1", Generation: 1, RtpTimestamp: 0},
	}
	for _, tc := range []struct {
		name   string
		change func(*agentv1.AssistanceReport)
		valid  bool
	}{
		{"zero timestamp", func(*agentv1.AssistanceReport) {}, true},
		{"timestamp wrap", func(r *agentv1.AssistanceReport) { r.DisplayFrame.RtpTimestamp = ^uint32(0) }, true},
		{"not emitted", func(r *agentv1.AssistanceReport) { r.DisplayFrame = nil }, true},
		{"wrong source", func(r *agentv1.AssistanceReport) { r.DisplayFrame.DisplayId = "monitor-2" }, false},
		{"wrong generation", func(r *agentv1.AssistanceReport) { r.DisplayFrame.Generation = 2 }, false},
		{"zero generation", func(r *agentv1.AssistanceReport) { r.DisplayFrame.Generation = 0 }, false},
		{"ungranted source", func(r *agentv1.AssistanceReport) { r.Displays = nil }, false},
		{"ended", func(r *agentv1.AssistanceReport) {
			r.Phase = agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED
			r.EndCause = agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := proto.CloneOf(base)
			tc.change(report)
			if (validator.Validate(report) == nil) != tc.valid {
				t.Fatal("device report admitted the wrong frame identity")
			}
			helper := &agentv1.SessionAssistanceReport{SessionId: report.SessionId, Phase: report.Phase, OfferSdp: report.OfferSdp, EndCause: report.EndCause, Displays: report.Displays, SelectedDisplayId: report.SelectedDisplayId, DisplayGeneration: report.DisplayGeneration, DisplayFrame: report.DisplayFrame}
			if (validator.Validate(helper) == nil) != tc.valid {
				t.Fatal("helper report admitted the wrong frame identity")
			}
			if tc.name == "ended" {
				return
			}
			session := &adminv1.AssistanceSession{Displays: report.Displays, SelectedDisplayId: report.SelectedDisplayId, DisplayGeneration: report.DisplayGeneration, DisplayFrame: report.DisplayFrame}
			if (validator.Validate(session) == nil) != tc.valid {
				t.Fatal("operator projection admitted the wrong frame identity")
			}
		})
	}
}
