// SPDX-License-Identifier: Apache-2.0

package assistance

import (
	"strings"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/auditkind"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
)

func TestTierThreePolicyNeverEnablesWithoutBoundsOrAboveTheCeiling(t *testing.T) {
	on, limited, off := agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
	if got := assistancePolicy(&agentv1.AssistancePolicy{Unattended: on}); got.GetUnattended() != off || got.GetUnattendedLimits() != nil {
		t.Fatalf("unbounded unattended policy enabled: %v", got)
	}
	limits := &agentv1.AssistanceUnattendedPolicy{MaxApprovalSeconds: 86400, MaxEnrollmentDays: 30, MaxSessionSeconds: 1800}
	request := &agentv1.AssistancePolicy{Unattended: on, UnattendedLimits: limits, Elevation: on, Annotation: on, Audio: on}
	ceiling := &agentv1.AssistancePolicy{Unattended: limited, UnattendedLimits: &agentv1.AssistanceUnattendedPolicy{MaxApprovalSeconds: 3600, MaxEnrollmentDays: 90, MaxSessionSeconds: 600}, Elevation: limited, Annotation: limited, Audio: limited}
	got := intersectAssistancePolicy(request, ceiling)
	if got.GetUnattended() != limited || got.GetElevation() != limited || got.GetAnnotation() != limited || got.GetAudio() != limited {
		t.Fatalf("modes widened: %v", got)
	}
	if got.GetUnattendedLimits().GetMaxApprovalSeconds() != 3600 || got.GetUnattendedLimits().GetMaxEnrollmentDays() != 30 || got.GetUnattendedLimits().GetMaxSessionSeconds() != 600 {
		t.Fatalf("unattended bounds widened: %v", got.GetUnattendedLimits())
	}
	if got := intersectAssistancePolicy(request, nil); got.GetUnattended() != off || got.GetElevation() != off || got.GetAnnotation() != off || got.GetAudio() != off {
		t.Fatalf("absent ceiling enabled a Tier 3 feature: %v", got)
	}
	validator, err := protovalidate.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(&agentv1.AssistancePolicy{Unattended: limited}); err == nil {
		t.Fatal("schema accepted unattended access without explicit bounds")
	}
}

func TestTierThreeCommandsNeedTheirOwnConsentedCapability(t *testing.T) {
	effective, err := proto.Marshal(&agentv1.AssistancePolicy{Elevation: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED, Annotation: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON})
	if err != nil {
		t.Fatal(err)
	}
	row := devicedb.AssistanceSession{Mode: int16(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW), EffectiveCapabilities: effective}
	elevation := &agentv1.AssistanceCommand{Kind: agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_ELEVATION_GUIDANCE}
	annotate := &agentv1.AssistanceCommand{Kind: agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_ANNOTATION, AnnotationEnabled: true}
	if assistanceCommandAllowed(row, elevation) || assistanceCommandAllowed(row, annotate) {
		t.Fatal("policy substituted for the local grant")
	}
	projection := &agentv1.AssistanceReport{GrantedCapabilities: &agentv1.AssistanceCapabilities{Policy: &agentv1.AssistancePolicy{Elevation: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED, Annotation: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED}}}
	if row.CapabilityProjection, err = proto.Marshal(projection); err != nil {
		t.Fatal(err)
	}
	if !assistanceCommandAllowed(row, elevation) || !assistanceCommandAllowed(row, annotate) {
		t.Fatal("granted guidance or pointer refused")
	}
	projection.Annotation = &agentv1.AssistanceAnnotationReport{Hidden: true}
	if row.CapabilityProjection, err = proto.Marshal(projection); err != nil {
		t.Fatal(err)
	}
	if assistanceCommandAllowed(row, annotate) {
		t.Fatal("operator re-enabled an overlay the employee hid")
	}
	if !assistanceCommandAllowed(row, &agentv1.AssistanceCommand{Kind: agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_ANNOTATION}) {
		t.Fatal("disabling a hidden overlay refused")
	}
	if got := assistanceCommandAuditKind(devicedb.AssistanceCommand{Kind: int16(agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_ANNOTATION), AnnotationEnabled: true}); got != auditkind.AssistanceAnnotationEnable {
		t.Fatalf("enable audit = %s", got)
	}
	if got := assistanceCommandAuditKind(devicedb.AssistanceCommand{Kind: int16(agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_ANNOTATION)}); got != auditkind.AssistanceAnnotationDisable {
		t.Fatalf("disable audit = %s", got)
	}
	if got := assistanceCommandAuditKind(devicedb.AssistanceCommand{Kind: int16(agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_ELEVATION_GUIDANCE)}); got != auditkind.AssistanceElevationRequest {
		t.Fatalf("guidance audit = %s", got)
	}
	// Guidance text is bounded and never part of the content-free audit.
	audit := strings.Join(assistanceOperationAudit(assistanceOperationMetadata(row, uuid.New(), &agentv1.AssistanceCommand{RequestId: uuid.NewString(), Kind: elevation.Kind, Text: "my password is hunter2"}), "denied", "input_paused"), " ")
	if strings.Contains(audit, "hunter2") {
		t.Fatal("guidance text reached the audit")
	}
}

func TestTierThreeSchemaBindsUnattendedAuthorityAndGuidance(t *testing.T) {
	validator, err := protovalidate.New(protovalidate.WithMessages(&adminv1.RunAssistanceCommandRequest{}, &adminv1.AuthorizeUnattendedAssistanceRequest{}, &adminv1.CreateAssistanceSessionRequest{}, &agentv1.AssistanceInvitation{}, &agentv1.AssistanceInputState{}), protovalidate.WithDisableLazy())
	if err != nil {
		t.Fatal(err)
	}
	command := func(kind agentv1.AssistanceCommandKind, text string, enabled bool) *adminv1.RunAssistanceCommandRequest {
		return &adminv1.RunAssistanceCommandRequest{SessionId: uuid.NewString(), Command: &agentv1.AssistanceCommand{RequestId: uuid.NewString(), Kind: kind, Text: text, AnnotationEnabled: enabled}}
	}
	for name, test := range map[string]struct {
		message proto.Message
		valid   bool
	}{
		"guidance note":         {command(agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_ELEVATION_GUIDANCE, "Enter your password", false), true},
		"guidance note bound":   {command(agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_ELEVATION_GUIDANCE, strings.Repeat("a", 513), false), false},
		"annotation enable":     {command(agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_ANNOTATION, "", true), true},
		"annotation with text":  {command(agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_ANNOTATION, "draw here", true), false},
		"enable flag elsewhere": {command(agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE, "hello", true), false},
		"pause reason unpaused": {&agentv1.AssistanceInputState{Epoch: 2, Pause: agentv1.AssistanceInputPause_ASSISTANCE_INPUT_PAUSE_ELEVATION}, false},
		"unattended enrollment offer": {&adminv1.CreateAssistanceSessionRequest{
			RequestId: uuid.NewString(), DeviceId: uuid.NewString(), Mode: agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, Reason: "support window",
			UnattendedGrantId: uuid.NewString(), RequestedCapabilities: &agentv1.AssistancePolicy{Unattended: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED},
		}, false},
		"grant with optional recording": {&adminv1.AuthorizeUnattendedAssistanceRequest{
			RequestId: uuid.NewString(), DeviceId: uuid.NewString(), Mode: agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, Reason: "support window",
			NotBefore: timestamppb.Now(), DurationSeconds: 3600, TargetUsername: "alice",
			RequestedCapabilities: &agentv1.AssistancePolicy{Recording: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED},
		}, false},
		"unattended without target": {&agentv1.AssistanceInvitation{
			SessionId: uuid.NewString(), Mode: agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, Reason: "support window", OperatorDisplay: "Olga",
			ConsentDeadline: timestamppb.Now(), EndsAt: timestamppb.New(time.Now().Add(time.Minute)),
			IceServers: []*agentv1.AssistanceIceServer{{Urls: []string{"turn:192.0.2.1:3478"}, Username: "u", Credential: "c"}},
			Unattended: &agentv1.AssistanceUnattendedAuthority{GrantId: uuid.NewString(), EnrollmentId: uuid.NewString(), ApproverDisplay: "Avery", ApprovedUntil: timestamppb.Now()},
		}, false},
	} {
		if err := validator.Validate(test.message); (err == nil) != test.valid {
			t.Fatalf("%s: valid = %v, error = %v", name, test.valid, err)
		}
	}
}

func TestUnattendedGrantStateAndScheduleNeverWiden(t *testing.T) {
	now := time.Now()
	row := devicedb.AssistanceUnattendedGrant{NotAfter: core.Timestamptz(now.Add(time.Hour))}
	if unattendedGrantState(row, now) != adminv1.AssistanceUnattendedGrantState_ASSISTANCE_UNATTENDED_GRANT_STATE_ACTIVE {
		t.Fatal("in-force grant not active")
	}
	if unattendedGrantState(row, now.Add(time.Hour)) != adminv1.AssistanceUnattendedGrantState_ASSISTANCE_UNATTENDED_GRANT_STATE_EXPIRED {
		t.Fatal("ended grant not expired")
	}
	row.RevokedAt = core.Timestamptz(now)
	if unattendedGrantState(row, now) != adminv1.AssistanceUnattendedGrantState_ASSISTANCE_UNATTENDED_GRANT_STATE_REVOKED {
		t.Fatal("revoked grant not revoked")
	}
	if decodeUnattendedSchedule(nil) != nil {
		t.Fatal("absent schedule decoded")
	}
	if corrupt := decodeUnattendedSchedule([]byte{0xff, 0xff}); corrupt == nil || len(corrupt.GetWindows()) != 0 {
		t.Fatal("a corrupt schedule widened to always")
	}
}
