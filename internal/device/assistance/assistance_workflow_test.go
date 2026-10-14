// SPDX-License-Identifier: Apache-2.0

package assistance

import (
	"crypto/rand"
	"testing"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/assistancerecording"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
)

func testWorkflowPolicy(reconnect, recording agentv1.AssistancePolicyMode) *agentv1.AssistancePolicy {
	return &agentv1.AssistancePolicy{
		Reconnect: reconnect, ReconnectLimits: &agentv1.AssistanceReconnectPolicy{WindowSeconds: 900, MaxReconnects: 3},
		Recording: recording, RecordingLimits: &agentv1.AssistanceRecordingPolicy{RetentionDays: 30, MaxBytes: 256 << 20},
	}
}

func TestAssistanceWorkflowPolicyNeverEnablesWithoutExplicitBounds(t *testing.T) {
	on, limited, off := agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
	unbounded := &agentv1.AssistancePolicy{Reconnect: on, Recording: on}
	if got := assistancePolicy(unbounded); got.GetReconnect() != off || got.GetRecording() != off || got.GetReconnectLimits() != nil || got.GetRecordingLimits() != nil {
		t.Fatalf("unbounded workflow policy enabled: %v", got)
	}
	ceiling := testWorkflowPolicy(limited, limited)
	ceiling.ReconnectLimits.WindowSeconds, ceiling.RecordingLimits.RetentionDays = 300, 7
	got := intersectAssistancePolicy(testWorkflowPolicy(on, on), ceiling)
	if got.GetReconnect() != limited || got.GetRecording() != limited || got.GetReconnectLimits().GetWindowSeconds() != 300 || got.GetRecordingLimits().GetRetentionDays() != 7 || got.GetRecordingLimits().GetMaxBytes() != 256<<20 {
		t.Fatalf("intersection widened workflow bounds: %v", got)
	}
	if got := intersectAssistancePolicy(testWorkflowPolicy(on, on), nil); got.GetReconnect() != off || got.GetRecording() != off {
		t.Fatal("absent ceiling enabled reconnect or recording")
	}
	validator, err := protovalidate.New()
	if err != nil {
		t.Fatal(err)
	}
	if validator.Validate(&agentv1.AssistancePolicy{Recording: limited}) == nil || validator.Validate(&agentv1.AssistancePolicy{Reconnect: limited}) == nil {
		t.Fatal("wire policy accepted enabled workflows without limits")
	}
	if validator.Validate(testWorkflowPolicy(on, on)) != nil {
		t.Fatal("bounded workflow policy rejected")
	}
}

func TestReconnectResumesOnlyAfterLogoutRebootLockOrLostConnection(t *testing.T) {
	for _, test := range []struct {
		cause  agentv1.AssistanceEndCause
		detail string
		want   bool
	}{
		{agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED, "logind_session_gone", true},
		{agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_LOCKED, "", true},
		{agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONNECTION_FAILED, "peer_connection_failed", true},
		{agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "device_unreachable", true},
		{agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "policy_changed", false},
		{agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "operator_authorization_lost", false},
		{agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED, "", false},
		{agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED, "", false},
		{agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED, "", false},
		{agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_PORTAL_CLOSED, "", false},
		{agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_EXPIRED, "", false},
		{agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_RECORDING_FAILED, "recording_failed", false},
		{agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DISABLED, "", false},
	} {
		if got := reconnectEligible(test.cause, test.detail); got != test.want {
			t.Fatalf("%v/%s eligible=%v, want %v", test.cause, test.detail, got, test.want)
		}
	}
}

func TestRecordingAuthorityIsImmutableAndBoundToTheDeploymentKey(t *testing.T) {
	seed := make([]byte, assistancerecording.PrivateKeySeedBytes)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	recipient, err := assistancerecording.NewRecipient(seed)
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{Service: &core.Service{AssistanceRecording: recipient}}
	row := devicedb.AssistanceRecording{ID: uuid.New(), Required: true, KeyID: recipient.KeyID(), MaxBytes: 64 << 20, RetentionDays: 14, State: recordingPending}
	first, err := s.assistanceRecordingAuthority(row)
	if err != nil {
		t.Fatal(err)
	}
	if err := protovalidate.Validate(first); err != nil {
		t.Fatalf("authority does not satisfy the device contract: %v", err)
	}
	row.State = recordingDeclined
	if second, err := s.assistanceRecordingAuthority(row); err != nil || !proto.Equal(first, second) {
		t.Fatal("authority changed with recording state; the executor would end the live session")
	}
	row.KeyID = assistancerecording.KeyID([]byte("replaced"))
	if _, err := s.assistanceRecordingAuthority(row); err == nil {
		t.Fatal("a replaced deployment key issued recording authority")
	}
	s.AssistanceRecording = nil
	if _, err := s.assistanceRecordingAuthority(row); err == nil {
		t.Fatal("unconfigured custody issued recording authority")
	}
}

func TestRecordingMetadataDisclosesNoKeyOrContent(t *testing.T) {
	row := devicedb.AssistanceRecording{ID: uuid.New(), SessionID: uuid.New(), DeviceID: uuid.New(), OperatorID: uuid.New(), State: recordingComplete, EncapsulatedKey: make([]byte, 1120), HashState: []byte("state"), CiphertextSha256: make([]byte, 32), KeyID: assistancerecording.KeyID([]byte("k"))}
	message := assistanceRecordingMessage(row)
	encoded, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > 1024 || message.GetState() != adminv1.AssistanceRecordingArchiveState_ASSISTANCE_RECORDING_ARCHIVE_STATE_COMPLETE || len(message.GetCiphertextSha256()) != 64 {
		t.Fatalf("metadata = %v", message)
	}
}
