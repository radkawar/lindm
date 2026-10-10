package device

import (
	"bytes"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/identity"
)

func restartActionSpec() *agentv1.DeviceActionSpec {
	return &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Restart{Restart: &agentv1.RestartAction{}}}
}

func shutdownActionSpec() *agentv1.DeviceActionSpec {
	return &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Shutdown{Shutdown: &agentv1.ShutdownAction{}}}
}

func refreshActionSpec() *agentv1.DeviceActionSpec {
	return &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_RefreshInventory{RefreshInventory: &agentv1.RefreshInventoryAction{}}}
}

func TestPowerInventoryActionPermissionsAndDigest(t *testing.T) {
	for _, spec := range []*agentv1.DeviceActionSpec{restartActionSpec(), shutdownActionSpec(), refreshActionSpec()} {
		want := identity.PermissionRunRemoteExecution
		if spec.GetRefreshInventory() != nil {
			want = identity.PermissionManageInventory
		}
		if deviceActionPermission(spec) != want || destructiveDeviceAction(spec) {
			t.Fatal("imperative action has incorrect authority or mandatory destructive approval")
		}
	}
	for _, spec := range []*agentv1.DeviceActionSpec{restartActionSpec(), shutdownActionSpec()} {
		baseline, err := actionDigest(spec)
		if err != nil {
			t.Fatal(err)
		}
		for _, message := range []bool{false, true} {
			changed := proto.CloneOf(spec)
			if restart := changed.GetRestart(); restart != nil {
				if message {
					restart.Message = proto.String("maintenance")
				} else {
					restart.DelaySeconds = proto.Uint32(30)
				}
			} else if message {
				changed.GetShutdown().Message = proto.String("maintenance")
			} else {
				changed.GetShutdown().DelaySeconds = proto.Uint32(30)
			}
			digest, err := actionDigest(changed)
			if err != nil || bytes.Equal(baseline, digest) {
				t.Fatalf("power options absent from immutable request: %v", err)
			}
		}
	}
}

func TestRestartRequiresDifferentMatchingBootEvidence(t *testing.T) {
	challenge := &agentv1.DeviceActionChallenge{BootId: uuid.NewString()}
	boot := uuid.NewString()
	valid := &agentv1.DeviceActionStatus{State: agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, Verification: &agentv1.DeviceActionVerification{Verified: true, BootId: boot, After: &agentv1.DeviceActionObservation{Supported: true, BootId: boot}}}
	if err := validatePowerActionResult(restartActionSpec(), challenge, valid); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*agentv1.DeviceActionStatus){
		func(s *agentv1.DeviceActionStatus) { s.Verification = nil },
		func(s *agentv1.DeviceActionStatus) { s.Verification.Verified = false },
		func(s *agentv1.DeviceActionStatus) { s.Verification.BootId = "" },
		func(s *agentv1.DeviceActionStatus) {
			s.Verification.BootId = challenge.GetBootId()
			s.Verification.After.BootId = challenge.GetBootId()
		},
		func(s *agentv1.DeviceActionStatus) { s.Verification.After.BootId = uuid.NewString() },
		func(s *agentv1.DeviceActionStatus) { s.Verification.After.Supported = false },
	} {
		status := proto.CloneOf(valid)
		change(status)
		if err := validatePowerActionResult(restartActionSpec(), challenge, status); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("unproved restart accepted: %v", err)
		}
	}
}

func TestShutdownNeverClaimsVerifiedSuccess(t *testing.T) {
	status := &agentv1.DeviceActionStatus{State: agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN, Verification: &agentv1.DeviceActionVerification{PowerRequestAccepted: true, Evidence: "outcome_unknown_until_contact"}}
	if err := validatePowerActionResult(shutdownActionSpec(), nil, status); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*agentv1.DeviceActionStatus){
		func(s *agentv1.DeviceActionStatus) { s.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED },
		func(s *agentv1.DeviceActionStatus) { s.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_FAILED },
		func(s *agentv1.DeviceActionStatus) { s.Verification.Verified = true },
		func(s *agentv1.DeviceActionStatus) { s.Verification.Evidence = "powered_off" },
	} {
		invalid := proto.CloneOf(status)
		change(invalid)
		if err := validatePowerActionResult(shutdownActionSpec(), nil, invalid); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("false shutdown certainty accepted: %v", err)
		}
	}
}
