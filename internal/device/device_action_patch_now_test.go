// SPDX-License-Identifier: Apache-2.0

package device

import (
	"testing"

	"lindm/internal/device/dispatch"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestPatchNowResultRequiresStartedRunWithoutPowerClaim(t *testing.T) {
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_PatchNow{PatchNow: &agentv1.PatchNowAction{}}}
	valid := &agentv1.DeviceActionStatus{State: agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, Verification: &agentv1.DeviceActionVerification{Verified: true, PatchRunStarted: true, Evidence: "native_patch_run_started"}}
	if err := dispatch.ValidatePatchNowResult(spec, valid); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*agentv1.DeviceActionStatus){
		func(s *agentv1.DeviceActionStatus) { s.Verification.Verified = false },
		func(s *agentv1.DeviceActionStatus) { s.Verification.PatchRunStarted = false },
		func(s *agentv1.DeviceActionStatus) { s.Verification.Evidence = "other" },
		func(s *agentv1.DeviceActionStatus) { s.Verification.PowerRequestAccepted = true },
	} {
		status := proto.CloneOf(valid)
		change(status)
		if err := dispatch.ValidatePatchNowResult(spec, status); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("unproved patch run accepted: %v", err)
		}
	}
	other := &agentv1.DeviceActionStatus{State: agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, Verification: &agentv1.DeviceActionVerification{Verified: true, PatchRunStarted: true}}
	if err := dispatch.ValidatePatchNowResult(restartActionSpec(), other); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("patch run claimed by other arm: %v", err)
	}
}
