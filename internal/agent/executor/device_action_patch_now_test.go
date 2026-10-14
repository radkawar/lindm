// SPDX-License-Identifier: Apache-2.0

package executor

import (
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func patchNowSpec() *agentv1.DeviceActionSpec {
	return &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_PatchNow{PatchNow: &agentv1.PatchNowAction{Selection: resourcev1.UpdateSelection_UPDATE_SELECTION_SECURITY, RebootPolicy: &resourcev1.OSUpdateRebootPolicy{Mode: resourcev1.OSUpdateRebootMode_OS_UPDATE_REBOOT_MODE_NEVER}}}}
}

// A started native run is the whole action; verification without that native
// evidence is never success, and installation outcome is not claimed here.
func TestPatchNowSucceedsOnlyOnStartedNativeRun(t *testing.T) {
	for _, tc := range []struct {
		name    string
		started bool
		want    agentv1.DeviceActionState
	}{
		{"started", true, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED},
		{"verified-without-run", false, agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDeviceActionFixture(t)
			i := f.actionIntent(t, 1, patchNowSpec())
			f.actionPrepare(t, i)
			grant := f.actionGrant(t, i)
			r, _ := deviceActionRow(t, f.svc, i.GetActionId())
			if _, err := f.svc.consumeDeviceAction(t.Context(), r, grant, false); err != nil {
				t.Fatal(err)
			}
			verification := &agentv1.DeviceActionVerification{Verified: true, After: r.GetNativePlan().GetBefore()}
			if tc.started {
				verification.PatchRunStarted, verification.Evidence = true, "native_patch_run_started"
			}
			f.svc.finishDeviceAction(i.GetActionId(), verification, nil, nil, false)
			status := awaitDeviceAction(t, f.svc, i.GetActionId(), tc.want)
			if status.GetVerification().GetPatchRunStarted() != tc.started || status.GetVerification().GetPowerRequestAccepted() {
				t.Fatalf("patch now status: %v", status)
			}
		})
	}
}
