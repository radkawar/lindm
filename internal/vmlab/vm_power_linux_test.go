//go:build linux

package vmlab

import (
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestPowerActionObservationRejectsGrantOnlyUnknown(t *testing.T) {
	unknown := agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN
	for _, test := range []struct {
		name   string
		status *agentv1.DeviceActionStatus
		want   bool
	}{
		{"missing", nil, false},
		{"grant only", &agentv1.DeviceActionStatus{State: unknown}, false},
		{"root report", &agentv1.DeviceActionStatus{State: unknown, Verification: &agentv1.DeviceActionVerification{Evidence: "outcome_unknown_until_contact", PowerRequestAccepted: true}}, true},
		{"running", &agentv1.DeviceActionStatus{State: agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := powerActionObserved(test.status, unknown); got != test.want {
				t.Fatalf("observed=%v want %v", got, test.want)
			}
		})
	}
	if !powerActionObserved(&agentv1.DeviceActionStatus{State: agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED}, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED) {
		t.Fatal("completed restart/refresh result not recognized")
	}
}
