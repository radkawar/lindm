//go:build linux

package executor

import (
	"fmt"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/packageprovider"
)

// A granted package change refused before its effect gate because another
// native frontend (a release upgrade) holds dpkg is a signed NATIVE_BUSY
// failure without a start, never OUTCOME_UNKNOWN or a generic NATIVE failure.
func TestGrantedResourceRefusedBusyBeforeGateIsNativeBusy(t *testing.T) {
	f := newResourceFixture(t, false)
	f.native.refuse = fmt.Errorf("%w: dpkg frontend lock held", packageprovider.ErrBusy)
	intent := f.intent(t, 1)
	f.prepare(t, intent)
	startResource(t, f.svc, intent.GetActionId(), f.grant(t, intent))
	terminal := awaitResourceTerminal(t, f.svc, intent.GetActionId())
	if terminal.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED || terminal.GetFailure() != agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NATIVE_BUSY || terminal.GetStartedAt() != nil {
		t.Fatalf("busy refusal before the gate = %v", terminal)
	}
	if f.native.effects.Load() != 0 {
		t.Fatal("busy refusal reached a native effect")
	}
}
