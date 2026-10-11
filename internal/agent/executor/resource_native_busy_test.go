//go:build linux

package executor

import (
	"fmt"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/osupdateprovider"
	"lindm/internal/agent/packageprovider"
)

// A granted resource change refused before its effect gate because another
// native frontend holds the package database (a release upgrade holding
// dpkg, or an OS update window run) is a signed NATIVE_BUSY failure without
// a start, never OUTCOME_UNKNOWN or a generic NATIVE failure.
func TestGrantedResourceRefusedBusyBeforeGateIsNativeBusy(t *testing.T) {
	for name, refusal := range map[string]error{
		"dpkg frontend lock": fmt.Errorf("%w: dpkg frontend lock held", packageprovider.ErrBusy),
		"os update run lock": osupdateprovider.ErrBusy,
	} {
		t.Run(name, func(t *testing.T) {
			f := newResourceFixture(t, false)
			f.native.refuse = refusal
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
		})
	}
}
