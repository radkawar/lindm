package devlab

import (
	"slices"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/trust"
)

// A console built with new action forms must not receive service-only signing
// authority. Reflecting the closed schema makes future action omissions visible.
func TestDefaultExecutionCapabilitiesCoverClosedDeviceActions(t *testing.T) {
	capabilities, err := defaultExecutionCapabilities()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(capabilities, "systemd.service.v1") {
		t.Fatal("default delegation lost service execution")
	}
	fields := (&agentv1.DeviceActionSpec{}).ProtoReflect().Descriptor().Oneofs().ByName("action").Fields()
	if len(capabilities) != fields.Len()+1 {
		t.Fatalf("default delegation has %d capabilities for %d actions plus services", len(capabilities), fields.Len())
	}
	for i := range fields.Len() {
		spec := new(agentv1.DeviceActionSpec)
		message := spec.ProtoReflect()
		field := fields.Get(i)
		message.Set(field, message.NewField(field))
		capability, err := trust.DeviceActionCapability(spec)
		if err != nil {
			t.Fatalf("action %s has no exact capability: %v", field.Name(), err)
		}
		if !slices.Contains(capabilities, capability) {
			t.Errorf("default delegation cannot execute %s (%s)", field.Name(), capability)
		}
	}
}
