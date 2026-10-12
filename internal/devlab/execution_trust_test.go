package devlab

import (
	"os"
	"slices"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	orgv1 "lindm/gen/lindm/org/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
	"lindm/internal/trust"
)

// A persistent organization demo's delegation must let its signers execute every
// resource kind the maintained organization assigns; otherwise every profile row
// is refused by the agent as execution_signing_rejected. A disposable action
// lane keeps its narrow read-only grant.
func TestPersistentDemoDelegationCoversOrganizationResourceKinds(t *testing.T) {
	data, err := os.ReadFile("../../lab/demo/org.json")
	if err != nil {
		t.Fatal(err)
	}
	organization := new(orgv1.Organization)
	if err := protojson.Unmarshal(data, organization); err != nil {
		t.Fatal(err)
	}
	persistent, err := deviceActionDelegationCapabilities(true)
	if err != nil {
		t.Fatal(err)
	}
	disposable, err := deviceActionDelegationCapabilities(false)
	if err != nil {
		t.Fatal(err)
	}
	kinds := 0
	for _, profile := range organization.GetProfiles() {
		for _, row := range profile.GetSpec().GetResources() {
			capability, err := resource.Capability(row.GetDesired().GetRef().GetKind())
			if err != nil {
				t.Fatalf("%s: %v", profile.GetSpec().GetName(), err)
			}
			if !slices.Contains(persistent, capability) {
				t.Errorf("persistent demo delegation cannot execute %s (%s) from %s", row.GetDesired().GetRef().GetKind(), capability, profile.GetSpec().GetName())
			}
			kinds++
		}
	}
	if kinds == 0 {
		t.Fatal("maintained organization assigns no resources")
	}
	service, err := resource.Capability(resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(disposable, service) {
		t.Fatal("disposable action lane gained service execution")
	}
}

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
	if !slices.Contains(capabilities, "ssh.server.v1") {
		t.Fatal("default delegation lost the banner-only SSH provider")
	}
	fields := (&agentv1.DeviceActionSpec{}).ProtoReflect().Descriptor().Oneofs().ByName("action").Fields()
	if len(capabilities) != fields.Len()+len(executableResourceKinds) {
		t.Fatalf("default delegation has %d capabilities for %d actions plus %d resource kinds", len(capabilities), fields.Len(), len(executableResourceKinds))
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
