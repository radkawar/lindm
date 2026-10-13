package dispatch

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
)

// Every action kind a client can filter by names the DeviceActionSpec field of
// the same number and maps to a distinct stored capability, so a filter can
// never silently match nothing or the wrong action after either enum changes.
func TestEveryActionKindMapsToItsSpecCapability(t *testing.T) {
	fields := (&agentv1.DeviceActionSpec{}).ProtoReflect().Descriptor().Oneofs().ByName("action").Fields()
	values := adminv1.DeviceActionKind(0).Descriptor().Values()
	if values.Len()-1 != fields.Len() {
		t.Fatalf("%d action kinds for %d spec actions", values.Len()-1, fields.Len())
	}
	seen := map[string]bool{}
	for i := range values.Len() {
		value := values.Get(i)
		if value.Number() == 0 {
			continue
		}
		field := fields.ByNumber(protoreflect.FieldNumber(value.Number()))
		if field == nil || "DEVICE_ACTION_KIND_"+strings.ToUpper(string(field.Name())) != string(value.Name()) {
			t.Fatalf("%s does not name spec field %d", value.Name(), value.Number())
		}
		capabilities, filter, err := actionKindCapabilities([]adminv1.DeviceActionKind{adminv1.DeviceActionKind(value.Number())})
		if err != nil || len(capabilities) != 1 || len(filter) != 1 || seen[capabilities[0]] {
			t.Fatalf("%s maps to %v, %v", value.Name(), capabilities, err)
		}
		seen[capabilities[0]] = true
	}
	if _, _, err := actionKindCapabilities([]adminv1.DeviceActionKind{99}); err == nil {
		t.Fatal("an undefined kind mapped to a capability")
	}
}
