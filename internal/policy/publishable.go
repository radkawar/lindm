package policy

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/reflect/protoreflect"

	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// ErrSettingEmpty refuses publication of a setting that names a resource but
// states nothing to enforce on it.
var ErrSettingEmpty = errors.New("profile_setting_empty")

// SettingError identifies the refused setting by its position in the caller's
// request and the desired-state arm that carries no effective content.
type SettingError struct {
	Index int
	State protoreflect.FieldDescriptor
}

func (e *SettingError) Error() string {
	return fmt.Sprintf("%s: resources[%d].desired.%s", ErrSettingEmpty, e.Index, e.State.Name())
}

func (e *SettingError) Unwrap() error { return ErrSettingEmpty }

// Publishable refuses settings that pass the schema but would publish no
// effective desired state. It applies only to new publications: retained
// revisions stay readable and executable as they were published.
//
// Every other kind's schema already requires content: an identity plus a managed
// dimension, a required oneof, a minimum item count or a constant requirement.
// A present firewall zone with no interface, source network or rule is the one
// schema-valid empty shape; it silently applies its default verdicts to all
// traffic. A deliberate catch-all zone lists 0.0.0.0/0 and ::/0.
func Publishable(spec *policyv1.ResourceProfile) error {
	for index, resource := range spec.GetResources() {
		zone := resource.GetDesired().GetFirewallZone()
		if zone == nil || zone.GetPresence() != resourcev1.Presence_PRESENCE_PRESENT {
			continue
		}
		if len(zone.GetInterfaces()) == 0 && len(zone.GetSourceNetworks()) == 0 && len(zone.GetRules()) == 0 {
			desired := resource.GetDesired().ProtoReflect()
			return &SettingError{Index: index, State: desired.WhichOneof(desired.Descriptor().Oneofs().ByName("state"))}
		}
	}
	return nil
}
