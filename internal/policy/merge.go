package policy

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

// mergeDesired changes only the owned destination. Optional scalar presence is
// authoritative, including explicit false and zero. Repeated values are atomic:
// merging two different ordered lists would invent an unrequested policy.
func mergeDesired(dst, src *resourcev1.ResourceDesiredState) bool {
	left, right := dst.GetSystemdService(), src.GetSystemdService()
	if left != nil && right != nil {
		if left.Runtime == resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_UNMANAGED {
			left.Runtime = right.Runtime
		} else if right.Runtime != resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_UNMANAGED && left.Runtime != right.Runtime {
			return false
		}
		if left.Enablement == resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED {
			left.Enablement = right.Enablement
		} else if right.Enablement != resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED && left.Enablement != right.Enablement {
			return false
		}
		return proto.Equal(dst.GetRef(), src.GetRef()) && left.GetUnit() == right.GetUnit()
	}
	return mergeMessage(dst.ProtoReflect(), src.ProtoReflect())
}

func mergeMessage(dst, src protoreflect.Message) bool {
	fields := src.Descriptor().Fields()
	for i := range fields.Len() {
		field := fields.Get(i)
		// Scalars without presence and lists are fully specified, including
		// zero values and empty lists inside present managed-set wrappers.
		if !field.HasPresence() || field.IsList() || field.IsMap() {
			if !dst.Get(field).Equal(src.Get(field)) {
				return false
			}
			continue
		}
		if !src.Has(field) {
			continue
		}
		if oneof := field.ContainingOneof(); oneof != nil {
			if selected := dst.WhichOneof(oneof); selected != nil && selected != field {
				return false
			}
		}
		if !dst.Has(field) {
			value := src.Get(field)
			if field.Message() != nil {
				value = protoreflect.ValueOfMessage(proto.Clone(value.Message().Interface()).ProtoReflect())
			}
			dst.Set(field, value)
			continue
		}
		if field.Message() != nil && !field.IsList() && !field.IsMap() {
			if !mergeMessage(dst.Mutable(field).Message(), src.Get(field).Message()) {
				return false
			}
		} else if !dst.Get(field).Equal(src.Get(field)) {
			return false
		}
	}
	return true
}
