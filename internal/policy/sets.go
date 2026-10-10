package policy

import (
	"bytes"
	"fmt"
	"sort"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// canonicalizeSets sorts only fields whose resource contract is set-valued.
// Ordered native inputs (including SSH matches, firewall rules, routes, DNS
// servers/search domains and repository mirror URLs) deliberately are not here.
// With mutate=false it inspects immutable inputs without changing them.
func canonicalizeSets(message protoreflect.Message, mutate bool) (bool, error) {
	ordered := true
	var failure error
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.IsList() {
			list := value.List()
			if field.Message() != nil {
				for i := range list.Len() {
					childOrdered, err := canonicalizeSets(list.Get(i).Message(), mutate)
					if err != nil {
						failure = err
						return false
					}
					ordered = ordered && childOrdered
				}
			}
			if list.Len() < 2 || !isSetField(field.FullName()) {
				return true
			}
			set := canonicalSet{list: list, kind: field.Kind()}
			if field.Message() != nil {
				set.keys = make([][]byte, list.Len())
				for i := range list.Len() {
					encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(list.Get(i).Message().Interface())
					if err != nil {
						failure = fmt.Errorf("canonicalize %s: %w", field.FullName(), err)
						return false
					}
					set.keys[i] = encoded
				}
			}
			if !sort.IsSorted(set) {
				ordered = false
				if mutate {
					sort.Sort(set)
				}
			}
		} else if field.Message() != nil {
			childOrdered, err := canonicalizeSets(value.Message(), mutate)
			if err != nil {
				failure = err
				return false
			}
			ordered = ordered && childOrdered
		}
		return true
	})
	return ordered, failure
}

func isSetField(name protoreflect.FullName) bool {
	switch name {
	case "lindm.resource.v1.MemberSet.local_user_names",
		"lindm.resource.v1.SSHAccessList.names",
		"lindm.resource.v1.CertificateTrustRefs.certificates",
		"lindm.resource.v1.VerificationPolicy.checks",
		"lindm.resource.v1.Applicability.products",
		"lindm.resource.v1.Applicability.features",
		"lindm.resource.v1.EAPCredential.server_names",
		"lindm.resource.v1.AptRepository.architectures",
		"lindm.resource.v1.RpmRepository.signing_keys",
		"lindm.resource.v1.AlpmRepository.signing_keys",
		"lindm.resource.v1.NixInput.cache_public_keys",
		"lindm.resource.v1.OstreeRemote.commit_signing_keys",
		"lindm.resource.v1.FlatpakPermissionPolicy.devices",
		"lindm.resource.v1.FlatpakPermissionPolicy.portals",
		"lindm.resource.v1.MaintenanceWindow.weekdays",
		"lindm.resource.v1.RepositorySnapshot.signer_sha256",
		"lindm.resource.v1.RepositorySnapshots.repositories",
		"lindm.resource.v1.OSUpdateDesired.exclusions",
		"lindm.resource.v1.TrustCADesired.purposes",
		"lindm.resource.v1.CertificateEnrollmentDesired.eku",
		"lindm.resource.v1.CertificateEnrollmentDesired.sans",
		"lindm.resource.v1.CertificateEnrollmentDesired.consumers",
		"lindm.resource.v1.DirectoryLoginPolicy.permitted_groups":
		return true
	default:
		return false
	}
}

type canonicalSet struct {
	list protoreflect.List
	kind protoreflect.Kind
	keys [][]byte
}

func (s canonicalSet) Len() int { return s.list.Len() }

func (s canonicalSet) Less(i, j int) bool {
	left, right := s.list.Get(i), s.list.Get(j)
	switch s.kind {
	case protoreflect.StringKind:
		return left.String() < right.String()
	case protoreflect.EnumKind:
		return left.Enum() < right.Enum()
	case protoreflect.BytesKind:
		return bytes.Compare(left.Bytes(), right.Bytes()) < 0
	default:
		return bytes.Compare(s.keys[i], s.keys[j]) < 0
	}
}

func (s canonicalSet) Swap(i, j int) {
	left := s.list.Get(i)
	s.list.Set(i, s.list.Get(j))
	s.list.Set(j, left)
	if s.keys != nil {
		s.keys[i], s.keys[j] = s.keys[j], s.keys[i]
	}
}
