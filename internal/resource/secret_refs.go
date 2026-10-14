// SPDX-License-Identifier: Apache-2.0

package resource

import (
	"bytes"
	"errors"
	"slices"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

// MaxSecretRefs bounds the sealed deliveries one resource intent may carry.
const MaxSecretRefs = 8

// ErrSecretRefs reports a SecretRef in a field without a declared purpose, a
// purpose that differs from its field, or more references than one intent carries.
var ErrSecretRefs = errors.New("secret_binding_mismatch")

var secretRefName = (&resourcev1.SecretRef{}).ProtoReflect().Descriptor().FullName()

// The only fields that may hold a SecretRef and the purpose each one accepts.
// Schema CEL pins the same purposes; this closed table also rejects a field a
// later schema adds before its delivery is reviewed.
var secretFieldPurposes = map[protoreflect.FullName]resourcev1.SecretPurpose{
	secretField(&resourcev1.HashedPasswordPolicy{}, "hash"):              resourcev1.SecretPurpose_SECRET_PURPOSE_PASSWORD_HASH,
	secretField(&resourcev1.WiFi{}, "psk"):                               resourcev1.SecretPurpose_SECRET_PURPOSE_WIFI_PSK,
	secretField(&resourcev1.EAPCredential{}, "password"):                 resourcev1.SecretPurpose_SECRET_PURPOSE_EAP_PASSWORD,
	secretField(&resourcev1.WireGuard{}, "private_key"):                  resourcev1.SecretPurpose_SECRET_PURPOSE_WIREGUARD_PRIVATE_KEY,
	secretField(&resourcev1.WireGuardPeer{}, "preshared_key"):            resourcev1.SecretPurpose_SECRET_PURPOSE_WIREGUARD_PRESHARED_KEY,
	secretField(&resourcev1.ManualProxy{}, "authentication"):             resourcev1.SecretPurpose_SECRET_PURPOSE_PROXY_AUTHENTICATION,
	secretField(&resourcev1.RepositoryDesired{}, "authentication"):       resourcev1.SecretPurpose_SECRET_PURPOSE_REPOSITORY_AUTHENTICATION,
	secretField(&resourcev1.DirectoryClientDesired{}, "join_credential"): resourcev1.SecretPurpose_SECRET_PURPOSE_DIRECTORY_JOIN,
}

func secretField(message proto.Message, name protoreflect.Name) protoreflect.FullName {
	field := message.ProtoReflect().Descriptor().Fields().ByName(name)
	if field == nil || field.Message() == nil || field.Message().FullName() != secretRefName {
		panic("resource: secret field table names a non-SecretRef field")
	}
	return field.FullName()
}

// SecretRefs returns the references whose material one signed intent must
// deliver, in the deterministic order both the minting server and the
// executor use: populated fields in field-number order, depth first, list
// elements in order. Release restores owned baselines and needs no material,
// so it delivers nothing. Returned values are clones.
func SecretRefs(desired *resourcev1.ResourceDesiredState, operation resourcev1.ResourceOperation) ([]*resourcev1.SecretRef, error) {
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE || desired == nil {
		return nil, nil
	}
	var refs []*resourcev1.SecretRef
	if err := collectSecretRefs(desired.ProtoReflect(), &refs); err != nil {
		return nil, err
	}
	return refs, nil
}

func collectSecretRefs(message protoreflect.Message, refs *[]*resourcev1.SecretRef) error {
	fields := message.Descriptor().Fields()
	ordered := make([]protoreflect.FieldDescriptor, 0, fields.Len())
	for i := range fields.Len() {
		ordered = append(ordered, fields.Get(i))
	}
	slices.SortFunc(ordered, func(a, b protoreflect.FieldDescriptor) int { return int(a.Number() - b.Number()) })
	for _, field := range ordered {
		if field.Message() == nil || !message.Has(field) {
			continue
		}
		if field.IsMap() {
			// No resource schema uses maps; their order is not a delivery contract.
			return ErrSecretRefs
		}
		visit := func(value protoreflect.Message) error {
			if field.Message().FullName() != secretRefName {
				return collectSecretRefs(value, refs)
			}
			ref, ok := value.Interface().(*resourcev1.SecretRef)
			if !ok {
				return ErrSecretRefs
			}
			purpose, known := secretFieldPurposes[field.FullName()]
			if !known || field.IsList() || ref.GetPurpose() != purpose || len(*refs) == MaxSecretRefs {
				return ErrSecretRefs
			}
			*refs = append(*refs, proto.CloneOf(ref))
			return nil
		}
		if field.IsList() {
			list := message.Get(field).List()
			for i := range list.Len() {
				if err := visit(list.Get(i).Message()); err != nil {
					return err
				}
			}
			continue
		}
		if err := visit(message.Get(field).Message()); err != nil {
			return err
		}
	}
	return nil
}

// PasswordHashMatches reports whether a crypt(3) hash names algorithm. It
// checks only the scheme prefix; SecretMaterial validation owns the full shape.
func PasswordHashMatches(algorithm resourcev1.PasswordHashAlgorithm, hash []byte) bool {
	switch algorithm {
	case resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_YESCRYPT:
		return bytes.HasPrefix(hash, []byte("$y$"))
	case resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_SHA512_CRYPT:
		return bytes.HasPrefix(hash, []byte("$6$"))
	case resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_BCRYPT:
		return bytes.HasPrefix(hash, []byte("$2a$")) || bytes.HasPrefix(hash, []byte("$2b$")) || bytes.HasPrefix(hash, []byte("$2y$"))
	default:
		return false
	}
}
