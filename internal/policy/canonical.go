package policy

import (
	"context"
	"crypto/sha256"
	"slices"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	policyv1 "lindm/gen/lindm/policy/v1"
)

// CanonicalSpec preserves semantic values while making resource/dependency order
// and UUID spelling irrelevant to immutable revision and request identities.
func CanonicalSpec(ctx context.Context, input *policyv1.ResourceProfile) (*policyv1.ResourceProfile, [sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if err := Validate(ctx, input); err != nil {
		return nil, zero, err
	}
	spec := proto.CloneOf(input)
	if _, err := canonicalizeSets(spec.ProtoReflect(), true); err != nil {
		return nil, zero, err
	}
	for _, resource := range spec.GetResources() {
		id, err := uuid.Parse(resource.GetResourceId())
		if err != nil {
			return nil, zero, err
		}
		resource.ResourceId = id.String()
		slices.SortFunc(resource.DependsOn, compareDependency)
	}
	slices.SortFunc(spec.Resources, func(a, b *policyv1.ProfileResource) int {
		return strings.Compare(a.GetResourceId(), b.GetResourceId())
	})
	// UUID aliases must not collapse two resources or dependencies after encoding.
	if err := Validate(ctx, spec); err != nil {
		return nil, zero, err
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(spec)
	if err != nil {
		return nil, zero, err
	}
	return spec, profileDigest(encoded), nil
}

func profileDigest(encoded []byte) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("lindm.resource-profile.spec.v1\x00"))
	_, _ = hash.Write(encoded)
	var digest [sha256.Size]byte
	hash.Sum(digest[:0])
	return digest
}
