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

// canonicalSpec preserves semantic values while making resource/dependency order
// and UUID spelling irrelevant to immutable revision and request identities.
func canonicalSpec(ctx context.Context, input *policyv1.ServiceProfileSpec) (*policyv1.ServiceProfileSpec, [sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if err := Validate(ctx, input); err != nil {
		return nil, zero, err
	}
	spec := proto.CloneOf(input)
	for _, resource := range spec.GetResources() {
		id, err := uuid.Parse(resource.GetResourceId())
		if err != nil {
			return nil, zero, err
		}
		resource.ResourceId = id.String()
		for i, value := range resource.GetDependsOn() {
			dependency, err := uuid.Parse(value)
			if err != nil {
				return nil, zero, err
			}
			resource.DependsOn[i] = dependency.String()
		}
		slices.Sort(resource.DependsOn)
	}
	slices.SortFunc(spec.Resources, func(a, b *policyv1.ServiceProfileResource) int {
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
	return spec, sha256.Sum256(encoded), nil
}
