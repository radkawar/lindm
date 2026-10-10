// Package policy retains immutable resource profile revisions and resolves
// assignments into deterministic previews. Catalog publication is separate
// from assignment activation and native execution.
package policy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/protodata"
	resourceidentity "lindm/internal/resource"
)

const maxAssignments = 128

// ResolutionState is the consumer-visible outcome of one canonical resource.
type ResolutionState int

const (
	ResolutionReady ResolutionState = iota + 1
	ResolutionConflict
	ResolutionBlocked
)

// ResolutionReason explains a non-ready outcome. ReasonNone accompanies a ready resource.
type ResolutionReason int

const (
	ReasonNone ResolutionReason = iota
	ReasonEqualPriority
	ReasonDependencyCycle
	ReasonDependencyConflict
	ReasonClaimConflict
)

// Assignment is one immutable profile revision competing at an explicit priority.
// Higher numeric priority wins. Equal priority merges complementary dimensions.
type Assignment struct {
	ProfileID  string
	RevisionID string
	Priority   int32
	Spec       *policyv1.ResourceProfile
}

// Contributor identifies one resource that participated in a resource outcome.
type Contributor struct {
	ProfileID  string
	RevisionID string
	ResourceID string
}

// Resolution is the deterministic preview for one canonical resource. Desired is
// owned by the result. It is nil when State is ResolutionConflict so a conflict
// cannot be applied as if a winner existed. A blocked result retains the merged
// intent for preview and must not be activated.
type Resolution struct {
	Ref          *resourcev1.ResourceRef
	Desired      *resourcev1.ResourceDesiredState
	Resource     *policyv1.ProfileResource
	State        ResolutionState
	Reason       ResolutionReason
	Contributors []Contributor
	Overridden   []Contributor
	Dependencies []*policyv1.ResourceDependency
}

var profileValidator = sync.OnceValues(func() (protovalidate.Validator, error) {
	return protovalidate.New(protovalidate.WithMessages(
		&policyv1.ResourceProfile{},
		&policyv1.ProfileResource{},
		&resourcev1.ResourceDesiredState{},
	), protovalidate.WithDisableLazy())
})

// Validate rejects a profile that violates the closed schema or contains a
// dependency cycle. The spec is not modified.
func Validate(ctx context.Context, spec *policyv1.ResourceProfile) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if spec == nil || !spec.ProtoReflect().IsValid() {
		return errors.New("absent resource profile")
	}
	if proto.Size(spec) > 1<<20 {
		return errors.New("resource profile exceeds storage limit")
	}
	if err := protodata.ValidateClosed(spec.ProtoReflect()); err != nil {
		return fmt.Errorf("resource profile: %w", err)
	}
	validator, err := profileValidator()
	if err != nil {
		return fmt.Errorf("compile resource profile rules: %w", err)
	}
	if err := validator.Validate(spec); err != nil {
		return fmt.Errorf("resource profile: %w", err)
	}
	for _, item := range spec.GetResources() {
		if err := resourceidentity.ValidateDesired(item.GetDesired()); err != nil {
			return fmt.Errorf("profile resource: %w", err)
		}
	}
	cyclic, err := dependencyCycle(ctx, spec)
	if err != nil {
		return err
	}
	if cyclic {
		return errors.New("resource profile dependency cycle")
	}
	return nil
}

type contender struct {
	profileID  string
	revisionID string
	priority   int32
	resource   *policyv1.ProfileResource
	deps       []*policyv1.ResourceDependency
}

// Resolve merges assigned profile revisions into one preview per canonical resource.
// Assignment order does not affect the result. Inputs are not modified.

func Resolve(ctx context.Context, assignments []Assignment) ([]Resolution, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(assignments) > maxAssignments {
		return nil, fmt.Errorf("resource profile assignments exceed %d", maxAssignments)
	}
	type assignmentKey struct {
		profileID  string
		revisionID string
		priority   int32
	}
	seen := make(map[assignmentKey]*policyv1.ResourceProfile, len(assignments))
	for i := range assignments {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		item := &assignments[i]
		if err := canonicalID("profile_id", item.ProfileID); err != nil {
			return nil, err
		}
		if err := canonicalID("revision_id", item.RevisionID); err != nil {
			return nil, err
		}
		if err := Validate(ctx, item.Spec); err != nil {
			return nil, err
		}
	}
	grouped := make(map[string][]contender)

	for i := range assignments {
		item := &assignments[i]
		spec := item.Spec
		ordered, err := canonicalizeSets(spec.ProtoReflect(), false)
		if err != nil {
			return nil, err
		}
		if !ordered {
			spec = proto.CloneOf(spec)
			if _, err := canonicalizeSets(spec.ProtoReflect(), true); err != nil {
				return nil, err
			}
		}
		key := assignmentKey{item.ProfileID, item.RevisionID, item.Priority}
		if previous, exists := seen[key]; exists {
			if !proto.Equal(previous, spec) {
				return nil, errors.New("inconsistent immutable profile assignment")
			}
			continue
		}
		seen[key] = spec
		for _, resource := range spec.GetResources() {
			unit := refKey(resource.GetDesired().GetRef())
			grouped[unit] = append(grouped[unit], contender{
				profileID:  item.ProfileID,
				revisionID: item.RevisionID,
				priority:   item.Priority,
				resource:   resource,
				deps:       resource.GetDependsOn(),
			})
		}
	}

	resolved := make(map[string]*Resolution, len(grouped))
	edges := make(map[string][]string, len(grouped))
	for unit, contenders := range grouped {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		maxPriority := contenders[0].priority
		for _, item := range contenders[1:] {
			if item.priority > maxPriority {
				maxPriority = item.priority
			}
		}
		var winners, losers []contender
		for _, item := range contenders {
			if item.priority == maxPriority {
				winners = append(winners, item)
			} else {
				losers = append(losers, item)
			}
		}
		resolution := &Resolution{
			Ref:          proto.CloneOf(winners[0].resource.GetDesired().GetRef()),
			State:        ResolutionReady,
			Contributors: contributors(winners),
			Overridden:   contributors(losers),
		}
		merged, ok := mergeResources(winners)
		if !ok {
			resolution.State = ResolutionConflict
			resolution.Reason = ReasonEqualPriority
			resolution.Dependencies = winnerDependencies(winners)
		} else {
			resolution.Resource = merged
			resolution.Desired = merged.GetDesired()
			resolution.Dependencies = merged.GetDependsOn()
		}
		resolved[unit] = resolution
		edges[unit] = dependencyKeys(resolution.Dependencies)
	}
	if err := markClaimConflicts(ctx, resolved); err != nil {
		return nil, err
	}

	cycles, err := markCycles(ctx, edges)
	if err != nil {
		return nil, err
	}
	for unit := range cycles {
		item := resolved[unit]
		if item.State == ResolutionReady {
			item.State = ResolutionConflict
			item.Reason = ReasonDependencyCycle
			item.Desired = nil
			item.Resource = nil
		}
	}
	if err := blockDependents(ctx, resolved); err != nil {
		return nil, err
	}

	units := make([]string, 0, len(resolved))
	for unit := range resolved {
		units = append(units, unit)
	}
	slices.Sort(units)
	out := make([]Resolution, len(units))
	for i, unit := range units {
		out[i] = *resolved[unit]
	}
	return out, nil
}

func canonicalID(name, value string) error {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || parsed.String() != value {
		return fmt.Errorf("malformed resource profile %s", name)
	}
	return nil
}

func contributors(items []contender) []Contributor {
	out := make([]Contributor, len(items))
	for i, item := range items {
		out[i] = Contributor{
			ProfileID:  item.profileID,
			RevisionID: item.revisionID,
			ResourceID: item.resource.GetResourceId(),
		}
	}
	slices.SortFunc(out, func(a, b Contributor) int {
		if c := cmpString(a.ProfileID, b.ProfileID); c != 0 {
			return c
		}
		if c := cmpString(a.RevisionID, b.RevisionID); c != 0 {
			return c
		}
		return cmpString(a.ResourceID, b.ResourceID)
	})
	return out
}

func cmpString(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func refKey(ref *resourcev1.ResourceRef) string {
	// A decimal kind followed by a colon is an unambiguous pair encoding.
	return fmt.Sprintf("%d:%s", ref.GetKind(), ref.GetCanonicalKey())
}

func dependencyKeys(deps []*policyv1.ResourceDependency) []string {
	keys := make([]string, len(deps))
	for i, dep := range deps {
		keys[i] = refKey(dep.GetRef())
	}
	return keys
}

func winnerDependencies(winners []contender) []*policyv1.ResourceDependency {
	var deps []*policyv1.ResourceDependency
	for _, item := range winners {
		for _, dep := range item.deps {
			deps = append(deps, proto.CloneOf(dep))
		}
	}
	slices.SortFunc(deps, compareDependency)
	return slices.CompactFunc(deps, func(a, b *policyv1.ResourceDependency) bool {
		return proto.Equal(a, b)
	})
}

func compareDependency(a, b *policyv1.ResourceDependency) int {
	if c := cmpString(refKey(a.GetRef()), refKey(b.GetRef())); c != 0 {
		return c
	}
	return int(a.GetCondition()) - int(b.GetCondition())
}

func mergeResources(winners []contender) (*policyv1.ProfileResource, bool) {
	slices.SortFunc(winners, func(a, b contender) int {
		if c := cmpString(a.profileID, b.profileID); c != 0 {
			return c
		}
		return cmpString(a.resource.GetResourceId(), b.resource.GetResourceId())
	})
	merged := proto.CloneOf(winners[0].resource)
	for _, item := range winners[1:] {
		source := item.resource
		// Metadata conveys authority and is never merged as desired dimensions.
		if !proto.Equal(merged.GetOwnership(), source.GetOwnership()) ||
			!proto.Equal(merged.GetVerification(), source.GetVerification()) ||
			!proto.Equal(merged.GetApplicability(), source.GetApplicability()) {
			return nil, false
		}
		if !mergeDesired(merged.Desired, source.GetDesired()) {
			return nil, false
		}
	}
	merged.DependsOn = winnerDependencies(winners)
	for i := 1; i < len(merged.DependsOn); i++ {
		if proto.Equal(merged.DependsOn[i-1].GetRef(), merged.DependsOn[i].GetRef()) {
			return nil, false
		}
	}
	if err := resourceidentity.ValidateDesired(merged.Desired); err != nil {
		return nil, false
	}
	return merged, true
}

func markClaimConflicts(ctx context.Context, resolved map[string]*Resolution) error {
	type claimed struct {
		item   *Resolution
		claims []*resourcev1.ResourceClaim
	}
	items := make([]claimed, 0, len(resolved))
	for _, item := range resolved {
		if item.State != ResolutionReady {
			continue
		}
		claims, err := resourceidentity.Claims(item.Desired)
		if err != nil {
			return err
		}
		items = append(items, claimed{item: item, claims: claims})
	}
	for i, left := range items {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, right := range items[i+1:] {
			if resourceidentity.Conflicts(left.claims, right.claims) {
				for _, item := range []*Resolution{left.item, right.item} {
					item.State, item.Reason = ResolutionConflict, ReasonClaimConflict
					item.Desired, item.Resource = nil, nil
				}
			}
		}
	}
	return nil
}

func dependencyCycle(ctx context.Context, spec *policyv1.ResourceProfile) (bool, error) {
	edges := make(map[string][]string, len(spec.GetResources()))
	for _, resource := range spec.GetResources() {
		edges[refKey(resource.GetDesired().GetRef())] = dependencyKeys(resource.GetDependsOn())
	}
	cycles, err := markCycles(ctx, edges)
	return len(cycles) != 0, err
}

// Tarjan's strongly connected components include branches that reach an already
// visited member of an open component; marking only DFS back-edge paths misses
// such members and incorrectly labels a cycle participant as merely blocked.
func markCycles(ctx context.Context, edges map[string][]string) (map[string]bool, error) {
	indices := make(map[string]int, len(edges))
	low := make(map[string]int, len(edges))
	open := make(map[string]bool, len(edges))
	cycles := make(map[string]bool)
	stack := make([]string, 0, len(edges))
	nextIndex := 1
	var visit func(string) error
	visit = func(node string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		indices[node], low[node] = nextIndex, nextIndex
		nextIndex++
		stack = append(stack, node)
		open[node] = true
		for _, next := range edges[node] {
			if indices[next] == 0 {
				if err := visit(next); err != nil {
					return err
				}
				low[node] = min(low[node], low[next])
			} else if open[next] {
				low[node] = min(low[node], indices[next])
			}
		}
		if low[node] != indices[node] {
			return nil
		}
		start := len(stack) - 1
		for stack[start] != node {
			start--
		}
		cyclic := len(stack)-start > 1 || slices.Contains(edges[node], node)
		for _, member := range stack[start:] {
			open[member] = false
			if cyclic {
				cycles[member] = true
			}
		}
		stack = stack[:start]
		return nil
	}
	for node := range edges {
		if indices[node] == 0 {
			if err := visit(node); err != nil {
				return nil, err
			}
		}
	}
	return cycles, nil
}

func blockDependents(ctx context.Context, resolved map[string]*Resolution) error {
	reverse := make(map[string][]string, len(resolved))
	queue := make([]string, 0, len(resolved))
	for unit, item := range resolved {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, dep := range item.Dependencies {
			dependency := refKey(dep.GetRef())
			reverse[dependency] = append(reverse[dependency], unit)
			if _, exists := resolved[dependency]; !exists && item.State == ResolutionReady {
				item.State = ResolutionBlocked
				item.Reason = ReasonDependencyConflict
			}
		}
		if item.State != ResolutionReady {
			queue = append(queue, unit)
		}
	}
	for index := 0; index < len(queue); index++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, dependent := range reverse[queue[index]] {
			item := resolved[dependent]
			if item.State == ResolutionReady {
				item.State = ResolutionBlocked
				item.Reason = ReasonDependencyConflict
				queue = append(queue, dependent)
			}
		}
	}
	return nil
}
