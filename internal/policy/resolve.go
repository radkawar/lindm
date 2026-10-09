// Package policy retains immutable service profile revisions and resolves
// assigned revisions into deterministic per-unit previews. Catalog publication
// is separate from assignment activation and native execution.
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

	agentv1 "lindm/gen/lindm/agent/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/protodata"
)

const maxAssignments = 128

// ResolutionState is the consumer-visible outcome of one canonical unit.
type ResolutionState int

const (
	ResolutionReady ResolutionState = iota + 1
	ResolutionConflict
	ResolutionBlocked
)

// ResolutionReason explains a non-ready outcome. ReasonNone accompanies a ready unit.
type ResolutionReason int

const (
	ReasonNone ResolutionReason = iota
	ReasonEqualPriority
	ReasonDependencyCycle
	ReasonDependencyConflict
)

// Assignment is one immutable profile revision competing at an explicit priority.
// Higher numeric priority wins. Equal priority merges complementary dimensions.
type Assignment struct {
	ProfileID  string
	RevisionID string
	Priority   int32
	Spec       *policyv1.ServiceProfileSpec
}

// Contributor identifies one resource that participated in a unit outcome.
type Contributor struct {
	ProfileID  string
	RevisionID string
	ResourceID string
}

// Resolution is the deterministic preview for one canonical unit. Desired is
// owned by the result. It is nil when State is ResolutionConflict so a conflict
// cannot be applied as if a winner existed. A blocked result retains the merged
// intent for preview and must not be activated.
type Resolution struct {
	Unit         string
	Desired      *agentv1.ServiceDesiredState
	State        ResolutionState
	Reason       ResolutionReason
	Contributors []Contributor
	Overridden   []Contributor
	Dependencies []string
}

var profileValidator = sync.OnceValues(func() (protovalidate.Validator, error) {
	return protovalidate.New(protovalidate.WithMessages(
		&policyv1.ServiceProfileSpec{},
		&policyv1.ServiceProfileResource{},
		&agentv1.ServiceDesiredState{},
	), protovalidate.WithDisableLazy())
})

// Validate rejects a profile that violates the closed schema or contains a
// dependency cycle. The spec is not modified.
func Validate(ctx context.Context, spec *policyv1.ServiceProfileSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if spec == nil || !spec.ProtoReflect().IsValid() {
		return errors.New("absent service profile")
	}
	if err := protodata.ValidateClosed(spec.ProtoReflect()); err != nil {
		return fmt.Errorf("service profile: %w", err)
	}
	validator, err := profileValidator()
	if err != nil {
		return fmt.Errorf("compile service profile rules: %w", err)
	}
	if err := validator.Validate(spec); err != nil {
		return fmt.Errorf("service profile: %w", err)
	}
	cyclic, err := dependencyCycle(ctx, spec)
	if err != nil {
		return err
	}
	if cyclic {
		return errors.New("service profile dependency cycle")
	}
	return nil
}

type contender struct {
	profileID  string
	revisionID string
	priority   int32
	resource   *policyv1.ServiceProfileResource
	deps       []string
}

// Resolve merges assigned profile revisions into one preview per canonical unit.
// Assignment order does not affect the result. Inputs are not modified.

func Resolve(ctx context.Context, assignments []Assignment) ([]Resolution, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(assignments) > maxAssignments {
		return nil, fmt.Errorf("service profile assignments exceed %d", maxAssignments)
	}
	seen := make(map[string]struct{}, len(assignments))
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
		if _, ok := seen[item.ProfileID]; ok {
			return nil, errors.New("duplicate service profile assignment")
		}
		seen[item.ProfileID] = struct{}{}
		if err := Validate(ctx, item.Spec); err != nil {
			return nil, err
		}
	}
	grouped := make(map[string][]contender)

	for i := range assignments {
		item := &assignments[i]
		byID := make(map[string]*policyv1.ServiceProfileResource, len(item.Spec.GetResources()))
		for _, resource := range item.Spec.GetResources() {
			byID[resource.GetResourceId()] = resource
		}
		for _, resource := range item.Spec.GetResources() {
			deps := make([]string, 0, len(resource.GetDependsOn()))
			for _, depID := range resource.GetDependsOn() {
				deps = append(deps, byID[depID].GetDesired().GetUnit())
			}
			unit := resource.GetDesired().GetUnit()
			grouped[unit] = append(grouped[unit], contender{
				profileID:  item.ProfileID,
				revisionID: item.RevisionID,
				priority:   item.Priority,
				resource:   resource,
				deps:       deps,
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
			Unit:         unit,
			State:        ResolutionReady,
			Contributors: contributors(winners),
			Overridden:   contributors(losers),
			Dependencies: winnerDependencies(winners),
		}
		desired, ok := mergeDesired(winners)
		if !ok {
			resolution.State = ResolutionConflict
			resolution.Reason = ReasonEqualPriority
		} else {
			resolution.Desired = desired
		}
		resolved[unit] = resolution
		edges[unit] = resolution.Dependencies
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
		return fmt.Errorf("malformed service profile %s", name)
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

func winnerDependencies(winners []contender) []string {
	var deps []string
	for _, item := range winners {
		deps = append(deps, item.deps...)
	}
	if len(deps) == 0 {
		return nil
	}
	slices.Sort(deps)
	return slices.Compact(deps)
}

func mergeDesired(winners []contender) (*agentv1.ServiceDesiredState, bool) {
	runtime, runtimeOK := mergeRuntime(winners)
	enablement, enablementOK := mergeEnablement(winners)
	if !runtimeOK || !enablementOK {
		return nil, false
	}
	merged := proto.CloneOf(winners[0].resource.GetDesired())
	merged.Runtime = runtime
	merged.Enablement = enablement
	return merged, true
}

func mergeRuntime(winners []contender) (agentv1.ServiceRuntimeState, bool) {
	var (
		chosen agentv1.ServiceRuntimeState
		set    bool
	)
	for _, item := range winners {
		value := item.resource.GetDesired().GetRuntime()
		if value == agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_UNMANAGED {
			continue
		}
		if set && value != chosen {
			return 0, false
		}
		chosen = value
		set = true
	}
	if !set {
		return agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_UNMANAGED, true
	}
	return chosen, true
}

func mergeEnablement(winners []contender) (agentv1.ServiceEnablement, bool) {
	var (
		chosen agentv1.ServiceEnablement
		set    bool
	)
	for _, item := range winners {
		value := item.resource.GetDesired().GetEnablement()
		if value == agentv1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED {
			continue
		}
		if set && value != chosen {
			return 0, false
		}
		chosen = value
		set = true
	}
	if !set {
		return agentv1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED, true
	}
	return chosen, true
}

func dependencyCycle(ctx context.Context, spec *policyv1.ServiceProfileSpec) (bool, error) {
	edges := make(map[string][]string, len(spec.GetResources()))
	for _, resource := range spec.GetResources() {
		edges[resource.GetResourceId()] = resource.GetDependsOn()
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
		for _, dependency := range item.Dependencies {
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
