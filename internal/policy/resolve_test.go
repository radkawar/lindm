package policy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
)

const (
	profileLow  = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1"
	profileMid  = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2"
	profileHigh = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3"
	revisionLow = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1"
	revisionMid = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2"
	revisionHi  = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb3"
	resourceA   = "cccccccc-cccc-4ccc-8ccc-ccccccccccc1"
	resourceB   = "cccccccc-cccc-4ccc-8ccc-ccccccccccc2"
	resourceC   = "cccccccc-cccc-4ccc-8ccc-ccccccccccc3"
	resourceD   = "cccccccc-cccc-4ccc-8ccc-ccccccccccc4"
	resourceE   = "cccccccc-cccc-4ccc-8ccc-ccccccccccc5"
	resourceF   = "cccccccc-cccc-4ccc-8ccc-ccccccccccc6"
)

func TestResolveOrderIndependentMergeAndOverride(t *testing.T) {
	low := spec("low", resource(resourceA, "zebra.service", runtimeActive(), enablementUnmanaged(), nil), resource(resourceB, "alpha.service", runtimeInactive(), enablementDisabled(), nil))
	high := spec("high", resource(resourceC, "zebra.service", runtimeUnmanaged(), enablementEnabled(), []string{resourceD}), resource(resourceD, "alpha.service", runtimeActive(), enablementUnmanaged(), nil))
	tieRuntime := spec("tie-runtime", resource(resourceE, "mid.service", runtimeActive(), enablementUnmanaged(), nil))
	tieEnable := spec("tie-enable", resource(resourceF, "mid.service", runtimeUnmanaged(), enablementEnabled(), []string{id(30)}), resource(id(30), "dep.service", runtimeInactive(), enablementUnmanaged(), nil))
	forward := []Assignment{
		{ProfileID: profileLow, RevisionID: revisionLow, Priority: 1, Spec: low},
		{ProfileID: profileHigh, RevisionID: revisionHi, Priority: 9, Spec: high},
		{ProfileID: profileMid, RevisionID: revisionMid, Priority: 4, Spec: tieRuntime},
		{ProfileID: id(7), RevisionID: id(8), Priority: 4, Spec: tieEnable},
	}
	reverse := []Assignment{forward[3], forward[2], forward[1], forward[0]}
	before := cloneAssignments(forward)

	got, err := Resolve(context.Background(), forward)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Resolve(context.Background(), reverse)
	if err != nil {
		t.Fatal(err)
	}
	if !sameResolutions(got, again) {
		t.Fatalf("assignment order changed resolution: %#v vs %#v", got, again)
	}
	if !assignmentsEqual(before, forward) {
		t.Fatal("resolve mutated input assignments")
	}

	if len(got) != 4 || got[0].Unit != "alpha.service" || got[1].Unit != "dep.service" || got[2].Unit != "mid.service" || got[3].Unit != "zebra.service" {
		t.Fatalf("units = %#v", unitsOf(got))
	}
	alpha := got[0]
	if alpha.State != ResolutionReady || alpha.Reason != ReasonNone || alpha.Desired.GetRuntime() != runtimeActive() || alpha.Desired.GetEnablement() != enablementUnmanaged() {
		t.Fatalf("higher priority did not fully override lower unit: %#v", alpha)
	}
	if len(alpha.Contributors) != 1 || alpha.Contributors[0].ResourceID != resourceD || len(alpha.Overridden) != 1 || alpha.Overridden[0].ResourceID != resourceB {
		t.Fatalf("override provenance = contributors %#v overridden %#v", alpha.Contributors, alpha.Overridden)
	}
	if len(alpha.Dependencies) != 0 {
		t.Fatalf("winning resource dependencies = %v", alpha.Dependencies)
	}

	mid := got[2]
	if mid.State != ResolutionReady || mid.Desired.GetRuntime() != runtimeActive() || mid.Desired.GetEnablement() != enablementEnabled() {
		t.Fatalf("complementary merge = %#v desired=%v", mid, mid.Desired)
	}
	if mid.Contributors[0].ProfileID != profileMid || mid.Contributors[1].ProfileID != id(7) {
		t.Fatalf("contributor order = %#v", mid.Contributors)
	}
	if len(mid.Dependencies) != 1 || mid.Dependencies[0] != "dep.service" {
		t.Fatalf("merged dependencies = %v", mid.Dependencies)
	}
	mid.Desired.Unit = "mutated.service"
	if forward[2].Spec.GetResources()[0].GetDesired().GetUnit() != "mid.service" {
		t.Fatal("result desired aliased input")
	}

	zebra := got[3]
	if zebra.Desired.GetRuntime() != runtimeUnmanaged() || zebra.Desired.GetEnablement() != enablementEnabled() || zebra.Dependencies[0] != "alpha.service" {
		t.Fatalf("partial higher-priority winner = %#v deps %v", zebra.Desired, zebra.Dependencies)
	}
	if zebra.Overridden[0].ProfileID != profileLow {
		t.Fatalf("lower priority not visible as overridden: %#v", zebra.Overridden)
	}
}

func TestResolveEqualPriorityDisagreement(t *testing.T) {
	left := spec("left",
		resource(resourceA, "app.service", runtimeActive(), enablementEnabled(), []string{resourceB}),
		resource(resourceB, "db.service", runtimeActive(), enablementUnmanaged(), nil),
		resource(resourceE, "worker.service", runtimeActive(), enablementUnmanaged(), []string{resourceA}),
	)
	right := spec("right", resource(resourceC, "app.service", runtimeInactive(), enablementEnabled(), nil))
	lower := spec("lower", resource(resourceD, "app.service", runtimeActive(), enablementDisabled(), nil))
	got, err := Resolve(context.Background(), []Assignment{
		{ProfileID: profileHigh, RevisionID: revisionHi, Priority: 3, Spec: left},
		{ProfileID: profileMid, RevisionID: revisionMid, Priority: 3, Spec: right},
		{ProfileID: profileLow, RevisionID: revisionLow, Priority: 2, Spec: lower},
	})
	if err != nil {
		t.Fatal(err)
	}
	app := byUnit(t, got, "app.service")
	if app.State != ResolutionConflict || app.Reason != ReasonEqualPriority || app.Desired != nil {
		t.Fatalf("disagreement = %#v", app)
	}
	if len(app.Contributors) != 2 || len(app.Overridden) != 1 || app.Overridden[0].ProfileID != profileLow {
		t.Fatalf("conflict provenance contributors %#v overridden %#v", app.Contributors, app.Overridden)
	}
	if len(app.Dependencies) != 1 || app.Dependencies[0] != "db.service" {
		t.Fatalf("conflict dependencies = %v", app.Dependencies)
	}
	db := byUnit(t, got, "db.service")
	if db.State != ResolutionReady || db.Reason != ReasonNone {
		t.Fatalf("conflicted dependent blocked its prerequisite: %#v", db)
	}
	worker := byUnit(t, got, "worker.service")
	if worker.State != ResolutionBlocked || worker.Reason != ReasonDependencyConflict || worker.Desired.GetRuntime() != runtimeActive() {
		t.Fatalf("dependent of conflict = %#v", worker)
	}
}
func TestResolveCrossProfileCycleAndTransitiveBlock(t *testing.T) {
	// Equal-priority winners each contribute one direction, so the unit graph cycles
	// even though neither profile is cyclic by itself.
	left := spec("left",
		resource(resourceA, "a.service", runtimeActive(), enablementUnmanaged(), []string{resourceB}),
		resource(resourceB, "b.service", runtimeUnmanaged(), enablementEnabled(), nil),
		resource(resourceC, "c.service", runtimeActive(), enablementEnabled(), []string{resourceA}),
	)
	right := spec("right",
		resource(resourceD, "b.service", runtimeActive(), enablementUnmanaged(), []string{resourceE}),
		resource(resourceE, "a.service", runtimeUnmanaged(), enablementEnabled(), nil),
	)
	// An overridden acyclic dependency must not constrain the higher winner.
	cycleLow := spec("cycle-low", resource(resourceA, "solo.service", runtimeInactive(), enablementUnmanaged(), []string{resourceB}), resource(resourceB, "other.service", runtimeActive(), enablementUnmanaged(), nil))
	cycleHigh := spec("cycle-high", resource(resourceC, "solo.service", runtimeActive(), enablementEnabled(), nil), resource(resourceD, "other.service", runtimeInactive(), enablementEnabled(), nil))
	// The winning low resource depends on a unit whose effective resource is higher priority.
	dependent := spec("dependent", resource(id(15), "edge.service", runtimeInactive(), enablementUnmanaged(), []string{id(16)}), resource(id(16), "base.service", runtimeInactive(), enablementDisabled(), nil))
	base := spec("base", resource(id(17), "base.service", runtimeActive(), enablementEnabled(), nil))
	got, err := Resolve(context.Background(), []Assignment{
		{ProfileID: profileLow, RevisionID: revisionLow, Priority: 4, Spec: left},
		{ProfileID: profileHigh, RevisionID: revisionHi, Priority: 4, Spec: right},
		{ProfileID: id(9), RevisionID: id(10), Priority: 1, Spec: cycleLow},
		{ProfileID: id(11), RevisionID: id(12), Priority: 5, Spec: cycleHigh},
		{ProfileID: id(18), RevisionID: id(19), Priority: 1, Spec: dependent},
		{ProfileID: id(21), RevisionID: id(22), Priority: 6, Spec: base},
	})
	if err != nil {
		t.Fatal(err)
	}
	a := byUnit(t, got, "a.service")
	b := byUnit(t, got, "b.service")
	c := byUnit(t, got, "c.service")
	if a.State != ResolutionConflict || a.Reason != ReasonDependencyCycle || a.Desired != nil {
		t.Fatalf("cycle member a = %#v", a)
	}
	if b.State != ResolutionConflict || b.Reason != ReasonDependencyCycle || b.Desired != nil {
		t.Fatalf("cycle member b = %#v", b)
	}
	if len(a.Dependencies) != 1 || a.Dependencies[0] != "b.service" || len(b.Dependencies) != 1 || b.Dependencies[0] != "a.service" {
		t.Fatalf("cycle edges a %v b %v", a.Dependencies, b.Dependencies)
	}
	if c.State != ResolutionBlocked || c.Reason != ReasonDependencyConflict {
		t.Fatalf("transitive dependent = %#v", c)
	}
	for _, unit := range []string{"solo.service", "other.service"} {
		item := byUnit(t, got, unit)
		if item.State != ResolutionReady || len(item.Dependencies) != 0 || len(item.Overridden) != 1 {
			t.Fatalf("overridden dependency leaked into %s: %#v", unit, item)
		}
	}
	edge := byUnit(t, got, "edge.service")
	baseUnit := byUnit(t, got, "base.service")
	if edge.State != ResolutionReady || len(edge.Dependencies) != 1 || edge.Dependencies[0] != "base.service" {
		t.Fatalf("dependency on higher-priority unit = %#v", edge)
	}
	if baseUnit.State != ResolutionReady || baseUnit.Contributors[0].ProfileID != id(21) || baseUnit.Overridden[0].ProfileID != id(18) {
		t.Fatalf("effective dependency resource = %#v", baseUnit)
	}
}

func TestResolveThreeProfileCycle(t *testing.T) {
	a := spec("a", resource(resourceA, "a.service", runtimeActive(), enablementUnmanaged(), []string{resourceB}), resource(resourceB, "b.service", runtimeUnmanaged(), enablementEnabled(), nil))
	b := spec("b", resource(resourceC, "b.service", runtimeActive(), enablementUnmanaged(), []string{resourceD}), resource(resourceD, "c.service", runtimeUnmanaged(), enablementEnabled(), nil))
	c := spec("c", resource(resourceE, "c.service", runtimeActive(), enablementUnmanaged(), []string{resourceF}), resource(resourceF, "a.service", runtimeUnmanaged(), enablementEnabled(), nil))
	tail := spec("tail", resource(id(20), "tail.service", runtimeInactive(), enablementUnmanaged(), []string{id(21)}), resource(id(21), "c.service", runtimeActive(), enablementDisabled(), nil))
	got, err := Resolve(context.Background(), []Assignment{
		{ProfileID: profileLow, RevisionID: revisionLow, Priority: 2, Spec: c},
		{ProfileID: profileMid, RevisionID: revisionMid, Priority: 2, Spec: a},
		{ProfileID: profileHigh, RevisionID: revisionHi, Priority: 2, Spec: b},
		{ProfileID: id(13), RevisionID: id(14), Priority: 1, Spec: tail},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, unit := range []string{"a.service", "b.service", "c.service"} {
		item := byUnit(t, got, unit)
		if item.State != ResolutionConflict || item.Reason != ReasonDependencyCycle || item.Desired != nil {
			t.Fatalf("%s = %#v", unit, item)
		}
	}
	item := byUnit(t, got, "tail.service")
	if item.State != ResolutionBlocked || item.Reason != ReasonDependencyConflict || item.Desired == nil {
		t.Fatalf("tail = %#v", item)
	}
}

func TestResolveAgreesOnExplicitValues(t *testing.T) {
	left := spec("left",
		resource(resourceA, "app.service", runtimeActive(), enablementEnabled(), []string{resourceC, id(40)}),
		resource(resourceC, "z.service", runtimeInactive(), enablementUnmanaged(), nil),
		resource(id(40), "a.service", runtimeUnmanaged(), enablementEnabled(), nil),
	)
	right := spec("right",
		resource(resourceB, "app.service", runtimeActive(), enablementEnabled(), []string{id(41), id(42)}),
		resource(id(41), "z.service", runtimeInactive(), enablementUnmanaged(), nil),
		resource(id(42), "m.service", runtimeUnmanaged(), enablementDisabled(), nil),
	)
	got, err := Resolve(context.Background(), []Assignment{
		{ProfileID: profileHigh, RevisionID: revisionHi, Priority: 0, Spec: right},
		{ProfileID: profileLow, RevisionID: revisionLow, Priority: 0, Spec: left},
	})
	if err != nil {
		t.Fatal(err)
	}
	app := byUnit(t, got, "app.service")
	if app.State != ResolutionReady || app.Desired.GetRuntime() != runtimeActive() || app.Desired.GetEnablement() != enablementEnabled() || len(app.Contributors) != 2 {
		t.Fatalf("equal explicit values = %#v", app)
	}
	if app.Contributors[0].ProfileID != profileLow || app.Contributors[1].ProfileID != profileHigh {
		t.Fatalf("provenance sort = %#v", app.Contributors)
	}
	if len(app.Dependencies) != 3 || app.Dependencies[0] != "a.service" || app.Dependencies[1] != "m.service" || app.Dependencies[2] != "z.service" {
		t.Fatalf("dependency order = %v", app.Dependencies)
	}
}

func TestResolveRejectsInvalidAssignments(t *testing.T) {
	valid := spec("ok", resource(resourceA, "app.service", runtimeActive(), enablementUnmanaged(), nil))
	base := Assignment{ProfileID: profileLow, RevisionID: revisionLow, Priority: 1, Spec: valid}
	cases := map[string][]Assignment{
		"duplicate profile": {
			base,
			{ProfileID: profileLow, RevisionID: revisionHi, Priority: 2, Spec: valid},
		},
		"malformed profile": {{ProfileID: "not-a-uuid", RevisionID: revisionLow, Priority: 1, Spec: valid}},
		"nonzero profile":   {{ProfileID: uuid.Nil.String(), RevisionID: revisionLow, Priority: 1, Spec: valid}},
		"uppercase profile": {{ProfileID: strings.ToUpper(profileLow), RevisionID: revisionLow, Priority: 1, Spec: valid}},
		"malformed revision": {{
			ProfileID: profileLow, RevisionID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1-extra", Priority: 1, Spec: valid,
		}},
		"nil spec": {{ProfileID: profileLow, RevisionID: revisionLow, Priority: 1}},
		"too many": tooMany(valid),
	}
	for name, assignments := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Resolve(context.Background(), assignments); err == nil {
				t.Fatal("accepted invalid assignments")
			}
		})
	}
	limit := tooMany(valid)[:maxAssignments]
	for i := range limit {
		limit[i].ProfileID = id(byte(i + 1))
		limit[i].RevisionID = id(byte(i + 1))
		limit[i].RevisionID = rewrite(limit[i].RevisionID, 'b')
	}
	if _, err := Resolve(context.Background(), limit); err != nil {
		t.Fatal(err)
	}
}

func TestValidateProfileSchemaAndCycles(t *testing.T) {
	ok := spec("edge", resource(resourceA, "app.service", runtimeActive(), enablementUnmanaged(), []string{resourceB}), resource(resourceB, "db.service", runtimeUnmanaged(), enablementEnabled(), nil))
	if err := Validate(context.Background(), ok); err != nil {
		t.Fatal(err)
	}
	cases := map[string]*policyv1.ServiceProfileSpec{
		"nil":               nil,
		"empty name":        spec("", resource(resourceA, "app.service", runtimeActive(), enablementUnmanaged(), nil)),
		"nul name":          spec("bad\x00name", resource(resourceA, "app.service", runtimeActive(), enablementUnmanaged(), nil)),
		"long name":         spec(strings.Repeat("n", 161), resource(resourceA, "app.service", runtimeActive(), enablementUnmanaged(), nil)),
		"long description":  withDescription(spec("ok", resource(resourceA, "app.service", runtimeActive(), enablementUnmanaged(), nil)), strings.Repeat("d", 4097)),
		"duplicate id":      spec("ok", resource(resourceA, "app.service", runtimeActive(), enablementUnmanaged(), nil), resource(resourceA, "db.service", runtimeInactive(), enablementUnmanaged(), nil)),
		"duplicate unit":    spec("ok", resource(resourceA, "app.service", runtimeActive(), enablementUnmanaged(), nil), resource(resourceB, "app.service", runtimeInactive(), enablementUnmanaged(), nil)),
		"self dependency":   spec("ok", resource(resourceA, "app.service", runtimeActive(), enablementUnmanaged(), []string{resourceA})),
		"absent dependency": spec("ok", resource(resourceA, "app.service", runtimeActive(), enablementUnmanaged(), []string{resourceB})),
		"zero resource":     spec("ok", resource(uuid.Nil.String(), "app.service", runtimeActive(), enablementUnmanaged(), nil)),
		"both unmanaged":    spec("ok", resource(resourceA, "app.service", agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_UNMANAGED, agentv1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED, nil)),
		"protected unit":    spec("ok", resource(resourceA, "lindm.service", runtimeActive(), enablementUnmanaged(), nil)),
		"cycle": spec("ok",
			resource(resourceA, "a.service", runtimeActive(), enablementUnmanaged(), []string{resourceB}),
			resource(resourceB, "b.service", runtimeInactive(), enablementUnmanaged(), []string{resourceC}),
			resource(resourceC, "c.service", runtimeUnmanaged(), enablementEnabled(), []string{resourceA}),
		),
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			if err := Validate(context.Background(), spec); err == nil {
				t.Fatal("accepted invalid profile")
			}
			if spec == nil {
				return
			}
			if _, err := Resolve(context.Background(), []Assignment{{ProfileID: profileLow, RevisionID: revisionLow, Priority: -1, Spec: spec}}); err == nil {
				t.Fatal("resolve accepted invalid profile")
			}
		})
	}
	unknown := spec("ok", resource(resourceA, "app.service", runtimeActive(), enablementUnmanaged(), nil))
	unknown.ProtoReflect().SetUnknown([]byte{0x20, 0x01})
	if err := Validate(context.Background(), unknown); err == nil {
		t.Fatal("accepted unknown profile field")
	}
	nested := spec("ok", resource(resourceA, "app.service", runtimeActive(), enablementUnmanaged(), nil))
	nested.GetResources()[0].GetDesired().ProtoReflect().SetUnknown([]byte{0x20, 0x01})
	if err := Validate(context.Background(), nested); err == nil {
		t.Fatal("accepted unknown desired field")
	}
}

func TestResolveHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Validate(ctx, spec("ok", resource(resourceA, "app.service", runtimeActive(), enablementUnmanaged(), nil))); !errors.Is(err, context.Canceled) {
		t.Fatalf("validate cancellation: %v", err)
	}
	if _, err := Resolve(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("resolve cancellation: %v", err)
	}
}

func spec(name string, resources ...*policyv1.ServiceProfileResource) *policyv1.ServiceProfileSpec {
	return &policyv1.ServiceProfileSpec{Name: name, Description: "preview", Resources: resources}
}

func withDescription(spec *policyv1.ServiceProfileSpec, description string) *policyv1.ServiceProfileSpec {
	spec.Description = description
	return spec
}

func resource(id, unit string, runtime agentv1.ServiceRuntimeState, enablement agentv1.ServiceEnablement, deps []string) *policyv1.ServiceProfileResource {
	return &policyv1.ServiceProfileResource{
		ResourceId: id,
		Desired: &agentv1.ServiceDesiredState{
			Unit:       unit,
			Runtime:    runtime,
			Enablement: enablement,
		},
		DependsOn: deps,
	}
}

func runtimeActive() agentv1.ServiceRuntimeState {
	return agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE
}
func runtimeInactive() agentv1.ServiceRuntimeState {
	return agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE
}
func runtimeUnmanaged() agentv1.ServiceRuntimeState {
	return agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_UNMANAGED
}
func enablementEnabled() agentv1.ServiceEnablement {
	return agentv1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED
}
func enablementDisabled() agentv1.ServiceEnablement {
	return agentv1.ServiceEnablement_SERVICE_ENABLEMENT_DISABLED
}
func enablementUnmanaged() agentv1.ServiceEnablement {
	return agentv1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED
}

func id(n byte) string {
	return "dddddddd-dddd-4ddd-8ddd-dddddddddd" + string([]byte{hex(n >> 4), hex(n & 0xf)})
}

func hex(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'a' + n - 10
}

func rewrite(id string, mark byte) string {
	return strings.Replace(id, "dddddddd", strings.Repeat(string(mark), 8), 1)
}

func tooMany(spec *policyv1.ServiceProfileSpec) []Assignment {
	out := make([]Assignment, maxAssignments+1)
	for i := range out {
		out[i] = Assignment{ProfileID: profileLow, RevisionID: revisionLow, Priority: 1, Spec: spec}
	}
	return out
}

func cloneAssignments(in []Assignment) []Assignment {
	out := make([]Assignment, len(in))
	for i := range in {
		out[i] = in[i]
		out[i].Spec = proto.CloneOf(in[i].Spec)
	}
	return out
}

func assignmentsEqual(a, b []Assignment) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ProfileID != b[i].ProfileID || a[i].RevisionID != b[i].RevisionID || a[i].Priority != b[i].Priority || !proto.Equal(a[i].Spec, b[i].Spec) {
			return false
		}
	}
	return true
}

func sameResolutions(a, b []Resolution) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Unit != b[i].Unit || a[i].State != b[i].State || a[i].Reason != b[i].Reason || !sameContributors(a[i].Contributors, b[i].Contributors) || !sameContributors(a[i].Overridden, b[i].Overridden) || !slicesEqual(a[i].Dependencies, b[i].Dependencies) || !proto.Equal(a[i].Desired, b[i].Desired) {
			return false
		}
	}
	return true
}

func sameContributors(a, b []Contributor) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func unitsOf(items []Resolution) []string {
	out := make([]string, len(items))
	for i := range items {
		out[i] = items[i].Unit
	}
	return out
}

func byUnit(t *testing.T, items []Resolution, unit string) Resolution {
	t.Helper()
	for _, item := range items {
		if item.Unit == unit {
			return item
		}
	}
	t.Fatalf("missing %s in %v", unit, unitsOf(items))
	return Resolution{}
}

func TestResolveOverlappingCycleBranches(t *testing.T) {
	left := spec("branching",
		resource(resourceA, "a.service", runtimeActive(), enablementUnmanaged(), []string{resourceB, resourceC}),
		resource(resourceB, "b.service", runtimeActive(), enablementUnmanaged(), nil),
		resource(resourceC, "c.service", runtimeActive(), enablementUnmanaged(), nil),
	)
	back := spec("back",
		resource(resourceD, "b.service", runtimeActive(), enablementUnmanaged(), []string{resourceE}),
		resource(resourceE, "a.service", runtimeActive(), enablementUnmanaged(), nil),
	)
	branch := spec("branch",
		resource(resourceF, "c.service", runtimeActive(), enablementUnmanaged(), []string{id(30)}),
		resource(id(30), "b.service", runtimeActive(), enablementUnmanaged(), nil),
	)
	resolved, err := Resolve(t.Context(), []Assignment{
		{ProfileID: profileLow, RevisionID: revisionLow, Spec: left},
		{ProfileID: profileMid, RevisionID: revisionMid, Spec: back},
		{ProfileID: profileHigh, RevisionID: revisionHi, Spec: branch},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, unit := range []string{"a.service", "b.service", "c.service"} {
		result := byUnit(t, resolved, unit)
		if result.State != ResolutionConflict || result.Reason != ReasonDependencyCycle || result.Desired != nil {
			t.Fatalf("strongly connected member %s escaped cycle classification: %#v", unit, result)
		}
	}
}
