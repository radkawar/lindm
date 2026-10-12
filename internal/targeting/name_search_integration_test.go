//go:build integration

package targeting

import (
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/identity"
)

func (f *targetingFixture) putNamedGroup(t *testing.T, id, name string, expected uint64) {
	t.Helper()
	r := &adminv1.PutDynamicGroupRequest{RequestId: uuid.NewString(), ExpectedRevision: expected, Reason: "Name a searchable group", Group: &adminv1.DynamicTargetGroup{GroupId: id, Name: name, Expression: &adminv1.TargetExpression{InventoryMaxAgeSeconds: 60, Nodes: []*adminv1.TargetNode{{Depth: 1, Node: &adminv1.TargetNode_Predicate{Predicate: &adminv1.DeviceFilter{OsId: "debian"}}}}}}}
	if err := f.transaction(t, func(tx pgx.Tx) error {
		_, err := f.store.PutDynamicGroup(t.Context(), tx, f.actor, identity.PermissionManageInventory, r)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func (f *targetingFixture) dynamicGroupNames(t *testing.T, r *adminv1.ListDynamicGroupsRequest) []string {
	t.Helper()
	var names []string
	if err := f.transaction(t, func(tx pgx.Tx) error {
		out, err := f.store.ListDynamicGroups(t.Context(), tx, f.actor, identity.PermissionManageInventory, r)
		for _, group := range out.GetGroups() {
			names = append(names, group.Name)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return names
}

// A picker finds a dynamic group by any part of its current name in any case,
// past the first page, and a % or _ in the search is a literal character.
func TestListDynamicGroupsNameSearch(t *testing.T) {
	f := newTargetingFixture(t)
	ids := []string{"00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", "00000000-0000-4000-8000-000000000003", "00000000-0000-4000-8000-000000000004"}
	f.putNamedGroup(t, ids[0], "Debian rack zero", 0)
	f.putNamedGroup(t, ids[1], "Fedora laptops", 0)
	f.putNamedGroup(t, ids[2], "debian_servers 100%", 0)
	f.putNamedGroup(t, ids[3], "Debianxservers", 0)

	if got := f.dynamicGroupNames(t, &adminv1.ListDynamicGroupsRequest{PageSize: 100, NameSearch: "DEBIAN"}); !slices.Equal(got, []string{"Debian rack zero", "debian_servers 100%", "Debianxservers"}) {
		t.Fatalf("case-insensitive search = %q", got)
	}
	if got := f.dynamicGroupNames(t, &adminv1.ListDynamicGroupsRequest{PageSize: 100, NameSearch: "n_s"}); !slices.Equal(got, []string{"debian_servers 100%"}) {
		t.Fatalf("underscore was a wildcard: %q", got)
	}
	if got := f.dynamicGroupNames(t, &adminv1.ListDynamicGroupsRequest{PageSize: 100, NameSearch: "0%"}); !slices.Equal(got, []string{"debian_servers 100%"}) {
		t.Fatalf("percent was a wildcard: %q", got)
	}
	if got := f.dynamicGroupNames(t, &adminv1.ListDynamicGroupsRequest{PageSize: 1, AfterId: proto.String(ids[0]), NameSearch: "debian"}); !slices.Equal(got, []string{"debian_servers 100%"}) {
		t.Fatalf("second searched page = %q", got)
	}
	if got := f.dynamicGroupNames(t, &adminv1.ListDynamicGroupsRequest{PageSize: 100}); len(got) != 4 {
		t.Fatalf("empty search hid groups: %q", got)
	}

	// Renaming changes what the search finds.
	f.putNamedGroup(t, ids[1], "Fedora workstations", 1)
	if got := f.dynamicGroupNames(t, &adminv1.ListDynamicGroupsRequest{PageSize: 100, NameSearch: "laptops"}); len(got) != 0 {
		t.Fatalf("old name still found: %q", got)
	}
	if got := f.dynamicGroupNames(t, &adminv1.ListDynamicGroupsRequest{PageSize: 100, NameSearch: "WORKSTATION"}); !slices.Equal(got, []string{"Fedora workstations"}) {
		t.Fatalf("new name not found: %q", got)
	}

	for _, invalid := range []*adminv1.ListDynamicGroupsRequest{
		{PageSize: 100, NameSearch: strings.Repeat("a", 129)},
		{PageSize: 100, NameSearch: "a\x00b"},
	} {
		if err := f.transaction(t, func(tx pgx.Tx) error {
			_, err := f.store.ListDynamicGroups(t.Context(), tx, f.actor, identity.PermissionManageInventory, invalid)
			return err
		}); err == nil {
			t.Fatalf("unbounded search %q accepted", invalid.NameSearch)
		}
	}
}

// A rollout is named by its ring names; a search finds any part of that name.
func TestListRolloutsNameSearch(t *testing.T) {
	f := newTargetingFixture(t)
	ring := func(name string) *policyv1.RolloutRing {
		return &policyv1.RolloutRing{Name: name, Cohort: &policyv1.TargetRef{Target: &policyv1.TargetRef_DeviceId{DeviceId: f.device.String()}}, CumulativeBasisPoints: 10000, MinimumCanaries: 1, MinimumObserved: 1, SoakSeconds: 60, HealthMaxAgeSeconds: 60, ManualPromotion: true}
	}
	ids := []string{"00000000-0000-4000-8000-000000000011", "00000000-0000-4000-8000-000000000012"}
	for i, rings := range [][]*policyv1.RolloutRing{{ring("canary"), ring("Broad")}, {ring("pilot")}} {
		r := &adminv1.PutRolloutRequest{RequestId: uuid.NewString(), Reason: "Name a searchable rollout", Rollout: &policyv1.RolloutSpec{RolloutId: ids[i], Salt: make([]byte, 32), Rings: rings}}
		if err := f.transaction(t, func(tx pgx.Tx) error {
			_, err := f.store.PutRollout(t.Context(), tx, f.actor, identity.PermissionAssignResources, r)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	list := func(r *adminv1.ListRolloutsRequest) []string {
		t.Helper()
		var got []string
		if err := f.transaction(t, func(tx pgx.Tx) error {
			out, err := f.store.ListRollouts(t.Context(), tx, f.actor, identity.PermissionAssignResources, r)
			for _, state := range out.GetRollouts() {
				got = append(got, state.Rollout.RolloutId)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return got
	}
	for search, want := range map[string][]string{
		"BROAD":     {ids[0]},
		"canary, b": {ids[0]},
		"pil":       {ids[1]},
		"O":         ids,
		"":          ids,
		"nothing":   nil,
	} {
		if got := list(&adminv1.ListRolloutsRequest{PageSize: 100, NameSearch: search}); !slices.Equal(got, want) {
			t.Errorf("search %q = %q, want %q", search, got, want)
		}
	}
	if got := list(&adminv1.ListRolloutsRequest{PageSize: 100, AfterId: proto.String(ids[0]), NameSearch: "o"}); !slices.Equal(got, ids[1:]) {
		t.Fatalf("second searched page = %q", got)
	}
	if err := f.transaction(t, func(tx pgx.Tx) error {
		_, err := f.store.ListRollouts(t.Context(), tx, f.actor, identity.PermissionAssignResources, &adminv1.ListRolloutsRequest{PageSize: 100, NameSearch: strings.Repeat("a", 129)})
		return err
	}); err == nil {
		t.Fatal("unbounded rollout search accepted")
	}
}
