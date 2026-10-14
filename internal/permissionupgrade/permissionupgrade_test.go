// SPDX-License-Identifier: Apache-2.0

package permissionupgrade

import (
	"slices"
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	authv1 "lindm/gen/lindm/auth/v1"
)

func TestPermissionsReplaceRetiredNamesInPlace(t *testing.T) {
	for _, test := range []struct {
		name     string
		in, want []string
		legacy   []string
	}{
		{"current names unchanged", []string{"fleet.read", "remote_assistance.view"}, []string{"fleet.read", "remote_assistance.view"}, nil},
		{"run alone", []string{"remote_assistance.run"}, []string{"remote_assistance.view", "remote_assistance.control"}, []string{"remote_assistance.run"}},
		{"position kept", []string{"fleet.read", "remote_assistance.run", "audit.read"}, []string{"fleet.read", "remote_assistance.view", "remote_assistance.control", "audit.read"}, []string{"remote_assistance.run"}},
		{"no duplicate", []string{"remote_assistance.control", "remote_assistance.run"}, []string{"remote_assistance.control", "remote_assistance.view"}, []string{"remote_assistance.run"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, legacy := Permissions(test.in)
			if !slices.Equal(got, test.want) || !slices.Equal(legacy, test.legacy) {
				t.Fatalf("Permissions(%q) = %q, %q; want %q, %q", test.in, got, legacy, test.want, test.legacy)
			}
		})
	}
}

// The previous release allowed 24 permissions per role, one of them run; the
// current bound admits the two-name replacement of such a full role.
func TestPolicyUpgradesEveryListToAValidPolicy(t *testing.T) {
	previous := []string{"fleet.read", "enrollment.manage", "device.revoke", "audit.read", "execution_trust.manage", "profiles.manage", "resources.assign", "accounts.manage", "inventory.manage", "recovery_keys.read", "remote_execution.run", "remote_assistance.run", "scripts.run", "destructive.execute", "approvals.manage", "integrations.manage", "release_updates.manage", "advisory_exceptions.manage", "encryption.manage", "actions.lock", "actions.release-lock", "actions.quarantine", "secrets.manage", "secrets.reveal"}
	policy := &authv1.AuthorizationPolicy{
		Roles: []*authv1.RoleDefinition{
			{Name: "everything", Permissions: previous},
			{Name: "reader", Permissions: []string{"fleet.read"}},
			{Name: "assist", Permissions: []string{"remote_assistance.run"}},
		},
		GroupBindings:               []*authv1.GroupBinding{{Group: "/helpdesk", Role: "assist"}},
		ApprovalRequiredPermissions: []string{"actions.lock"},
	}
	if protovalidate.Validate(policy) == nil {
		t.Fatal("current validator accepted a retired permission")
	}
	unchanged := proto.CloneOf(policy)
	changes := Policy(policy)
	if len(changes) != 2 || changes[0].List != "roles/everything" || changes[1].List != "roles/assist" || !slices.Equal(changes[1].Legacy, []string{"remote_assistance.run"}) {
		t.Fatalf("changes = %+v", changes)
	}
	if err := protovalidate.Validate(policy); err != nil {
		t.Fatalf("upgraded policy invalid: %v", err)
	}
	if len(policy.GetRoles()[0].GetPermissions()) != 25 || !proto.Equal(policy.GetRoles()[1], unchanged.GetRoles()[1]) || !proto.Equal(policy.GetGroupBindings()[0], unchanged.GetGroupBindings()[0]) || !slices.Equal(policy.GetApprovalRequiredPermissions(), unchanged.GetApprovalRequiredPermissions()) {
		t.Fatal("upgrade changed more than retired names")
	}
	if Policy(policy) != nil || Policy(nil) != nil {
		t.Fatal("upgrade is not idempotent")
	}
}
