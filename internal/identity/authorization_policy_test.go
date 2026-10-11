package identity

import (
	"slices"
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	authv1 "lindm/gen/lindm/auth/v1"
)

func TestBuiltInPermissionMatrix(t *testing.T) {
	all := []Permission{PermissionReadFleet, PermissionManageEnrollment, PermissionRevokeDevice, PermissionReadAudit, PermissionManageExecutionTrust, PermissionManageProfiles, PermissionAssignResources, PermissionManageAccounts, PermissionManageInventory, PermissionReadRecoveryKeys, PermissionRunRemoteExecution, PermissionRunScripts, PermissionExecuteDestructive, PermissionManageApprovals, PermissionManageIntegrations, PermissionManageReleaseUpdates, PermissionManageAdvisoryExceptions, PermissionManageEncryption, PermissionLockDevice, PermissionReleaseLockDevice, PermissionQuarantineDevice, PermissionManageSecrets, PermissionRevealSecrets, PermissionRunRemoteAssistance}
	for _, test := range []struct {
		role   string
		grants []Permission
	}{
		{RoleOwner, all},
		{RoleAdmin, []Permission{PermissionReadFleet, PermissionManageEnrollment, PermissionRevokeDevice, PermissionReadAudit, PermissionManageExecutionTrust, PermissionManageProfiles, PermissionAssignResources, PermissionManageInventory, PermissionReadRecoveryKeys, PermissionRunRemoteExecution, PermissionRunScripts, PermissionExecuteDestructive, PermissionManageApprovals, PermissionManageIntegrations, PermissionManageReleaseUpdates, PermissionManageAdvisoryExceptions, PermissionManageEncryption, PermissionLockDevice, PermissionReleaseLockDevice, PermissionQuarantineDevice, PermissionManageSecrets, PermissionRevealSecrets, PermissionRunRemoteAssistance}},
		{RoleOperator, []Permission{PermissionReadFleet, PermissionManageEnrollment, PermissionManageProfiles, PermissionAssignResources}},
		{RoleHelpdesk, []Permission{PermissionReadFleet, PermissionManageEnrollment}},
		{RoleAuditor, []Permission{PermissionReadFleet, PermissionReadAudit}},
		{"missing", nil},
	} {
		t.Run(test.role, func(t *testing.T) {
			for _, permission := range append(append([]Permission(nil), all...), Permission("unknown.permission")) {
				if got := Authorize(Principal{Role: test.role}, permission); got != slices.Contains(test.grants, permission) {
					t.Fatalf("%s grant=%v", permission, got)
				}
			}
		})
	}
}

func TestPermissionScopesDoNotCrossGrants(t *testing.T) {
	read := &authv1.DeviceScope{Labels: []string{"read-only"}}
	write := &authv1.DeviceScope{Labels: []string{"managed"}, DeviceIds: []string{"11111111-1111-1111-1111-111111111111"}}
	p := Principal{Role: RoleOwner, Bindings: []*authv1.RoleBinding{
		{Role: "reader", Permissions: []string{string(PermissionReadFleet)}, Scopes: []*authv1.DeviceScope{read}},
		{Role: "writer", Permissions: []string{string(PermissionAssignResources)}, Scopes: []*authv1.DeviceScope{write}},
		{Role: "unknown", Permissions: []string{"future.permission"}},
	}}
	for _, test := range []struct {
		permission Permission
		scope      *authv1.DeviceScope
	}{{PermissionReadFleet, read}, {PermissionAssignResources, write}} {
		unrestricted, scopes := DeviceScopes(p, test.permission)
		if unrestricted || len(scopes) != 1 || !proto.Equal(scopes[0], test.scope) {
			t.Fatalf("scope cross-product for %s: %v %v", test.permission, unrestricted, scopes)
		}
	}
	if Authorize(p, Permission("future.permission")) || Authorize(p, PermissionManageAccounts) {
		t.Fatal("unknown grant or display role bypassed bindings")
	}
	p.Bindings = append(p.Bindings, &authv1.RoleBinding{Permissions: []string{string(PermissionReadFleet)}})
	if unrestricted, scopes := DeviceScopes(p, PermissionReadFleet); !unrestricted || len(scopes) != 0 {
		t.Fatal("unrestricted granting binding did not win")
	}
	p.BreakGlass = true
	p.AllowedPermissions = []string{string(PermissionReadFleet)}
	if Authorize(p, PermissionAssignResources) || !slices.Equal(Permissions(p), []string{string(PermissionReadFleet)}) {
		t.Fatal("emergency intersection lost")
	}
	if unrestricted, scopes := DeviceScopes(p, PermissionAssignResources); unrestricted || len(scopes) != 0 {
		t.Fatal("denied emergency action retained scopes")
	}
	p.Bindings = []*authv1.RoleBinding{}
	if Authorize(p, PermissionReadFleet) {
		t.Fatal("empty resolved bindings fell back to display role")
	}
}

func TestPolicyValidationAndSourceExclusivity(t *testing.T) {
	rules, err := protovalidate.New(protovalidate.WithMessages(&authv1.AuthorizationPolicy{}))
	if err != nil {
		t.Fatal(err)
	}
	valid := &authv1.AuthorizationPolicy{Roles: []*authv1.RoleDefinition{{Name: "custom", Permissions: []string{string(PermissionReadFleet)}}}, GroupBindings: []*authv1.GroupBinding{{Group: "/fleet", Role: "custom", Scopes: []*authv1.DeviceScope{{Labels: []string{"owned"}}}}}}
	for _, test := range []struct {
		name   string
		change func(*authv1.AuthorizationPolicy)
		local  bool
		valid  bool
	}{
		{name: "custom", valid: true},
		{name: "unknown permission", change: func(p *authv1.AuthorizationPolicy) { p.Roles[0].Permissions = []string{"future.permission"} }},
		{name: "builtin override", change: func(p *authv1.AuthorizationPolicy) { p.Roles[0].Name = RoleOwner }},
		{name: "unknown role", change: func(p *authv1.AuthorizationPolicy) { p.GroupBindings[0].Role = "absent" }},
		{name: "duplicate role", change: func(p *authv1.AuthorizationPolicy) { p.Roles = append(p.Roles, proto.CloneOf(p.Roles[0])) }},
		{name: "mixed source", local: true},
		{name: "invalid scope", change: func(p *authv1.AuthorizationPolicy) { p.GroupBindings[0].Scopes[0].DeviceIds = []string{"not-an-id"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := proto.CloneOf(valid)
			if test.change != nil {
				test.change(policy)
			}
			_, err := compilePolicy(Config{Local: test.local, Policy: policy}, rules)
			if (err == nil) != test.valid {
				t.Fatalf("compile policy=%v", err)
			}
		})
	}
	policy := testPolicy(t, Config{Policy: valid})
	s := &Service{policy: policy}
	local := s.snapshotPrincipal(directorySnapshot{policy: s.policy, Local: true, Groups: []string{"/fleet"}}, RoleHelpdesk)
	if len(local.Bindings) != 1 || local.Bindings[0].Role != RoleHelpdesk || len(local.Bindings[0].Scopes) != 0 {
		t.Fatal("directory mapping leaked into local authority")
	}
	directory := s.snapshotPrincipal(directorySnapshot{policy: s.policy, Groups: []string{"/fleet"}}, RoleOwner)
	if Authorize(directory, PermissionManageAccounts) || len(directory.Bindings) != 1 || directory.Bindings[0].Role != "custom" {
		t.Fatal("local/display role leaked into directory authority")
	}
	captured := &Authorization{principal: clonePrincipal(directory)}
	copy := captured.Principal()
	copy.Bindings[0].Permissions[0] = "accounts.manage"
	copy.Bindings[0].Scopes[0].Labels[0] = "mutated"
	if Authorize(captured.Principal(), PermissionManageAccounts) || captured.Principal().Bindings[0].Scopes[0].Labels[0] != "owned" {
		t.Fatal("captured authority mutated through accessor")
	}
}

func TestConfiguredSensitiveApprovalPermissions(t *testing.T) {
	for _, permission := range []Permission{
		PermissionAssignResources, PermissionManageExecutionTrust,
		PermissionRunRemoteExecution, PermissionReadRecoveryKeys,
		PermissionManageInventory,
		PermissionManageEncryption, PermissionLockDevice, PermissionReleaseLockDevice, PermissionQuarantineDevice, PermissionRevealSecrets,
	} {
		t.Run(string(permission), func(t *testing.T) {
			service := Principal{policy: testPolicy(t, Config{Local: true})}
			if service.ApprovalRequired(permission) {
				t.Fatal("optional approval required without configuration")
			}
			service.policy = testPolicy(t, Config{Local: true, Policy: &authv1.AuthorizationPolicy{
				ApprovalRequiredPermissions: []string{string(permission)},
			}})
			if !service.ApprovalRequired(permission) {
				t.Fatal("configured sensitive operation bypassed approval")
			}
			if !service.ApprovalRequired(PermissionRevokeDevice) || !service.ApprovalRequired(PermissionExecuteDestructive) {
				t.Fatal("optional policy displaced mandatory approval")
			}
		})
	}
}

func TestReleaseLockPermissionDoesNotInheritLockScope(t *testing.T) {
	lockScope := &authv1.DeviceScope{Labels: []string{"lock-only"}}
	releaseScope := &authv1.DeviceScope{Labels: []string{"release-only"}}
	principal := Principal{Role: RoleOwner, Bindings: []*authv1.RoleBinding{
		{Permissions: []string{string(PermissionLockDevice)}, Scopes: []*authv1.DeviceScope{lockScope}},
	}}
	if Authorize(principal, PermissionReleaseLockDevice) {
		t.Fatal("lock-only binding granted release")
	}
	principal.Bindings = append(principal.Bindings, &authv1.RoleBinding{Permissions: []string{string(PermissionReleaseLockDevice)}, Scopes: []*authv1.DeviceScope{releaseScope}})
	unrestricted, scopes := DeviceScopes(principal, PermissionReleaseLockDevice)
	if unrestricted || len(scopes) != 1 || !proto.Equal(scopes[0], releaseScope) {
		t.Fatal("release inherited another grant's lock scope")
	}
}
