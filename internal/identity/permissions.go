package identity

import (
	"slices"

	authv1 "lindm/gen/lindm/auth/v1"
)

// The permission registry is deliberately explicit: new actions do not silently
// become operator/helpdesk grants. Unknown values always deny, even in bindings.
var permissionTable = []struct {
	permission Permission
	roles      []string
}{
	{PermissionReadFleet, []string{RoleOwner, RoleAdmin, RoleOperator, RoleHelpdesk, RoleAuditor}},
	{PermissionManageEnrollment, []string{RoleOwner, RoleAdmin, RoleOperator, RoleHelpdesk}},
	{PermissionRevokeDevice, []string{RoleOwner, RoleAdmin}},
	{PermissionReadAudit, []string{RoleOwner, RoleAdmin, RoleAuditor}},
	{PermissionManageExecutionTrust, []string{RoleOwner, RoleAdmin}},
	{PermissionManageProfiles, []string{RoleOwner, RoleAdmin, RoleOperator}},
	{PermissionAssignResources, []string{RoleOwner, RoleAdmin, RoleOperator}},
	{PermissionManageAccounts, []string{RoleOwner}},
	{PermissionManageInventory, []string{RoleOwner, RoleAdmin}},
	{PermissionReadRecoveryKeys, []string{RoleOwner, RoleAdmin}},
	{PermissionRunRemoteExecution, []string{RoleOwner, RoleAdmin}},
	{PermissionRunScripts, []string{RoleOwner, RoleAdmin}},
	{PermissionExecuteDestructive, []string{RoleOwner, RoleAdmin}},
	{PermissionManageApprovals, []string{RoleOwner, RoleAdmin}},
	{PermissionManageIntegrations, []string{RoleOwner, RoleAdmin}},
	{PermissionManageReleaseUpdates, []string{RoleOwner, RoleAdmin}},
	{PermissionManageAdvisoryExceptions, []string{RoleOwner, RoleAdmin}},
	{PermissionManageEncryption, []string{RoleOwner, RoleAdmin}},
	{PermissionLockDevice, []string{RoleOwner, RoleAdmin}},
	{PermissionReleaseLockDevice, []string{RoleOwner, RoleAdmin}},
	{PermissionQuarantineDevice, []string{RoleOwner, RoleAdmin}},
	{PermissionManageSecrets, []string{RoleOwner, RoleAdmin}},
	{PermissionRevealSecrets, []string{RoleOwner, RoleAdmin}},
	{PermissionRunRemoteAssistance, []string{RoleOwner, RoleAdmin}},
}

func knownPermission(permission Permission) bool {
	for _, entry := range permissionTable {
		if entry.permission == permission {
			return true
		}
	}
	return false
}

func builtinPermissions(role string) []string {
	var permissions []string
	for _, entry := range permissionTable {
		if slices.Contains(entry.roles, role) {
			permissions = append(permissions, string(entry.permission))
		}
	}
	return permissions
}

func emergencyAllows(p Principal, permission Permission) bool {
	return !p.BreakGlass || p.Role == RoleOwner && slices.Contains(p.AllowedPermissions, string(permission))
}

// Authorize checks grants, not target scope. Device consumers must additionally
// apply DeviceScopes for this same permission, never scopes from another grant.
func Authorize(p Principal, permission Permission) bool {
	if !knownPermission(permission) || !emergencyAllows(p, permission) {
		return false
	}
	if p.Bindings == nil {
		for _, entry := range permissionTable {
			if entry.permission == permission {
				return slices.Contains(entry.roles, p.Role)
			}
		}
		return false
	}
	for _, binding := range p.Bindings {
		if slices.Contains(binding.GetPermissions(), string(permission)) {
			return true
		}
	}
	return false
}

// Permissions returns effective known permissions, including emergency restrictions.
func Permissions(p Principal) []string {
	permissions := make([]string, 0, len(permissionTable))
	for _, entry := range permissionTable {
		if Authorize(p, entry.permission) {
			permissions = append(permissions, string(entry.permission))
		}
	}
	return permissions
}

// DeviceScopes ORs only bindings granting permission. Scope dimensions are ANDed
// by the target consumer; an unrestricted granting binding wins over restrictions.
func DeviceScopes(p Principal, permission Permission) (bool, []*authv1.DeviceScope) {
	if !Authorize(p, permission) {
		return false, nil
	}
	if p.Bindings == nil {
		return true, nil
	}
	var scopes []*authv1.DeviceScope
	for _, binding := range p.Bindings {
		if !slices.Contains(binding.GetPermissions(), string(permission)) {
			continue
		}
		if len(binding.GetScopes()) == 0 {
			return true, nil
		}
		scopes = append(scopes, binding.GetScopes()...)
	}
	return false, scopes
}
