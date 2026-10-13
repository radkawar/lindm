// Package permissionupgrade maps permission names an earlier release could
// persist or configure to their current, meaning-preserving equivalents. It is
// applied only to state an earlier release wrote: the persisted runtime
// authorization policy and the server configuration file. API and declarative
// input validators keep rejecting retired names.
package permissionupgrade

import (
	"slices"

	authv1 "lindm/gen/lindm/auth/v1"
)

// Rename is one retired permission and the current permissions that together
// grant exactly what it granted.
type Rename struct {
	Legacy  string
	Current []string
}

// renames is append-only: an upgrade from any earlier release applies every
// entry. Current names are always current; retiring one of them updates the
// earlier entry too. Each entry needs an upgrade fixture under
// internal/identity/testdata/upgrade.
var renames = []Rename{
	// remote_assistance.run granted both viewing and control until c793dfef.
	{Legacy: "remote_assistance.run", Current: []string{"remote_assistance.view", "remote_assistance.control"}},
}

// Renames returns every retired permission in registration order.
func Renames() []Rename {
	out := make([]Rename, len(renames))
	for i, rename := range renames {
		out[i] = Rename{Legacy: rename.Legacy, Current: slices.Clone(rename.Current)}
	}
	return out
}

// Replacement returns the current permissions for a retired name.
func Replacement(name string) ([]string, bool) {
	index := slices.IndexFunc(renames, func(r Rename) bool { return r.Legacy == name })
	if index < 0 {
		return nil, false
	}
	return slices.Clone(renames[index].Current), true
}

// Permissions replaces each retired name in place by its current names, keeping
// the first occurrence of a duplicate. It returns the input unchanged and no
// legacy names when nothing was retired.
func Permissions(permissions []string) (upgraded, legacy []string) {
	for _, name := range permissions {
		if _, ok := Replacement(name); ok {
			legacy = append(legacy, name)
		}
	}
	if len(legacy) == 0 {
		return permissions, nil
	}
	upgraded = make([]string, 0, len(permissions)+len(legacy))
	for _, name := range permissions {
		names, ok := Replacement(name)
		if !ok {
			names = []string{name}
		}
		for _, name := range names {
			if !slices.Contains(upgraded, name) {
				upgraded = append(upgraded, name)
			}
		}
	}
	return upgraded, legacy
}

// Change is one permission list that held retired names.
type Change struct {
	// List is "roles/<name>" or "approval_required_permissions".
	List   string
	Legacy []string
}

// Policy rewrites the custom roles and approval gates of policy in place.
// Group bindings name roles, not permissions, and are unaffected.
func Policy(policy *authv1.AuthorizationPolicy) []Change {
	var changes []Change
	for _, role := range policy.GetRoles() {
		upgraded, legacy := Permissions(role.GetPermissions())
		if len(legacy) != 0 {
			role.Permissions = upgraded
			changes = append(changes, Change{List: "roles/" + role.GetName(), Legacy: legacy})
		}
	}
	if policy != nil {
		upgraded, legacy := Permissions(policy.GetApprovalRequiredPermissions())
		if len(legacy) != 0 {
			policy.ApprovalRequiredPermissions = upgraded
			changes = append(changes, Change{List: "approval_required_permissions", Legacy: legacy})
		}
	}
	return changes
}
