//go:build linux

package journal

import (
	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/resourceprovider"
)

// ownershipKind holds the journal's kind-specific ownership rules. Kinds
// without an entry use only the generic snapshot checks.
type ownershipKind struct {
	// valid checks the kind's private snapshot shape.
	valid func(*agentv1.ResourceOwnershipSnapshot) bool
	// acquisition decides whether a first claim may adopt the observed state.
	acquisition func(*agentv1.ResourceExecutionIntent, *agentv1.ResourceOwnershipSnapshot) bool
	// baseline replaces the generic per-dimension baseline comparison.
	baseline func(*agentv1.ResourceOwnershipLedger, *agentv1.ResourceOwnershipSnapshot, agentv1.ResourceOwnedDimension) bool
	// numeric is the journal-owned numeric identity dimension, if any.
	numeric agentv1.ResourceOwnedDimension
}

// ownershipKinds is the journal's only resource-kind dispatch.
var ownershipKinds = resourceprovider.NewRegistry(map[resourcev1.ResourceKind]ownershipKind{
	resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL:             {valid: sysctlOwnershipSnapshotValid, acquisition: sysctlOwnershipAcquisitionAllowed},
	resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_DEFINITION: {valid: definitionOwnershipSnapshotValid, acquisition: definitionOwnershipAcquisitionAllowed},
	resourcev1.ResourceKind_RESOURCE_KIND_PASSWORD_POLICY:    {valid: passwordOwnershipSnapshotValid, acquisition: passwordOwnershipAcquisitionAllowed, baseline: PasswordBaselineDimensionMatches},
	resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE:      {valid: firewallOwnershipSnapshotValid, acquisition: firewallOwnershipAcquisitionAllowed},
	resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER:         {numeric: agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_USER_UID},
	resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP:        {numeric: agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_GROUP_GID},
})

// ownershipRules returns the kind's rules, or none for generic kinds.
func ownershipRules(kind resourcev1.ResourceKind) ownershipKind {
	rules, _ := ownershipKinds.Lookup(kind) // an unregistered kind has no extra rules
	return rules
}
