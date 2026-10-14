// SPDX-License-Identifier: Apache-2.0

package orgapply

import (
	"context"
	"fmt"
	"slices"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	adminv1connect "lindm/gen/lindm/admin/v1/adminv1connect"
	agentv1 "lindm/gen/lindm/agent/v1"
)

// capabilityScopeKey names a capability policy scope in outcomes and request
// identities: "deployment", "static_group:<id>" or "dynamic_group:<id>".
func capabilityScopeKey(scope *adminv1.CapabilityPolicyScope) string {
	switch s := scope.GetScope().(type) {
	case *adminv1.CapabilityPolicyScope_StaticGroupId:
		return "static_group:" + s.StaticGroupId
	case *adminv1.CapabilityPolicyScope_DynamicGroupId:
		return "dynamic_group:" + s.DynamicGroupId
	default:
		return "deployment"
	}
}

// capabilityPolicies plans after groups, so a policy for a group created by
// this document applies once the group exists. Each entry replaces its scope's
// complete policy; equal policies (as sets) are unchanged.
func (p *ChangePlan) capabilityPolicies(ctx context.Context, client adminv1connect.AdminServiceClient) error {
	if len(p.spec.GetCapabilityPolicies()) == 0 {
		return nil
	}
	response, err := client.ListCapabilityPolicies(ctx, connect.NewRequest(&adminv1.ListCapabilityPoliciesRequest{}))
	if err != nil {
		return fmt.Errorf("list capability policies: %w", err)
	}
	current := map[string]*adminv1.CapabilityPolicy{"deployment": response.Msg.GetDeployment()}
	for _, policy := range response.Msg.GetGroups() {
		current[capabilityScopeKey(policy.GetScope())] = policy
	}
	for _, entry := range p.spec.GetCapabilityPolicies() {
		desired := proto.CloneOf(entry.GetRequest())
		key := capabilityScopeKey(desired.GetScope())
		existing := current[key]
		id := desired.GetScope().GetStaticGroupId() + desired.GetScope().GetDynamicGroupId()
		if sameCapabilityPolicy(existing, desired) {
			p.add("capability_policy", key, id, "unchanged", "", nil)
			continue
		}
		status, detail := "updated", ""
		switch {
		case existing.GetRevision() == 0:
			status = "created"
		case id != "" && len(desired.GetCapabilities()) == 0:
			detail = "Removes the group's capability policy."
		}
		desired.ExpectedRevision = existing.GetRevision()
		desired.Reason = reason(p.spec)
		p.add("capability_policy", key, id, status, detail, desired)
	}
	return nil
}

func sameCapabilityPolicy(existing *adminv1.CapabilityPolicy, desired *adminv1.SetCapabilityPolicyRequest) bool {
	sorted := func(values []agentv1.ManagementCapability) []agentv1.ManagementCapability {
		return slices.Sorted(slices.Values(values))
	}
	return slices.Equal(sorted(existing.GetCapabilities()), sorted(desired.GetCapabilities())) &&
		slices.Equal(slices.Sorted(slices.Values(existing.GetSysctlKeys())), slices.Sorted(slices.Values(desired.GetSysctlKeys()))) &&
		proto.Equal(existing.GetFirewall(), desired.GetFirewall())
}
