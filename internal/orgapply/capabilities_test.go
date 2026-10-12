package orgapply

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	orgv1 "lindm/gen/lindm/org/v1"
	"lindm/internal/rpcreason"
)

// capabilityAdmin keeps the product's revision semantics: one policy per scope,
// a stale expected revision is refused, an empty group policy is removed.
type capabilityAdmin struct {
	*fakeAdmin
	policies map[string]*adminv1.CapabilityPolicy
	revision uint64
	sets     []*adminv1.SetCapabilityPolicyRequest
}

func newCapabilityAdmin() *capabilityAdmin {
	deployment := &adminv1.CapabilityPolicy{
		Scope:        &adminv1.CapabilityPolicyScope{Scope: &adminv1.CapabilityPolicyScope_Deployment{Deployment: true}},
		Capabilities: []agentv1.ManagementCapability{1, 2, 4, 6}, Revision: 1,
	}
	return &capabilityAdmin{fakeAdmin: newFakeAdmin(), policies: map[string]*adminv1.CapabilityPolicy{"deployment": deployment}, revision: 1}
}

func (f *capabilityAdmin) ListCapabilityPolicies(context.Context, *connect.Request[adminv1.ListCapabilityPoliciesRequest]) (*connect.Response[adminv1.ListCapabilityPoliciesResponse], error) {
	response := &adminv1.ListCapabilityPoliciesResponse{Deployment: proto.CloneOf(f.policies["deployment"])}
	for key, policy := range f.policies {
		if key != "deployment" {
			response.Groups = append(response.Groups, proto.CloneOf(policy))
		}
	}
	return connect.NewResponse(response), nil
}

func (f *capabilityAdmin) SetCapabilityPolicy(_ context.Context, r *connect.Request[adminv1.SetCapabilityPolicyRequest]) (*connect.Response[adminv1.SetCapabilityPolicyResponse], error) {
	f.sets = append(f.sets, proto.CloneOf(r.Msg))
	key := capabilityScopeKey(r.Msg.GetScope())
	if f.policies[key].GetRevision() != r.Msg.GetExpectedRevision() {
		return nil, rpcreason.Error(connect.CodeAborted, "capability_policy_revision_conflict")
	}
	if key != "deployment" && len(r.Msg.GetCapabilities()) == 0 {
		delete(f.policies, key)
		return connect.NewResponse(&adminv1.SetCapabilityPolicyResponse{Policy: &adminv1.CapabilityPolicy{Scope: r.Msg.GetScope()}}), nil
	}
	f.revision++
	policy := &adminv1.CapabilityPolicy{Scope: r.Msg.GetScope(), Capabilities: r.Msg.GetCapabilities(), SysctlKeys: r.Msg.GetSysctlKeys(), Firewall: r.Msg.GetFirewall(), Revision: f.revision}
	f.policies[key] = policy
	return connect.NewResponse(&adminv1.SetCapabilityPolicyResponse{Policy: proto.CloneOf(policy)}), nil
}

func capabilityPolicyEntry(scope *adminv1.CapabilityPolicyScope, capabilities ...agentv1.ManagementCapability) *orgv1.CapabilityPolicy {
	return &orgv1.CapabilityPolicy{Request: &adminv1.SetCapabilityPolicyRequest{Scope: scope, Capabilities: capabilities}}
}

func TestCapabilityPoliciesApplyAfterGroupsAndAreIdempotent(t *testing.T) {
	spec := organizationFixture()
	group := &adminv1.CapabilityPolicyScope{Scope: &adminv1.CapabilityPolicyScope_StaticGroupId{StaticGroupId: groupID}}
	deployment := &adminv1.CapabilityPolicyScope{Scope: &adminv1.CapabilityPolicyScope_Deployment{Deployment: true}}
	spec.CapabilityPolicies = []*orgv1.CapabilityPolicy{
		capabilityPolicyEntry(group, agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_KERNEL_MODULE_BLOCKLIST),
		// Equal to the seeded deployment policy as a set, in another order.
		capabilityPolicyEntry(deployment, 6, 4, 2, 1),
	}
	client := newCapabilityAdmin()
	plan, err := Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	statuses := make(map[string]string)
	groupIndex, policyIndex := -1, -1
	for i, outcome := range plan.Outcomes {
		if outcome.Kind == "capability_policy" {
			statuses[outcome.Name] = outcome.Status
			if policyIndex < 0 {
				policyIndex = i
			}
		}
		if outcome.Kind == "group" {
			groupIndex = i
		}
	}
	if statuses["static_group:"+groupID] != "created" || statuses["deployment"] != "unchanged" {
		t.Fatalf("planned capability outcomes %v", statuses)
	}
	if groupIndex < 0 || policyIndex < groupIndex {
		t.Fatal("capability policies must apply after the groups they reference")
	}
	if _, err := Apply(t.Context(), client, plan, Options{}); err != nil {
		t.Fatal(err)
	}
	if len(client.sets) != 1 {
		t.Fatalf("applied %d capability policies, want 1", len(client.sets))
	}
	set := client.sets[0]
	if set.GetRequestId() == "" || set.GetReason() != "Apply organization test" || set.GetExpectedRevision() != 0 {
		t.Fatalf("engine-owned fields not completed: %+v", set)
	}
	again, err := Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(t.Context(), client, again, Options{}); err != nil {
		t.Fatal(err)
	}
	if len(client.sets) != 1 {
		t.Fatal("unchanged capability policies were applied again")
	}
	// Changing a declared scope uses its observed revision; a stale plan aborts.
	spec.CapabilityPolicies[1] = capabilityPolicyEntry(deployment, 1, 2)
	changed, err := Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(t.Context(), client, changed, Options{}); err != nil {
		t.Fatal(err)
	}
	if last := client.sets[len(client.sets)-1]; last.GetExpectedRevision() != 1 || len(client.policies["deployment"].GetCapabilities()) != 2 {
		t.Fatalf("deployment update did not carry the observed revision: %+v", last)
	}
	if _, err := Apply(t.Context(), client, changed, Options{}); connect.CodeOf(err) != connect.CodeAborted {
		t.Fatalf("stale capability plan must surface the CAS conflict, got %v", err)
	}
}

func TestCapabilityPolicyValidationRejectsDuplicateScopesAndOwnedFields(t *testing.T) {
	deployment := &adminv1.CapabilityPolicyScope{Scope: &adminv1.CapabilityPolicyScope_Deployment{Deployment: true}}
	spec := organizationFixture()
	spec.CapabilityPolicies = []*orgv1.CapabilityPolicy{capabilityPolicyEntry(deployment, 1), capabilityPolicyEntry(deployment, 2)}
	if err := Validate(spec); err == nil {
		t.Fatal("duplicate scope accepted")
	}
	spec.CapabilityPolicies = []*orgv1.CapabilityPolicy{capabilityPolicyEntry(deployment, 1)}
	spec.CapabilityPolicies[0].Request.ExpectedRevision = 3
	if err := Validate(spec); err == nil {
		t.Fatal("document-supplied expected revision accepted")
	}
	spec.CapabilityPolicies[0].Request.ExpectedRevision = 0
	spec.CapabilityPolicies[0].Request.Capabilities = []agentv1.ManagementCapability{agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PASSWORD_POLICY}
	if err := Validate(spec); err == nil {
		t.Fatal("local-only capability accepted")
	}
}
