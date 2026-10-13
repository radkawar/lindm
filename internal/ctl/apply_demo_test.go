package ctl

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"

	"connectrpc.com/connect"

	adminv1 "lindm/gen/lindm/admin/v1"
	adminv1connect "lindm/gen/lindm/admin/v1/adminv1connect"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/orgapply"
	"lindm/internal/policy"
)

// An empty product catalog, not an engine mock: Plan must validate the actual
// checked-in document before resolving its objects through these read-only RPCs.
type emptyOrganizationCatalog struct {
	adminv1connect.AdminServiceClient
}

func (emptyOrganizationCatalog) GetAuthorization(context.Context, *connect.Request[adminv1.GetAuthorizationRequest]) (*connect.Response[adminv1.GetAuthorizationResponse], error) {
	return connect.NewResponse(&adminv1.GetAuthorizationResponse{}), nil
}

func (emptyOrganizationCatalog) ListDeviceGroups(context.Context, *connect.Request[adminv1.ListDeviceGroupsRequest]) (*connect.Response[adminv1.ListDeviceGroupsResponse], error) {
	return connect.NewResponse(&adminv1.ListDeviceGroupsResponse{}), nil
}
func (emptyOrganizationCatalog) GetDynamicGroup(context.Context, *connect.Request[adminv1.GetDynamicGroupRequest]) (*connect.Response[adminv1.GetDynamicGroupResponse], error) {
	return nil, connect.NewError(connect.CodeNotFound, errors.New("absent"))
}
func (emptyOrganizationCatalog) GetProfileRevision(context.Context, *connect.Request[adminv1.GetProfileRevisionRequest]) (*connect.Response[adminv1.GetProfileRevisionResponse], error) {
	return nil, connect.NewError(connect.CodeNotFound, errors.New("absent"))
}
func (emptyOrganizationCatalog) ListRollouts(context.Context, *connect.Request[adminv1.ListRolloutsRequest]) (*connect.Response[adminv1.ListRolloutsResponse], error) {
	return connect.NewResponse(&adminv1.ListRolloutsResponse{}), nil
}
func (emptyOrganizationCatalog) ListTargetAssignments(context.Context, *connect.Request[adminv1.ListTargetAssignmentsRequest]) (*connect.Response[adminv1.ListTargetAssignmentsResponse], error) {
	return connect.NewResponse(&adminv1.ListTargetAssignmentsResponse{}), nil
}
func (emptyOrganizationCatalog) ListProvisioningTokens(context.Context, *connect.Request[adminv1.ListProvisioningTokensRequest]) (*connect.Response[adminv1.ListProvisioningTokensResponse], error) {
	return connect.NewResponse(&adminv1.ListProvisioningTokensResponse{}), nil
}
func (emptyOrganizationCatalog) ListEnrollmentGrants(context.Context, *connect.Request[adminv1.ListEnrollmentGrantsRequest]) (*connect.Response[adminv1.ListEnrollmentGrantsResponse], error) {
	return connect.NewResponse(&adminv1.ListEnrollmentGrantsResponse{}), nil
}
func (emptyOrganizationCatalog) ListCapabilityPolicies(context.Context, *connect.Request[adminv1.ListCapabilityPoliciesRequest]) (*connect.Response[adminv1.ListCapabilityPoliciesResponse], error) {
	// A fresh deployment holds only the seeded all-devices policy.
	return connect.NewResponse(&adminv1.ListCapabilityPoliciesResponse{Deployment: &adminv1.CapabilityPolicy{
		Scope:        &adminv1.CapabilityPolicyScope{Scope: &adminv1.CapabilityPolicyScope_Deployment{Deployment: true}},
		Capabilities: []agentv1.ManagementCapability{1, 2, 4, 6},
		Revision:     1,
	}}), nil
}
func (emptyOrganizationCatalog) ListDevices(context.Context, *connect.Request[adminv1.ListDevicesRequest]) (*connect.Response[adminv1.ListDevicesResponse], error) {
	return connect.NewResponse(&adminv1.ListDevicesResponse{}), nil
}

func TestDemoOrganizationPlan(t *testing.T) {
	data, err := os.ReadFile("../../lab/demo/org.json")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := orgapply.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	var helpdesk []string
	for _, role := range spec.GetAuthorization().GetRoles() {
		if role.GetName() == "demo-helpdesk" {
			helpdesk = role.GetPermissions()
		}
	}
	if !slices.Equal(helpdesk, []string{"fleet.read", "remote_assistance.view", "actions.lock"}) {
		t.Fatalf("helpdesk example must remain view-only without implicit capability grants: %v", helpdesk)
	}
	for _, profile := range spec.GetProfiles() {
		if err := policy.Validate(t.Context(), profile.GetSpec()); err != nil {
			t.Fatalf("profile %s: %v", profile.GetSpec().GetName(), err)
		}
	}
	plan, err := orgapply.Plan(t.Context(), emptyOrganizationCatalog{}, spec)
	if err != nil {
		t.Fatal(err)
	}
	counts := make(map[string]int)
	for _, outcome := range plan.Outcomes {
		counts[outcome.Kind]++
	}
	for kind, want := range map[string]int{"group": 4, "dynamic_group": 4, "profile": 4, "rollout": 0, "assignment": 7, "provisioning_token": 4, "enrollment_grant": 1, "account": 4, "authorization": 1, "advisory_exception": 2, "capability_policy": 3} {
		if counts[kind] != want {
			t.Errorf("%s outcomes=%d want %d", kind, counts[kind], want)
		}
	}
}
