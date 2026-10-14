// SPDX-License-Identifier: Apache-2.0

package orgapply

import (
	"testing"

	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

func TestApplyPreservesIndependentRebootPolicy(t *testing.T) {
	spec := organizationFixture()
	policy := &resourcev1.OSUpdateDesired{
		Selection:   resourcev1.UpdateSelection_UPDATE_SELECTION_SECURITY,
		Maintenance: &resourcev1.MaintenanceWindow{TimeZone: "Europe/London", Weekdays: []resourcev1.Weekday{resourcev1.Weekday_WEEKDAY_MONDAY}, LocalStartMinute: 120, DurationMinutes: 120},
		RebootPolicy: &resourcev1.OSUpdateRebootPolicy{
			Mode: resourcev1.OSUpdateRebootMode_OS_UPDATE_REBOOT_MODE_SCHEDULED, MaxDelayMinutes: 360,
			RebootWindow:     &resourcev1.MaintenanceWindow{TimeZone: "Europe/Berlin", Weekdays: []resourcev1.Weekday{resourcev1.Weekday_WEEKDAY_MONDAY}, LocalStartMinute: 360, DurationMinutes: 60},
			EmployeeDeferral: &resourcev1.OSUpdateRebootDeferral{MaxDeferrals: 2, DelayMinutes: 15},
		},
	}
	spec.Profiles[0].Spec.Resources[0].Desired = &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_OS_UPDATE_POLICY, CanonicalKey: "system"}, State: &resourcev1.ResourceDesiredState_OsUpdate{OsUpdate: policy}}
	client := newFakeAdmin()
	plan, err := Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(t.Context(), client, plan, Options{}); err != nil {
		t.Fatal(err)
	}
	got := client.profiles[profileID].GetSpec().GetResources()[0].GetDesired().GetOsUpdate()
	if !proto.Equal(got, policy) {
		t.Fatalf("apply changed independent windows or employee limits: %v", got)
	}
	policy.RebootPolicy.EmployeeDeferral.MaxDeferrals = 1
	plan, err = Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(t.Context(), client, plan, Options{}); err != nil {
		t.Fatal(err)
	}
	if client.profiles[profileID].GetRevisionNumber() != 2 {
		t.Fatal("reboot policy change did not publish a new immutable revision")
	}
}
