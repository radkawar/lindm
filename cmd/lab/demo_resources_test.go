// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// The held demo's resource report shows the product's own outcome per row,
// including device refusals, and never publishes desired values.
func TestDemoResourceRowsReportProductOutcomeWithoutDesiredValues(t *testing.T) {
	const content = "Company managed device. Authorized use only.\n"
	file := &resourcev1.ResourceDesiredState{
		Ref:   &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE, CanonicalKey: "/etc/motd.d/50-company"},
		State: &resourcev1.ResourceDesiredState_ManagedFile{ManagedFile: &resourcev1.ManagedFileDesired{Path: "/etc/motd.d/50-company", Content: []byte(content)}},
	}
	group := &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP, CanonicalKey: "developers"}}
	state := &adminv1.GetDeviceResourceStateResponse{Resources: []*adminv1.ResourceState{
		{
			Desired:        file,
			Disposition:    adminv1.ResourceDisposition_RESOURCE_DISPOSITION_SUCCEEDED,
			Compliance:     adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_COMPLIANT,
			LastVerifiedAt: timestamppb.Now(),
			LatestAction: &adminv1.ResourceActionSummary{Status: &agentv1.ResourceExecutionStatus{
				State:        agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED,
				Failure:      agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NONE,
				Verification: &resourcev1.ResourceVerification{Disposition: resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED},
			}},
		},
		{
			Desired:     group,
			Disposition: adminv1.ResourceDisposition_RESOURCE_DISPOSITION_ATTENTION,
			Compliance:  adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_ATTENTION,
			Reason:      "resource_failed",
			LatestAction: &adminv1.ResourceActionSummary{Status: &agentv1.ResourceExecutionStatus{
				State:            agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED,
				Failure:          agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_UNSUPPORTED,
				AdmissionRefusal: &agentv1.ResourceAdmissionRefusal{Reason: agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_UNSUPPORTED_NATIVE},
			}},
		},
	}}
	rows := demoResourceRows(state)
	want := []demoResourceRow{
		{Kind: "MANAGED_FILE", Key: "/etc/motd.d/50-company", Disposition: "SUCCEEDED", Compliance: "COMPLIANT", Execution: "SUCCEEDED", Verification: "CONVERGED", Verified: true},
		{Kind: "LOCAL_GROUP", Key: "developers", Disposition: "ATTENTION", Compliance: "ATTENTION", Reason: "resource_failed", Execution: "FAILED", Failure: "UNSUPPORTED", Refusal: "UNSUPPORTED_NATIVE"},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows = %+v", rows)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d = %+v, want %+v", i, rows[i], want[i])
		}
	}
	encoded, err := json.Marshal(demoResourceRecord{Resources: rows})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "Authorized use") || strings.Contains(string(encoded), "Q29tcGFueSBtYW5hZ2Vk") {
		t.Fatal("resource evidence published desired content")
	}
	if text := demoResourcesText(rows); !strings.Contains(text, "LOCAL_GROUP developers ATTENTION/ATTENTION resource_failed UNSUPPORTED UNSUPPORTED_NATIVE") {
		t.Fatalf("summary hides the refusal: %s", text)
	}
}

// The held demo records the device page's capability grant with its scopes and
// the executor's own report, including the closed detail of an unavailable
// capability, and names a refused row's detail in the summary.
func TestDemoCapabilitiesReportGrantSourcesAndExecutorStatus(t *testing.T) {
	const finance = "9b1eb9f4-dee7-54b3-839d-4e0938f5a579"
	view := demoCapabilities(&adminv1.DeviceCapabilityState{
		Granted: []*adminv1.DeviceCapabilityGrant{
			{Capability: agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES, Sources: []*adminv1.CapabilityPolicyScope{{Scope: &adminv1.CapabilityPolicyScope_Deployment{Deployment: true}}}},
			{Capability: agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_KERNEL_MODULE_BLOCKLIST, Sources: []*adminv1.CapabilityPolicyScope{{Scope: &adminv1.CapabilityPolicyScope_StaticGroupId{StaticGroupId: finance}}}},
		},
		IssuedVersion: 2,
		Reported: &agentv1.CapabilityPolicyObservation{
			State:          agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_ACTIVE,
			AppliedVersion: 2,
			Capabilities: []*agentv1.CapabilityObservation{
				{Capability: agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES, Status: agentv1.CapabilityStatus_CAPABILITY_STATUS_UNAVAILABLE, Detail: "native_tool_outdated"},
				{Capability: agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_FIREWALL, Status: agentv1.CapabilityStatus_CAPABILITY_STATUS_NOT_ENABLED},
			},
		},
	})
	want := "granted [PACKAGES (deployment); KERNEL_MODULE_BLOCKLIST (static_group:" + finance + ")] issued v2; executor ACTIVE v2 [PACKAGES UNAVAILABLE native_tool_outdated; FIREWALL NOT_ENABLED]"
	if text := demoCapabilitiesText(view); text != want {
		t.Fatalf("capabilities = %q, want %q", text, want)
	}
	if text := demoCapabilitiesText(demoCapabilities(nil)); text != "not reported" {
		t.Fatalf("absent capabilities = %q", text)
	}
	rows := demoResourceRows(&adminv1.GetDeviceResourceStateResponse{Resources: []*adminv1.ResourceState{{
		Desired:     &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SSH_SERVER, CanonicalKey: "system"}},
		Disposition: adminv1.ResourceDisposition_RESOURCE_DISPOSITION_BLOCKED,
		Compliance:  adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_ATTENTION,
		Reason:      "adoption_required",
		LatestAction: &adminv1.ResourceActionSummary{Status: &agentv1.ResourceExecutionStatus{
			State:            agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED,
			Failure:          agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION,
			AdmissionRefusal: &agentv1.ResourceAdmissionRefusal{Reason: agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_ADOPTION_REQUIRED, Detail: "existing_banner_file"},
		}},
	}}})
	if text := demoResourcesText(rows); text != "SSH_SERVER system BLOCKED/ATTENTION adoption_required PRECONDITION ADOPTION_REQUIRED existing_banner_file" {
		t.Fatalf("summary = %q", text)
	}
}
