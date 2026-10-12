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
