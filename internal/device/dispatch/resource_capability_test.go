package dispatch

import (
	"slices"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
)

func refusalStatus(reason agentv1.ResourceAdmissionRefusalReason, capability agentv1.ManagementCapability, detail string) *agentv1.ResourceExecutionStatus {
	failure := agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION
	if reason == agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_UNSUPPORTED_NATIVE {
		failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_UNSUPPORTED
	}
	return &agentv1.ResourceExecutionStatus{
		State: agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED, Failure: failure,
		AdmissionRefusal: &agentv1.ResourceAdmissionRefusal{Reason: reason, Capability: capability, Detail: detail, NativeEvidenceUnavailable: true},
	}
}

// The console names the exact capability to enable, and only capability_*
// reasons are dispatched again when the device's capabilities change.
func TestResourceResultDispositionNamesRefusals(t *testing.T) {
	for _, test := range []struct {
		name        string
		status      *agentv1.ResourceExecutionStatus
		disposition int16
		reason      string
	}{
		{"packages not enabled", refusalStatus(agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_CAPABILITY_NOT_ENABLED, agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES, ""), 5, "capability_packages_not_enabled"},
		{"local-only custom roots", refusalStatus(agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_CAPABILITY_NOT_ENABLED, agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_CUSTOM_FILE_ROOTS, ""), 5, "capability_custom_file_roots_not_enabled"},
		{"capability detail does not hide the capability", refusalStatus(agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_CAPABILITY_NOT_ENABLED, agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_KERNEL_SETTINGS, "key_not_allowed"), 5, "capability_kernel_settings_not_enabled"},
		{"adoption required", refusalStatus(agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_ADOPTION_REQUIRED, 0, ""), 5, "adoption_required"},
		{"adoption detail", refusalStatus(agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_ADOPTION_REQUIRED, 0, "existing_banner_file"), 5, "existing_banner_file"},
		{"precondition", refusalStatus(agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_PRECONDITION, 0, ""), 5, "admission_precondition"},
		{"precondition detail", refusalStatus(agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_PRECONDITION, 0, "vendor_key_unrecognized"), 5, "vendor_key_unrecognized"},
		{"unsupported detail", refusalStatus(agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_UNSUPPORTED_NATIVE, 0, "native_tool_outdated"), 6, "native_tool_outdated"},
		{"unsupported", refusalStatus(agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_UNSUPPORTED_NATIVE, 0, ""), 6, "native_unsupported"},
		{"provider unsupported before start", &agentv1.ResourceExecutionStatus{State: agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED, Failure: agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_UNSUPPORTED}, 6, "native_unsupported"},
		{"unsupported after start stays a failure", &agentv1.ResourceExecutionStatus{State: agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED, Failure: agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_UNSUPPORTED, StartedAt: timestamppb.Now()}, 4, "execution_failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			disposition, reason := resourceResultDisposition(test.status)
			if disposition != test.disposition || reason != test.reason {
				t.Fatalf("disposition=%d reason=%q want %d %q", disposition, reason, test.disposition, test.reason)
			}
		})
	}
}

func TestResourceResultBindingAdmitsCapabilityRefusalsAsPreconditions(t *testing.T) {
	ref := &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE, CanonicalKey: "apt/example"}
	intent := &agentv1.ResourceExecutionIntent{Operation: resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, Desired: &resourcev1.ResourceDesiredState{Ref: ref}}
	for _, reason := range []agentv1.ResourceAdmissionRefusalReason{
		agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_CAPABILITY_NOT_ENABLED,
		agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_ADOPTION_REQUIRED,
	} {
		status := refusalStatus(reason, agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES, "")
		status.AdmissionRefusal.Ref, status.AdmissionRefusal.Operation = ref, intent.GetOperation()
		if err := ResourceResultBinding(intent, status); err != nil {
			t.Fatalf("%s refused: %v", reason, err)
		}
		status.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_UNSUPPORTED
		if err := ResourceResultBinding(intent, status); err == nil {
			t.Fatalf("%s admitted with a non-precondition failure", reason)
		}
	}
}

func TestReleaseResultStateNamesCapability(t *testing.T) {
	state, reason := ReleaseResultState(refusalStatus(agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_CAPABILITY_NOT_ENABLED, agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_LOCAL_ACCOUNTS, ""))
	if state != "release_conflict" || reason != "capability_local_accounts_not_enabled" {
		t.Fatalf("state=%s reason=%s", state, reason)
	}
	if _, reason := ReleaseResultState(refusalStatus(agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_PRECONDITION, 0, "native_tool_outdated")); reason != "native_tool_outdated" {
		t.Fatalf("release dropped the refusal detail: %s", reason)
	}
}

// Every qualified kind must be delegable by a production owner: the owner tool
// and development fixtures accept exactly resource.ExecutableKinds.
func TestQualifiedResourceKindsAreDelegable(t *testing.T) {
	executable := resource.ExecutableKinds()
	if len(executable) != len(QualifiedResourceKinds) {
		t.Fatalf("%d executable kinds, %d qualified kinds", len(executable), len(QualifiedResourceKinds))
	}
	for kind := range QualifiedResourceKinds {
		if !slices.Contains(executable, kind) {
			t.Errorf("qualified kind %s cannot be delegated", kind)
		}
	}
}
