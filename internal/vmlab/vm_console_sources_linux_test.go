// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/platform"
)

// These are proof-guard/capture regressions, not native package evidence.
func TestSourceProofAdmitsRHEL10WithoutBroadeningTheLane(t *testing.T) {
	for _, key := range []string{"debian-12", "debian-13", "rhel-9", "rhel-10", "rhel-8", "fedora-44"} {
		t.Run(key, func(t *testing.T) {
			_, err := proveRegistryPackageSources(context.Background(), nil, &platform.Release{Key: key}, "", VMConsoleEnrollmentOptions{}, nil)
			want := "release has no registry package source"
			if key == "rhel-8" || key == "fedora-44" {
				want = "package-source proof requires Debian12/13 or RHEL9/10"
			}
			if err == nil || err.Error() != want {
				t.Fatalf("release %s: got %v, want %s", key, err, want)
			}
		})
	}
}

func TestSourceCapabilityRequiresCurrentSignedDeploymentGrant(t *testing.T) {
	notBefore := time.Unix(100, 0)
	state := &adminv1.DeviceCapabilityState{IssuedVersion: 3, IssuedAt: timestamppb.New(notBefore), Granted: []*adminv1.DeviceCapabilityGrant{{Capability: agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES, Sources: []*adminv1.CapabilityPolicyScope{{Scope: &adminv1.CapabilityPolicyScope_Deployment{Deployment: true}}}}}, Reported: &agentv1.CapabilityPolicyObservation{State: agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_ACTIVE, AppliedVersion: 3, AppliedSha256: make([]byte, 32), Capabilities: []*agentv1.CapabilityObservation{{Capability: agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES, Status: agentv1.CapabilityStatus_CAPABILITY_STATUS_ENABLED}}}}
	if !sourceCapabilityMatches(state, agentv1.CapabilityStatus_CAPABILITY_STATUS_ENABLED, "", notBefore) {
		t.Fatal("current remote grant rejected")
	}
	for _, tc := range []struct {
		name  string
		alter func(*adminv1.DeviceCapabilityState)
	}{
		{"no grant", func(s *adminv1.DeviceCapabilityState) { s.Granted = nil }},
		{"unsigned", func(s *adminv1.DeviceCapabilityState) { s.Reported.AppliedSha256 = nil }},
		{"stale", func(s *adminv1.DeviceCapabilityState) { s.Reported.AppliedVersion = 2 }},
		{"old grant issuance", func(s *adminv1.DeviceCapabilityState) { s.IssuedAt = timestamppb.New(notBefore.Add(-time.Second)) }},
		{"no issuance timestamp", func(s *adminv1.DeviceCapabilityState) { s.IssuedAt = nil }},
		{"inert", func(s *adminv1.DeviceCapabilityState) {
			s.Reported.State = agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_INERT
		}},
		{"local opt-in", func(s *adminv1.DeviceCapabilityState) {
			s.Reported.Capabilities[0].Status = agentv1.CapabilityStatus_CAPABILITY_STATUS_LOCAL
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := proto.CloneOf(state)
			tc.alter(copy)
			if sourceCapabilityMatches(copy, agentv1.CapabilityStatus_CAPABILITY_STATUS_ENABLED, "", notBefore) {
				t.Fatal("unqualified capability accepted")
			}
		})
	}
}

func TestSourceRowsRequireAttestedNativeConvergence(t *testing.T) {
	stamp := timestamppb.Now()
	state := &adminv1.GetDeviceResourceStateResponse{Assignment: &adminv1.ResourceAssignment{AssignmentId: "owned-head"}, Resources: []*adminv1.ResourceState{{Disposition: adminv1.ResourceDisposition_RESOURCE_DISPOSITION_SUCCEEDED, Compliance: adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_COMPLIANT, LastVerifiedAt: stamp, LatestAction: &adminv1.ResourceActionSummary{ClosedReason: "result", AttestedAt: stamp, ReceivedAt: stamp, Status: &agentv1.ResourceExecutionStatus{State: agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED, Verification: &resourcev1.ResourceVerification{Disposition: resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED}}}}}}
	if !sourceRowsSettled(state, "owned-head", 1, false) {
		t.Fatal("authenticated converged row rejected")
	}
	for _, tc := range []struct {
		name  string
		alter func(*adminv1.GetDeviceResourceStateResponse)
	}{
		{"wrong head", func(s *adminv1.GetDeviceResourceStateResponse) { s.Assignment.AssignmentId = "other-head" }},
		{"no rows", func(s *adminv1.GetDeviceResourceStateResponse) { s.Resources = nil }},
		{"hold merely released", func(s *adminv1.GetDeviceResourceStateResponse) {
			s.Resources[0].Disposition = adminv1.ResourceDisposition_RESOURCE_DISPOSITION_BLOCKED
		}},
		{"server only", func(s *adminv1.GetDeviceResourceStateResponse) { s.Resources[0].LatestAction.AttestedAt = nil }},
		{"not ingested", func(s *adminv1.GetDeviceResourceStateResponse) { s.Resources[0].LatestAction.ReceivedAt = nil }},
		{"no native verification", func(s *adminv1.GetDeviceResourceStateResponse) { s.Resources[0].LastVerifiedAt = nil }},
		{"unknown native outcome", func(s *adminv1.GetDeviceResourceStateResponse) { s.Resources[0].LatestAction.Status.Verification = nil }},
		{"stale", func(s *adminv1.GetDeviceResourceStateResponse) {
			s.Resources[0].Compliance = adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_STALE
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := proto.CloneOf(state)
			tc.alter(copy)
			if sourceRowsSettled(copy, "owned-head", 1, false) {
				t.Fatal("unqualified native row accepted")
			}
		})
	}
	row := state.Resources[0]
	row.Disposition = adminv1.ResourceDisposition_RESOURCE_DISPOSITION_BLOCKED
	row.Reason = "rhsm_registration_required"
	if !sourceRowsSettled(state, "owned-head", 1, true) {
		t.Fatal("actual registration gate rejected")
	}
	row.Reason = "native_unsupported"
	if sourceRowsSettled(state, "owned-head", 1, true) {
		t.Fatal("generic failure substituted for registration gate")
	}
}

func TestSourceRowsRetryRequiresNewPostregistrationAttestation(t *testing.T) {
	notBefore := time.Unix(100, 0)
	after := timestamppb.New(notBefore.Add(time.Second))
	gate := &adminv1.GetDeviceResourceStateResponse{
		Assignment: &adminv1.ResourceAssignment{AssignmentId: "owned-head"},
		Resources: []*adminv1.ResourceState{{
			ResourceId: "owned-row",
			LatestAction: &adminv1.ResourceActionSummary{
				ActionId: "gate-action", ResourceSequence: 3,
			},
		}},
	}
	retried := &adminv1.GetDeviceResourceStateResponse{
		Assignment: &adminv1.ResourceAssignment{AssignmentId: "owned-head"},
		Resources: []*adminv1.ResourceState{{
			ResourceId: "owned-row", Disposition: adminv1.ResourceDisposition_RESOURCE_DISPOSITION_SUCCEEDED,
			Compliance: adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_COMPLIANT, LastVerifiedAt: after,
			LatestAction: &adminv1.ResourceActionSummary{
				ActionId: "retry-action", ResourceSequence: 4, ClosedReason: "result",
				AttestedAt: after, ReceivedAt: after,
				Status: &agentv1.ResourceExecutionStatus{
					State:        agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED,
					Verification: &resourcev1.ResourceVerification{Disposition: resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED},
				},
			},
		}},
	}
	if !sourceRowsRetried(retried, gate, "owned-head", 1, notBefore) {
		t.Fatal("new postregistration attested retry rejected")
	}
	for _, tc := range []struct {
		name  string
		alter func(*adminv1.GetDeviceResourceStateResponse)
	}{
		{"original convergence", func(s *adminv1.GetDeviceResourceStateResponse) { s.Resources[0].LatestAction.ResourceSequence = 1 }},
		{"same gate sequence", func(s *adminv1.GetDeviceResourceStateResponse) { s.Resources[0].LatestAction.ResourceSequence = 3 }},
		{"same action", func(s *adminv1.GetDeviceResourceStateResponse) { s.Resources[0].LatestAction.ActionId = "gate-action" }},
		{"no action identity", func(s *adminv1.GetDeviceResourceStateResponse) { s.Resources[0].LatestAction.ActionId = "" }},
		{"other resource", func(s *adminv1.GetDeviceResourceStateResponse) { s.Resources[0].ResourceId = "other-row" }},
		{"old verification", func(s *adminv1.GetDeviceResourceStateResponse) {
			s.Resources[0].LastVerifiedAt = timestamppb.New(notBefore.Add(-time.Second))
		}},
		{"equal verification time", func(s *adminv1.GetDeviceResourceStateResponse) {
			s.Resources[0].LastVerifiedAt = timestamppb.New(notBefore)
		}},
		{"old attestation", func(s *adminv1.GetDeviceResourceStateResponse) {
			s.Resources[0].LatestAction.AttestedAt = timestamppb.New(notBefore)
		}},
		{"hold released", func(s *adminv1.GetDeviceResourceStateResponse) {
			s.Resources[0].Disposition = adminv1.ResourceDisposition_RESOURCE_DISPOSITION_BLOCKED
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := proto.CloneOf(retried)
			tc.alter(copy)
			if sourceRowsRetried(copy, gate, "owned-head", 1, notBefore) {
				t.Fatal("stale or unqualified retry accepted")
			}
		})
	}
	if sourceRowsRetried(retried, gate, "other-head", 1, notBefore) ||
		sourceRowsRetried(retried, nil, "owned-head", 1, notBefore) ||
		sourceRowsRetried(retried, gate, "owned-head", 1, time.Time{}) {
		t.Fatal("missing registration or assignment fence accepted")
	}
}

func TestSourceRHSMCleanupRetainsPublicOutcome(t *testing.T) {
	for _, failed := range []bool{false, true} {
		name := "success"
		if failed {
			name = "failure"
		}
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			evidence := &VMRedHatEvidence{RunName: "lindm-lab-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ConsumerUUID: "11111111-1111-4111-8111-111111111111", Registered: true, Unregistered: !failed, ActivationKeyDeleted: !failed}
			var cleanupErr error
			if failed {
				cleanupErr = errors.New("secret-input-sentinel")
			}
			if err := captureSourceRHSMCleanup(directory, evidence, cleanupErr); err != nil {
				t.Fatal(err)
			}
			paths, err := filepath.Glob(filepath.Join(directory, "lindm-cloud-init-*.json"))
			if err != nil || len(paths) != 1 {
				t.Fatalf("cleanup capture missing: %v %v", paths, err)
			}
			info, err := os.Stat(paths[0])
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("cleanup capture is not private")
			}
			data, err := os.ReadFile(paths[0])
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "secret-input-sentinel") {
				t.Fatal("cleanup error text escaped into evidence")
			}
			var captured struct {
				Phase    string           `json:"phase"`
				Evidence VMRedHatEvidence `json:"evidence"`
				Failed   bool             `json:"failed"`
			}
			if err := json.Unmarshal(data, &captured); err != nil {
				t.Fatal(err)
			}
			if captured.Phase != "registry-package-source-rhsm-cleanup" || captured.Failed != failed || captured.Evidence.ConsumerUUID != evidence.ConsumerUUID || captured.Evidence.Unregistered != !failed || captured.Evidence.ActivationKeyDeleted != !failed {
				t.Fatal("cleanup outcome was lost or fabricated")
			}
		})
	}
}
