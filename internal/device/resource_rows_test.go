package device

import (
	"testing"

	"google.golang.org/protobuf/proto"

	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func bridgeServiceResource() *policyv1.ProfileResource {
	return &policyv1.ProfileResource{
		Desired:      &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: "example.service"}, State: &resourcev1.ResourceDesiredState_SystemdService{SystemdService: &resourcev1.SystemdServiceDesired{Unit: "example.service", Runtime: resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, Enablement: resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED}}},
		Ownership:    &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN},
		Verification: &resourcev1.VerificationPolicy{MaxAgeSeconds: 1800, Checks: []resourcev1.HealthCheck{resourcev1.HealthCheck_HEALTH_CHECK_NATIVE_STATE}},
	}
}

func TestResourceServiceBridgeDoesNotPromiseUnsupportedMetadata(t *testing.T) {
	base := bridgeServiceResource()
	if reason := resourceDispatchUnsupported(base); reason != "" {
		t.Fatalf("ordinary service rejected: %s", reason)
	}
	cases := []struct {
		name   string
		change func(*policyv1.ProfileResource)
	}{
		{"native restore", func(r *policyv1.ProfileResource) {
			r.Ownership.Release = resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED
		}},
		{"ownership adoption", func(r *policyv1.ProfileResource) {
			r.Ownership.Mode = resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION
		}},
		{"application readiness", func(r *policyv1.ProfileResource) {
			r.Verification.Checks = append(r.Verification.Checks, resourcev1.HealthCheck_HEALTH_CHECK_APPLICATION_READY)
		}},
		{"capability qualification", func(r *policyv1.ProfileResource) {
			r.Applicability = &resourcev1.Applicability{Features: []resourcev1.ResourceFeature{resourcev1.ResourceFeature_RESOURCE_FEATURE_SAFE_RELEASE}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := proto.CloneOf(base)
			tc.change(r)
			if resourceDispatchUnsupported(r) == "" {
				t.Fatal("unsupported metadata silently accepted by legacy service execution boundary")
			}
		})
	}
}

func TestResourceDependencyRequiresManagedActiveProof(t *testing.T) {
	item := bridgeServiceResource()
	if !resourceDependencySatisfied(item, policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_ACTIVE) {
		t.Fatal("managed active proof rejected")
	}
	item.Desired.GetSystemdService().Runtime = resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_UNMANAGED
	if resourceDependencySatisfied(item, policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_ACTIVE) {
		t.Fatal("unmanaged runtime fabricated active dependency evidence")
	}
	if resourceDependencySatisfied(item, policyv1.DependencyCondition_DEPENDENCY_CONDITION_CREDENTIAL_READY) {
		t.Fatal("service proof fabricated credential readiness")
	}
	if !resourceDependencySatisfied(item, policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_CONFIGURED) {
		t.Fatal("configured service proof rejected")
	}
}
