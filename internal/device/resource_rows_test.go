// SPDX-License-Identifier: Apache-2.0

package device

import (
	"slices"
	"testing"

	"lindm/internal/device/dispatch"

	"google.golang.org/protobuf/proto"

	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func qualifiedServiceResource() *policyv1.ProfileResource {
	return &policyv1.ProfileResource{
		Desired:      &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: "example.service"}, State: &resourcev1.ResourceDesiredState_SystemdService{SystemdService: &resourcev1.SystemdServiceDesired{Unit: "example.service", Runtime: resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, Enablement: resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED}}},
		Ownership:    &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN},
		Verification: &resourcev1.VerificationPolicy{MaxAgeSeconds: 1800, Checks: []resourcev1.HealthCheck{resourcev1.HealthCheck_HEALTH_CHECK_NATIVE_STATE}},
	}
}

func TestResourceDispatchDoesNotPromiseUnsupportedMetadata(t *testing.T) {
	base := qualifiedServiceResource()
	if reason := dispatch.ResourceDispatchUnsupported(base); reason != "" {
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
			if dispatch.ResourceDispatchUnsupported(r) == "" {
				t.Fatal("unsupported metadata silently accepted by resource dispatch")
			}
		})
	}
}

func TestResourceDependencyRequiresManagedActiveProof(t *testing.T) {
	item := qualifiedServiceResource()
	if !dispatch.ResourceDependencySatisfied(item, policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_ACTIVE) {
		t.Fatal("managed active proof rejected")
	}
	item.Desired.GetSystemdService().Runtime = resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_UNMANAGED
	if dispatch.ResourceDependencySatisfied(item, policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_ACTIVE) {
		t.Fatal("unmanaged runtime fabricated active dependency evidence")
	}
	if dispatch.ResourceDependencySatisfied(item, policyv1.DependencyCondition_DEPENDENCY_CONDITION_CREDENTIAL_READY) {
		t.Fatal("service proof fabricated credential readiness")
	}
	if !dispatch.ResourceDependencySatisfied(item, policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_CONFIGURED) {
		t.Fatal("configured service proof rejected")
	}
}

func TestResourceDispatchKeepsEveryUnqualifiedKindBlocked(t *testing.T) {
	for kind := range resourcev1.ResourceKind_name {
		if _, qualified := dispatch.QualifiedResourceKinds[resourcev1.ResourceKind(kind)]; qualified {
			continue
		}
		item := qualifiedServiceResource()
		item.Desired.Ref.Kind = resourcev1.ResourceKind(kind)
		if reason := dispatch.ResourceDispatchUnsupported(item); reason != "resource_executor_not_available" {
			t.Fatalf("unqualified kind %d admitted or misclassified: %q", kind, reason)
		}
	}
}

// A qualified kind admits only the ownership operations its native records
// exercised; any other mode or release behavior stays visibly unsupported.
func TestQualifiedKindsAdmitOnlyExercisedOwnership(t *testing.T) {
	for kind, qualification := range dispatch.QualifiedResourceKinds {
		for _, mode := range []resourcev1.OwnershipMode{resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION} {
			for _, release := range []resourcev1.ReleaseBehavior{resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED, resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN} {
				item := qualifiedServiceResource()
				item.Desired.Ref.Kind = kind
				if kind == resourcev1.ResourceKind_RESOURCE_KIND_SSH_SERVER {
					item.Desired.Ref.CanonicalKey = "system"
					item.Desired.State = &resourcev1.ResourceDesiredState_SshServer{SshServer: &resourcev1.SSHServerDesired{BannerText: proto.String("Authorized use only.\n")}}
				}
				item.Ownership = &resourcev1.OwnershipPolicy{Mode: mode, Release: release}
				exercised := slices.Contains(qualification.Releases, release) && slices.Contains(qualification.Modes, mode)
				if got := dispatch.ResourceDispatchUnsupported(item); (got == "") != exercised || (!exercised && got != dispatch.ResourceOwnershipUnavailable) {
					t.Errorf("kind %s mode %s release %s: %q", kind, mode, release, got)
				}
			}
		}
	}
}

func TestResourceDependencyPresenceFollowsDesiredState(t *testing.T) {
	file := &policyv1.ProfileResource{Desired: &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE, CanonicalKey: "/etc/example"}, State: &resourcev1.ResourceDesiredState_ManagedFile{ManagedFile: &resourcev1.ManagedFileDesired{Path: "/etc/example", Presence: resourcev1.Presence_PRESENCE_PRESENT}}}}
	if !dispatch.ResourceDependencySatisfied(file, policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_PRESENT) || dispatch.ResourceDependencySatisfied(file, policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_ACTIVE) {
		t.Fatal("present file dependency misclassified")
	}
	file.Desired.GetManagedFile().Presence = resourcev1.Presence_PRESENCE_ABSENT
	if dispatch.ResourceDependencySatisfied(file, policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_PRESENT) || !dispatch.ResourceDependencySatisfied(file, policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_CONFIGURED) {
		t.Fatal("verified absence satisfied a presence dependency")
	}
	sysctl := &policyv1.ProfileResource{Desired: &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL, CanonicalKey: "vm.swappiness"}, State: &resourcev1.ResourceDesiredState_Sysctl{Sysctl: &resourcev1.SysctlDesired{Key: "vm.swappiness", Value: "10"}}}}
	if dispatch.ResourceDependencySatisfied(sysctl, policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_PRESENT) || !dispatch.ResourceDependencySatisfied(sysctl, policyv1.DependencyCondition_DEPENDENCY_CONDITION_VERIFIED_CONFIGURED) {
		t.Fatal("configuration-only kind fabricated presence")
	}
}

func TestSSHDispatchAdmitsOnlyBanner(t *testing.T) {
	item := qualifiedServiceResource()
	item.Desired = &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SSH_SERVER, CanonicalKey: "system"}, State: &resourcev1.ResourceDesiredState_SshServer{SshServer: &resourcev1.SSHServerDesired{BannerText: proto.String("Authorized use only.\n")}}}
	item.Ownership.Release = resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED
	if reason := dispatch.ResourceDispatchUnsupported(item); reason != "" {
		t.Fatal(reason)
	}
	item.Desired.GetSshServer().Port = proto.Uint32(22)
	if reason := dispatch.ResourceDispatchUnsupported(item); reason != "resource_executor_not_available" {
		t.Fatal("banner qualification admitted unimplemented listener changes", reason)
	}
}
