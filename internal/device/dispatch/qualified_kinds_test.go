package dispatch

import (
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// The console offers exactly the kinds and ownership operations this response
// reports, so the response must agree with what dispatch actually admits: every
// listed (kind, mode, release) dispatches, and every other combination is held.
func TestQualifiedResourceKindsMatchDispatchAdmission(t *testing.T) {
	listed := qualifiedResourceKinds()
	if !slices.IsSortedFunc(listed, func(a, b *adminv1.QualifiedResourceKind) int { return int(a.GetKind()) - int(b.GetKind()) }) {
		t.Fatal("qualified kinds are not ordered by kind number")
	}
	modes := []resourcev1.OwnershipMode{resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION}
	releases := []resourcev1.ReleaseBehavior{resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED, resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN}
	for number := range resourcev1.ResourceKind_name {
		kind := resourcev1.ResourceKind(number)
		index := slices.IndexFunc(listed, func(entry *adminv1.QualifiedResourceKind) bool { return entry.GetKind() == kind })
		for _, mode := range modes {
			for _, release := range releases {
				offered := index >= 0 && slices.Contains(listed[index].GetOwnershipModes(), mode) && slices.Contains(listed[index].GetReleaseBehaviors(), release)
				reason := ResourceDispatchUnsupported(dispatchProbe(kind, mode, release))
				if offered != (reason == "") {
					t.Errorf("kind %s mode %s release %s: offered=%t, dispatch reason %q", kind, mode, release, offered, reason)
				}
			}
		}
	}
}

// dispatchProbe is a minimal resource of kind; SSH server is the banner-only
// configuration, the only SSH admission that is qualified.
func dispatchProbe(kind resourcev1.ResourceKind, mode resourcev1.OwnershipMode, release resourcev1.ReleaseBehavior) *policyv1.ProfileResource {
	desired := &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: kind, CanonicalKey: "probe"}}
	if kind == resourcev1.ResourceKind_RESOURCE_KIND_SSH_SERVER {
		desired.Ref.CanonicalKey = "system"
		desired.State = &resourcev1.ResourceDesiredState_SshServer{SshServer: &resourcev1.SSHServerDesired{BannerText: proto.String("Authorized use only.\n")}}
	}
	return &policyv1.ProfileResource{
		Desired:      desired,
		Ownership:    &resourcev1.OwnershipPolicy{Mode: mode, Release: release},
		Verification: &resourcev1.VerificationPolicy{MaxAgeSeconds: 1800, Checks: []resourcev1.HealthCheck{resourcev1.HealthCheck_HEALTH_CHECK_NATIVE_STATE}},
	}
}
