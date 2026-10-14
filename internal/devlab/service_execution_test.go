// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
	"lindm/internal/trust"
)

func TestResourceChallengeWindowDeviceClockTolerance(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		skew time.Duration
		want bool
	}{
		{"ahead ninety seconds", 90 * time.Second, true},
		{"behind ninety seconds", -90 * time.Second, true},
		{"ahead inclusive boundary", trust.MaxDeviceClockSkew, true},
		{"ahead beyond boundary", trust.MaxDeviceClockSkew + time.Nanosecond, false},
		{"expired exclusive boundary", -trust.MaxDeviceClockSkew - 30*time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			intent := &agentv1.ResourceExecutionIntent{NotBefore: timestamppb.New(now.Add(-5 * time.Minute)), ExpiresAt: timestamppb.New(now.Add(5 * time.Minute))}
			challenge := &agentv1.ResourceExecutionChallenge{IssuedAt: timestamppb.New(now.Add(tc.skew)), ExpiresAt: timestamppb.New(now.Add(tc.skew + 30*time.Second))}
			if got := serviceChallengeWindow(now, intent, challenge); got != tc.want {
				t.Fatalf("signing window accepted=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestResourceChallengeWindowDoesNotExtendIntent(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name                        string
		start, end, issued, expires time.Duration
	}{
		{"host intent expired", -time.Minute, 0, -30 * time.Second, -time.Second},
		{"host intent not yet valid", time.Second, time.Minute, 2 * time.Second, 30 * time.Second},
		{"challenge predates intent", -time.Second, time.Minute, -2 * time.Second, 28 * time.Second},
		{"challenge outlives intent", -time.Minute, time.Second, 0, 30 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			intent := &agentv1.ResourceExecutionIntent{NotBefore: timestamppb.New(now.Add(tc.start)), ExpiresAt: timestamppb.New(now.Add(tc.end))}
			challenge := &agentv1.ResourceExecutionChallenge{IssuedAt: timestamppb.New(now.Add(tc.issued)), ExpiresAt: timestamppb.New(now.Add(tc.expires))}
			if serviceChallengeWindow(now, intent, challenge) {
				t.Fatal("device-clock tolerance extended host intent authority")
			}
		})
	}
}

// The lab's pacman resource lane (Omarchy 4.0.4 executor phase) signed no
// intent: the fixture admitted only DEB and RPM proof packages.
func TestFixtureResourceIntentAdmitsALPMProofPackage(t *testing.T) {
	intent := func(architecture, repository string) *agentv1.ResourceExecutionIntent {
		exact := &resourcev1.NativeVersion{Version: &resourcev1.NativeVersion_Alpm{Alpm: &resourcev1.ALPMVersion{Pkgver: "1.0", Pkgrel: "1"}}}
		desired := &resourcev1.NativePackageDesired{Package: &resourcev1.PackageIdentity{Ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM, NativeName: "lindm-resource-proof", Architecture: architecture}, Presence: resourcev1.Presence_PRESENCE_PRESENT, Repository: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_PACKAGE_REPOSITORY, CanonicalKey: repository}, Removal: resourcev1.PackageRemovalPolicy_PACKAGE_REMOVAL_POLICY_PRESERVE_DATA, Version: &resourcev1.NativePackageDesired_Exact{Exact: exact}}
		return &agentv1.ResourceExecutionIntent{Operation: resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, Desired: &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE, CanonicalKey: "alpm/lindm-resource-proof/" + architecture}, State: &resourcev1.ResourceDesiredState_NativePackage{NativePackage: desired}}}
	}
	if err := resource.ValidateDesired(intent("x86_64", "alpm/d06a3d03-3118-4779-a00f-a5544ff095ad").GetDesired()); err != nil {
		t.Fatal(err)
	}
	if !fixtureResourceIntent(intent("x86_64", "alpm/d06a3d03-3118-4779-a00f-a5544ff095ad")) {
		t.Fatal("ALPM proof package from the disposable repository was refused")
	}
	for _, refused := range [][2]string{{"x86_64", "alpm/00000000-0000-0000-0000-000000000000"}, {"aarch64", "alpm/d06a3d03-3118-4779-a00f-a5544ff095ad"}, {"x86_64", "rpm/d06a3d03-3118-4779-a00f-a5544ff095ad"}} {
		if fixtureResourceIntent(intent(refused[0], refused[1])) {
			t.Fatalf("fixture signed ALPM intent outside its repository: %v", refused)
		}
	}
}
