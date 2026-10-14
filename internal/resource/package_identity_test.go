// SPDX-License-Identifier: Apache-2.0

package resource

import (
	"crypto/sha256"
	"testing"

	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

func nativePackageJSON(architecture, version string) string {
	identity := `{"ecosystem":1,"nativeName":"git"`
	if architecture != "" {
		identity += `,"architecture":"` + architecture + `"`
	}
	selection := `"any":{}`
	if version != "" {
		selection = `"exact":{"deb":"` + version + `"}`
	}
	return `{"nativePackage":{"package":` + identity + `},"presence":1,` + selection + `,"repository":` + fixtureRepository + `,"removal":1}}`
}

func TestNativePackageIdentityFollowsDeviceArchitectureWhenEmpty(t *testing.T) {
	for architecture, want := range map[string]string{"": "deb/git", "amd64": "deb/git/amd64", "all": "deb/git/all"} {
		desired := desiredJSON(t, nativePackageJSON(architecture, ""))
		if key := desired.GetRef().GetCanonicalKey(); key != want {
			t.Fatalf("architecture %q key = %q, want %q", architecture, key, want)
		}
		if err := ValidateRef(desired.GetRef()); err != nil {
			t.Fatalf("derived key %q rejected: %v", want, err)
		}
	}
	for _, key := range []string{"deb/git/", "deb", "deb/git/amd64/extra", "deb//amd64", "debian/git", "deb/git/am d64"} {
		ref := &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE, CanonicalKey: key}
		if err := ValidateRef(ref); err == nil {
			t.Errorf("noncanonical native package key %q accepted", key)
		}
	}
	neutral := desiredJSON(t, nativePackageJSON("", ""))
	neutral.Ref.CanonicalKey = "deb/git/amd64"
	if err := ValidateDesired(neutral); err == nil {
		t.Fatal("neutral desired package accepted a pinned key")
	}
}

func nativePackageObservation(t *testing.T, ref, architecture string) (*resourcev1.ResourceObservation, *resourcev1.NativePackageRecord) {
	t.Helper()
	_, observation, _ := serviceEvidence(t)
	identity := &resourcev1.PackageIdentity{Ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, NativeName: "git", Architecture: architecture}
	nativeIdentity := sha256.Sum256([]byte("fixture installed git/" + architecture + " 1.0 instance 1"))
	record := &resourcev1.NativePackageRecord{Package: proto.CloneOf(identity), Version: &resourcev1.NativeVersion{Version: &resourcev1.NativeVersion_Deb{Deb: "1.0"}}, NativeIdentitySha256: nativeIdentity[:]}
	observation.Ref = &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE, CanonicalKey: ref}
	observation.Observed = &resourcev1.ResourceObservation_NativePackage{NativePackage: &resourcev1.NativePackageObservation{
		Package: identity, Installed: true, Record: record, DatabaseRevisionSha256: make([]byte, 32),
	}}
	return observation, record
}

func TestNeutralPackageObservationCarriesResolvedArchitecture(t *testing.T) {
	for _, architecture := range []string{"amd64", "arm64", "all"} {
		observation, record := nativePackageObservation(t, "deb/git", architecture)
		if err := ValidateObservation(observation); err != nil {
			t.Fatalf("resolved %s evidence for a neutral package rejected: %v", architecture, err)
		}
		record.Package.Architecture = "i386"
		if err := ValidateObservation(observation); err == nil {
			t.Fatal("record of another architecture accepted for the resolved package")
		}
	}
	unresolved, record := nativePackageObservation(t, "deb/git", "")
	record.Package.Architecture = ""
	if err := ValidateObservation(unresolved); err == nil {
		t.Fatal("neutral package evidence without a resolved architecture accepted")
	}
	other, _ := nativePackageObservation(t, "deb/git-man", "amd64")
	if err := ValidateObservation(other); err == nil {
		t.Fatal("evidence for another package name accepted for a neutral ref")
	}
	pinned, _ := nativePackageObservation(t, "deb/git/amd64", "arm64")
	if err := ValidateObservation(pinned); err == nil {
		t.Fatal("pinned package accepted evidence of another architecture")
	}
	pinned.GetNativePackage().Package.Architecture = "amd64"
	pinned.GetNativePackage().Record.Package.Architecture = "amd64"
	if err := ValidateObservation(pinned); err != nil {
		t.Fatalf("pinned package evidence rejected: %v", err)
	}
}

func TestNeutralAndPinnedPackageRowsConflict(t *testing.T) {
	rpm := `{"nativePackage":{"package":{"ecosystem":2,"nativeName":"git"},"presence":1,"exact":{"rpm":{"epoch":0,"version":"2.0","release":"1"}},"repository":{"kind":13,"canonicalKey":"rpm/` + fixtureID + `"},"removal":1}}`
	cases := []struct {
		name     string
		left     string
		right    string
		conflict bool
	}{
		{"neutral and pinned row of one package", nativePackageJSON("", ""), nativePackageJSON("amd64", ""), true},
		{"neutral and foreign pinned row of one package", nativePackageJSON("", ""), nativePackageJSON("i386", ""), true},
		{"neutral rows agree", nativePackageJSON("", "1.0-1"), nativePackageJSON("", "1.0-1"), false},
		{"pinned rows of two architectures", nativePackageJSON("amd64", ""), nativePackageJSON("i386", ""), false},
		{"pinned rows with different exact versions", nativePackageJSON("amd64", "1.0-1"), nativePackageJSON("i386", "2.0-1"), true},
		{"pinned rows with one exact version", nativePackageJSON("amd64", "1.0-1"), nativePackageJSON("i386", "1.0-1"), false},
		{"another ecosystem", nativePackageJSON("", "1.0-1"), rpm, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			left, right := claimsJSON(t, test.left), claimsJSON(t, test.right)
			if actual := Conflicts(left, right); actual != test.conflict {
				t.Fatalf("conflict = %v, want %v", actual, test.conflict)
			}
			if actual := Conflicts(right, left); actual != test.conflict {
				t.Fatalf("reversed conflict = %v, want %v", actual, test.conflict)
			}
		})
	}
	neutral, pinned := claimsJSON(t, nativePackageJSON("", "1.0-1")), claimsJSON(t, nativePackageJSON("amd64", "2.0-1"))
	exact := func(claims []*resourcev1.ResourceClaim) *resourcev1.ResourceClaim {
		for _, claim := range claims {
			if claim.GetDomain() == resourcev1.ClaimDomain_CLAIM_DOMAIN_PACKAGE && claim.GetKey() == "deb/git" && claim.GetMode() == resourcev1.ClaimMode_CLAIM_MODE_VALUE {
				return claim
			}
		}
		return nil
	}
	if left, right := exact(neutral), exact(pinned); left == nil || right == nil || !Conflicts([]*resourcev1.ResourceClaim{left}, []*resourcev1.ResourceClaim{right}) {
		t.Fatal("neutral and pinned exact versions of one package are not comparable")
	}
}

func TestRollingSnapshotAllowsNeutralPackageWithoutPin(t *testing.T) {
	desired := desiredJSON(t, updateJSON())
	desired.GetOsUpdate().Selection = resourcev1.UpdateSelection_UPDATE_SELECTION_ALL
	desired.GetOsUpdate().DeferralDays = 0
	desired.GetOsUpdate().RollingSnapshot = &resourcev1.RollingUpdateSnapshot{Date: "2026-10-02"}
	rolling, err := Claims(desired)
	if err != nil {
		t.Fatal(err)
	}
	if Conflicts(rolling, claimsJSON(t, nativePackageJSON("", ""))) {
		t.Fatal("rolling snapshot refused an unpinned neutral package")
	}
	if !Conflicts(rolling, claimsJSON(t, nativePackageJSON("", "1.0-1"))) {
		t.Fatal("rolling snapshot silently overrode a neutral package pin")
	}
}
