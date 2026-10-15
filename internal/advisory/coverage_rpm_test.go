// SPDX-License-Identifier: Apache-2.0

package advisory

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	"lindm/internal/platform"
)

func TestRHELProductMembershipRequiresExactVendorDeclaration(t *testing.T) {
	source := &advisoryv1.FeedSource{Distro: "rhel", Release: "9", PlatformStream: "standard", Architecture: "x86_64"}
	base := &advisoryv1.Advisory{PackageName: "nodejs-libs", PlatformRelease: "9", PlatformStream: "standard", Architecture: "x86_64", ModuleName: "nodejs", ModuleStream: "18", ComponentVersion: "1:18.19.0-1.module.el9"}
	version := "1:18.19.0-1.module.el9"
	if !exactRhelDeclaration(source, base, version, "x86_64", "src", "nodejs", "18") {
		t.Fatal("exact native product declaration rejected")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*advisoryv1.Advisory)
	}{
		{"other-product", func(r *advisoryv1.Advisory) { r.PlatformRelease = "10" }},
		{"other-servicing-stream", func(r *advisoryv1.Advisory) { r.PlatformStream = "eus" }},
		{"other-architecture", func(r *advisoryv1.Advisory) { r.Architecture = "aarch64" }},
		{"binary-architecture-absent", func(r *advisoryv1.Advisory) { r.Architecture = "" }},
		{"other-module", func(r *advisoryv1.Advisory) { r.ModuleName = "ruby" }},
		{"other-module-stream", func(r *advisoryv1.Advisory) { r.ModuleStream = "20" }},
		{"nonmodular-component", func(r *advisoryv1.Advisory) { r.ModuleName = ""; r.ModuleStream = "" }},
		{"only-affected-range", func(r *advisoryv1.Advisory) {
			r.ComponentVersion = ""
			r.IntroducedVersion = "0"
			r.FixedVersion = "1:18.20.0-1.module.el9"
		}},
		{"other-build-of-same-package", func(r *advisoryv1.Advisory) { r.ComponentVersion = "1:18.19.0-2.module.el9" }},
		{"source-record-rejected", func(r *advisoryv1.Advisory) { r.SourceRecordRejected = true }},
		{"source-epoch-unproved", func(r *advisoryv1.Advisory) { r.SourcePackage = true; r.Architecture = "src" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := proto.CloneOf(base)
			tc.mutate(r)
			if exactRhelDeclaration(source, r, version, "x86_64", "src", "nodejs", "18") {
				t.Fatalf("unproved product membership admitted: %v", r)
			}
		})
	}
	for _, kind := range []string{"fixed", "exact-range"} {
		t.Run(kind, func(t *testing.T) {
			r := proto.CloneOf(base)
			r.ComponentVersion = ""
			switch kind {
			case "fixed":
				r.FixedVersion = version
			case "exact-range":
				r.IntroducedVersion = version
				r.LastAffectedVersion = version
			}
			if !exactRhelDeclaration(source, r, version, "x86_64", "src", "nodejs", "18") {
				t.Fatalf("exact product declaration rejected: %v", r)
			}
		})
	}
}

func TestRHELCoverageCacheIdentityKeepsDerivativeSemantics(t *testing.T) {
	packages, origins := []byte("packages"), []byte("origins")
	rhel := derivativeCoverage(platform.Identify(platform.OSRelease{ID: "rhel", VersionID: "9.8"}))
	if rhel == nil || !rhel.rpm || bytes.Equal(rhel.setDigest(packages, origins), packages) {
		t.Fatal("RHEL authority policy missing from finding-set identity")
	}
	osID, version := feedIdentity(rhel, "rhel", "9.8")
	if osID != "rhel" || version != "9.8" {
		t.Fatal("RHEL stream identity was rewritten")
	}
	mint := derivativeCoverage(platform.Identify(platform.OSRelease{ID: "linuxmint", VersionID: "22.3"}))
	if mint == nil || mint.rpm || bytes.Equal(mint.setDigest(packages, origins), rhel.setDigest(packages, origins)) {
		t.Fatal("derivative and RPM policies share authority")
	}
	osID, version = feedIdentity(mint, "linuxmint", "22.3")
	if osID != "ubuntu" || version != "24.04" {
		t.Fatal("APT derivative semantics changed")
	}
	if derivativeCoverage(platform.Identify(platform.OSRelease{ID: "ubuntu", VersionID: "24.04"})) != nil {
		t.Fatal("native Ubuntu was unnecessarily restricted")
	}
}

func TestRHELSourceEpochLowerBoundIsNotAnExactEpoch(t *testing.T) {
	sourceVR := "1.12.20-8.el9"
	for _, tc := range []struct {
		name, fixed, introduced, last string
		clear                         bool
	}{
		{"older-zero-epoch-fixed", "0:1.12.20-7.el9", "", "", true},
		{"equal-zero-epoch-fixed", "0:1.12.20-8.el9", "", "", true},
		{"newer-zero-epoch-fixed", "0:1.12.20-9.el9", "", "", false},
		{"higher-source-epoch-fixed", "1:1.0-1", "", "", false},
		{"introduced-requires-epoch", "0:1.12.20-7.el9", "1:1-1", "", false},
		{"last-affected-requires-epoch", "0:1.12.20-7.el9", "", "1:1-1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &advisoryv1.Advisory{SourcePackage: true, ComponentVersion: tc.fixed, FixedVersion: tc.fixed, IntroducedVersion: tc.introduced, LastAffectedVersion: tc.last}
			if !rhelSourceEpochRequired(r) {
				t.Fatal("source predicate silently obtained an exact epoch")
			}
			if got := rhelSourceFixedRangeCleared(sourceVR, r); got != tc.clear {
				t.Fatalf("minimum source epoch rule=%v want=%v", got, tc.clear)
			}
		})
	}
	for _, notAffected := range []bool{false, true} {
		r := &advisoryv1.Advisory{SourcePackage: true, NotAffected: notAffected}
		if rhelSourceEpochRequired(r) {
			t.Fatal("unversioned source status invented an EVR requirement")
		}
		r.ComponentVersion = "0:" + sourceVR
		if !rhelSourceEpochRequired(r) {
			t.Fatal("versioned source status inferred exact epoch zero")
		}
	}
}

func TestRHELSourceArchitectureUsesSignedSourceRole(t *testing.T) {
	source := &advisoryv1.FeedSource{Release: "9", PlatformStream: "standard"}
	record := &advisoryv1.Advisory{SourcePackage: true, Architecture: "src", PlatformRelease: "9", PlatformStream: "standard", ModuleName: "nodejs", ModuleStream: "18"}
	if !rhelCandidateScopeMatches(source, record, "x86_64", "src", "nodejs", "18") {
		t.Fatal("signed source role did not match")
	}
	if rhelCandidateScopeMatches(source, record, "x86_64", "nosrc", "nodejs", "18") {
		t.Fatal("different source architecture was inferred")
	}
	if rhelCandidateScopeMatches(source, record, "x86_64", "src", "nodejs", "20") {
		t.Fatal("different source module stream was inferred")
	}
}

func TestRHELBinaryNegativeMustApplyToInstalledEVR(t *testing.T) {
	for _, tc := range []struct {
		name, component, introduced, last string
		applies                           bool
	}{
		{"different-exact-negative", "0:3-1", "0:3-1", "0:3-1", false},
		{"installed-exact-negative", "0:2-1", "0:2-1", "0:2-1", true},
		{"different-component-without-range", "0:3-1", "", "", false},
		{"legacy-negative-range-misses", "", "0:3-1", "0:4-1", false},
		{"legacy-negative-range-applies", "", "0:1-1", "0:3-1", true},
		{"unversioned-negative", "", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := &advisoryv1.Advisory{NotAffected: true, ComponentVersion: tc.component, IntroducedVersion: tc.introduced, LastAffectedVersion: tc.last}
			if got := rhelBinaryAssessmentApplies("rpm", "0:2-1", record); got != tc.applies {
				t.Fatalf("binary negative applicability=%v want=%v", got, tc.applies)
			}
			if !record.NotAffected {
				t.Fatal("scope check mutated the original negative")
			}
		})
	}
}
