// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"testing"

	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

func TestPublishedBoundaryUsesOnlySamePackageVendorVersions(t *testing.T) {
	// Unit inputs exercise selection only, not a live feed qualification.
	target := &advisoryv1.Advisory{Id: "newer", PackageName: "package", Architecture: "x86_64", FixedVersion: "2:3-1"}
	older := &advisoryv1.Advisory{Id: "older", PackageName: "package", Architecture: "x86_64", FixedVersion: "1:9-9"}
	boundary := publishedBoundaryPair("rpm", target, older)
	if boundary == nil || boundary.VulnerableVersion != older.GetFixedVersion() || boundary.Claim != target || boundary.ComparisonClaim != older || boundary.VersionOrigin != "comparison_claim.fixed_version" {
		t.Fatalf("lost vendor version provenance: %+v", boundary)
	}
	for name, mutate := range map[string]func(*advisoryv1.Advisory){
		"different package":      func(a *advisoryv1.Advisory) { a.PackageName = "other" },
		"different architecture": func(a *advisoryv1.Advisory) { a.Architecture = "aarch64" },
		"different namespace":    func(a *advisoryv1.Advisory) { a.SourcePackage = true },
		"unknown assessment":     func(a *advisoryv1.Advisory) { a.AssessmentUnknown = true },
		"rejected record":        func(a *advisoryv1.Advisory) { a.SourceRecordRejected = true },
		"not affected":           func(a *advisoryv1.Advisory) { a.NotAffected = true },
		"equal fix":              func(a *advisoryv1.Advisory) { a.FixedVersion = target.GetFixedVersion() },
		"newer fix":              func(a *advisoryv1.Advisory) { a.FixedVersion = "3:1-1" },
	} {
		t.Run(name, func(t *testing.T) {
			other := proto.CloneOf(older)
			mutate(other)
			if publishedBoundaryPair("rpm", target, other) != nil {
				t.Fatal("unrelated or non-vulnerable version became a positive oracle")
			}
		})
	}
	target.IntroducedVersion = "2:1-1"
	if publishedBoundaryPair("rpm", target, older) != nil {
		t.Fatal("version before the vendor's introduced boundary became affected")
	}
}
