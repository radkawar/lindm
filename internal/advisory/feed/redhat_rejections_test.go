// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

func TestRedHatSinkCannotMasqueradeAsRejectedVendorRecord(t *testing.T) {
	source := redHatSource("9", "standard")
	stage, err := newRedHatStager(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stage.close(); err != nil {
			t.Error(err)
		}
	})
	vendor := &redHatRejectedRecordError{record: &advisoryv1.RejectedRecord{Id: "CVE-2024-12345", Reason: "simulated vendor-shaped sink failure", Unscoped: true}, cause: errors.New("sink failure")}
	sink := &redHatSinkError{cause: vendor}
	doc := new(advisoryv1.FeedDocument)
	err = acceptRedHatDocument(source, redHatValidator(t), stage, doc, func() error { return sink })
	if !errors.Is(err, sink) || len(doc.RejectedRecords) != 0 {
		t.Fatalf("sink suppressed as vendor rejection: err=%v metadata=%v", err, doc)
	}
}

func TestRedHatRejectedRecordThresholdFailsClosed(t *testing.T) {
	source := redHatSource("9", "standard")
	limit := uint32(0)
	source.MaxRejectedRecords = &limit
	stage, err := newRedHatStager(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stage.close(); err != nil {
			t.Error(err)
		}
	})
	vendor := &redHatRejectedRecordError{record: &advisoryv1.RejectedRecord{Id: "CVE-2024-12345", Reason: "invalid identity", Unscoped: true}, cause: errors.New("invalid identity")}
	doc := new(advisoryv1.FeedDocument)
	if err := acceptRedHatDocument(source, redHatValidator(t), stage, doc, func() error { return vendor }); err == nil || len(doc.RejectedRecords) != 0 {
		t.Fatalf("zero rejection threshold accepted vendor record: err=%v doc=%v", err, doc)
	}
}

func redHatRejectionSpecimen(t *testing.T) suseCSAF {
	t.Helper()
	var notice suseCSAF
	if err := json.Unmarshal(redHatFixture(t, "rhsa-2024_6783"), &notice); err != nil {
		t.Fatal(err)
	}
	notice.Tree.Branches = []suseBranch{{Category: "vendor", Name: "Red Hat"}}
	notice.Tree.Relationships = nil
	notice.Vulnerabilities = notice.Vulnerabilities[:1]
	notice.Vulnerabilities[0].Status = nil
	notice.Vulnerabilities[0].Remediations = nil
	redHatAppendTestPlatform(&notice, "rhel9", "cpe:/o:redhat:enterprise_linux:9")
	redHatAppendTestPlatform(&notice, "rhel8", "cpe:/o:redhat:enterprise_linux:8")
	return notice
}

func redHatRejectionTestPackage(notice *suseCSAF, id, purl, platform string) string {
	product := suseProduct{ID: id, Name: "opaque display name"}
	product.Helper.PURL = purl
	notice.Tree.Branches[0].Branches = append(notice.Tree.Branches[0].Branches, suseBranch{Category: "product_version", Name: "opaque branch", Product: &product})
	edge := id + "-edge"
	notice.Tree.Relationships = append(notice.Tree.Relationships, suseRelationship{Category: "default_component_of", Component: id, Platform: platform, Product: suseProduct{ID: edge, Name: "opaque relationship"}})
	return edge
}

func TestRedHatRejectionIncludesEveryVulnerabilityNotJustOffendingNames(t *testing.T) {
	notice := redHatRejectionSpecimen(t)
	before := redHatRejectionTestPackage(&notice, "before", "pkg:rpm/redhat/prefix?arch=src", "rhel9")
	broken := redHatRejectionTestPackage(&notice, "broken", "pkg:rpm/redhat/broken@invalid?arch=src", "rhel9")
	after := redHatRejectionTestPackage(&notice, "after", "pkg:rpm/redhat/suffix?arch=src", "rhel9")
	offstream := redHatRejectionTestPackage(&notice, "offstream", "pkg:rpm/redhat/unbounded:module?arch=src", "rhel8")
	first := notice.Vulnerabilities[0]
	notice.Vulnerabilities = append(notice.Vulnerabilities, first, first)
	notice.Vulnerabilities[0].Status = map[string][]string{"known_affected": {before}}
	notice.Vulnerabilities[1].Status = map[string][]string{"known_affected": {broken}}
	notice.Vulnerabilities[2].Status = map[string][]string{"known_not_affected": {after, offstream}}
	raw, err := json.Marshal(notice)
	if err != nil {
		t.Fatal(err)
	}
	var claims []*advisoryv1.Advisory
	doc, err := stageRedHatStream(t.Context(), redHatSource("9.8", "standard"), redHatValidator(t), bytes.NewReader(raw), func(record *advisoryv1.Advisory) error {
		claims = append(claims, record)
		return nil
	})
	if err != nil || doc == nil || len(doc.RejectedRecords) != 1 {
		t.Fatalf("rejection missing: doc=%v err=%v", doc, err)
	}
	rejected := doc.RejectedRecords[0]
	if rejected.Unscoped || !slices.Equal(rejected.PackageNames, []string{"broken", "prefix", "suffix"}) || len(claims) != 6 {
		t.Fatalf("document-wide quarantine scope changed: rejection=%v claims=%v", rejected, claims)
	}
	for _, claim := range claims {
		if !claim.SourceRecordRejected || !claim.AssessmentUnknown || claim.NotAffected || claim.FixedVersion != "" || len(claim.Cves) != 0 {
			t.Fatalf("valid-prefix or valid-suffix assertion escaped rejected document: %v", claim)
		}
	}
}

func TestRedHatRejectedModuleNeedsIndependentNativeSourceFamily(t *testing.T) {
	for _, test := range []struct {
		name, source, binary, marker string
		unscoped                     bool
	}{
		{"declared-family-all-streams", "pkg:rpm/redhat/nginx?arch=src&rpmmod=nginx:1.22", "pkg:rpm/redhat/nginx-core?rpmmod=nginx:1.26", "pkg:rpm/redhat/nginx:1.24?arch=src", false},
		{"no-module-declaration", "pkg:rpm/redhat/nginx?arch=src", "pkg:rpm/redhat/nginx-core", "pkg:rpm/redhat/nginx:1.24?arch=src", true},
		{"other-source-name", "pkg:rpm/redhat/other?arch=src&rpmmod=nginx:1.22", "pkg:rpm/redhat/nginx-core?rpmmod=nginx:1.26", "pkg:rpm/redhat/nginx:1.24?arch=src", true},
		{"ambiguous-module-marker", "pkg:rpm/redhat/nginx?arch=src&rpmmod=nginx:1.22", "pkg:rpm/redhat/nginx-core?rpmmod=nginx:1.26", "pkg:rpm/redhat/nginx:1.24:extra?arch=src", true},
		{"ambiguous-rpm-name", "pkg:rpm/redhat/nginx?arch=src&rpmmod=nginx:1.22", "pkg:rpm/redhat/nginx-core?rpmmod=nginx:1.26", "pkg:rpm/redhat/nginx%2fother:1.24?arch=src", true},
		{"ambiguous-qualifier", "pkg:rpm/redhat/nginx?arch=src&rpmmod=nginx:1.22", "pkg:rpm/redhat/nginx-core?rpmmod=nginx:1.26", "pkg:rpm/redhat/nginx:1.24?arch=src&arch=src", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			notice := redHatRejectionSpecimen(t)
			redHatRejectionTestPackage(&notice, "source", test.source, "rhel9")
			redHatRejectionTestPackage(&notice, "binary", test.binary, "rhel9")
			bad := redHatRejectionTestPackage(&notice, "marker", test.marker, "rhel9")
			redHatRejectionTestPackage(&notice, "unrelated", "pkg:rpm/redhat/bash?arch=src", "rhel9")
			notice.Vulnerabilities[0].Status = map[string][]string{"known_affected": {bad}}
			raw, err := json.Marshal(notice)
			if err != nil {
				t.Fatal(err)
			}
			doc, err := parseRedHat(redHatSource("9.8", "standard"), raw, redHatValidator(t))
			if err != nil || doc == nil || len(doc.RejectedRecords) != 1 {
				t.Fatalf("malformed marker escaped rejection: doc=%v err=%v", doc, err)
			}
			rejected := doc.RejectedRecords[0]
			if rejected.Unscoped != test.unscoped || slices.Contains(rejected.PackageNames, "bash") {
				t.Fatalf("unsupported family proof: %v", rejected)
			}
			if !test.unscoped && !slices.Equal(rejected.PackageNames, []string{"nginx", "nginx-core"}) {
				t.Fatalf("family's independent source/binary names omitted: %v", rejected)
			}
			for _, claim := range doc.Advisories {
				if !claim.SourceRecordRejected || !claim.AssessmentUnknown || claim.ModuleName != "" || claim.ModuleStream != "" {
					t.Fatalf("module marker became an RPM claim: %v", claim)
				}
			}
		})
	}
}

func TestRedHatUnknownAndAmbiguousRejectionScopeStaysUnscoped(t *testing.T) {
	for _, kind := range []string{"unknown-reference", "unknown-platform", "ambiguous-component", "ambiguous-relationship", "invalid-module", "conflicting-module"} {
		t.Run(kind, func(t *testing.T) {
			notice := redHatRejectionSpecimen(t)
			edge := redHatRejectionTestPackage(&notice, "component", "pkg:rpm/redhat/bounded?arch=src", "rhel9")
			switch kind {
			case "unknown-reference":
				edge = "undeclared"
			case "unknown-platform":
				notice.Tree.Relationships[0].Platform = "undeclared"
			case "ambiguous-component":
				redHatRejectionTestPackage(&notice, "component", "pkg:rpm/redhat/other?arch=src", "rhel9")
			case "ambiguous-relationship":
				other := redHatRejectionTestPackage(&notice, "other", "pkg:rpm/redhat/other?arch=src", "rhel9")
				notice.Tree.Relationships[len(notice.Tree.Relationships)-1].Product.ID = edge
				if other == edge {
					t.Fatal("fixture relationship IDs unexpectedly collide")
				}
			case "invalid-module":
				notice.Tree.Branches[0].Branches[2].Product.Helper.PURL += "&rpmmod=ambiguous"
			case "conflicting-module":
				notice.Tree.Branches[0].Branches[2].Product.Helper.PURL += "&rpmmod=bounded:1"
				module := suseProduct{ID: "bounded:2", Name: "opaque module"}
				notice.Tree.Branches[0].Branches = append(notice.Tree.Branches[0].Branches, suseBranch{Category: "product_version", Name: "module", Product: &module})
				notice.Tree.Relationships[0].Platform = "module-edge"
				notice.Tree.Relationships = append(notice.Tree.Relationships, suseRelationship{Category: "default_component_of", Component: module.ID, Platform: "rhel9", Product: suseProduct{ID: "module-edge", Name: "module edge"}})
			}
			notice.Vulnerabilities[0].Status = map[string][]string{"known_affected": {edge}}
			raw, err := json.Marshal(notice)
			if err != nil {
				t.Fatal(err)
			}
			doc, err := parseRedHat(redHatSource("9.8", "standard"), raw, redHatValidator(t))
			if err != nil || doc == nil || len(doc.RejectedRecords) != 1 || !doc.RejectedRecords[0].Unscoped {
				t.Fatalf("uncertain scope established clean coverage: doc=%v err=%v", doc, err)
			}
		})
	}
}

func TestRedHatRejectedNameBoundNeverImpliesExhaustiveScope(t *testing.T) {
	record := new(advisoryv1.RejectedRecord)
	for i := 4095; i >= 0; i-- {
		redHatRejectedPackageName(record, fmt.Sprintf("package-%04d", i))
	}
	if record.Unscoped || len(record.PackageNames) != 4096 {
		t.Fatalf("bounded exhaustive names needlessly lost scope: %v", record)
	}
	redHatRejectedPackageName(record, "package-4096")
	if !record.Unscoped || len(record.PackageNames) != 4096 || record.PackageNames[0] != "package-0000" || record.PackageNames[4095] != "package-4095" {
		t.Fatalf("name bound hid omitted components: %v", record)
	}
}

func TestRedHatRejectedMetadataByteBoundRemainsSourceFailure(t *testing.T) {
	source := redHatSource("9", "standard")
	stage, err := newRedHatStager(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stage.close(); err != nil {
			t.Error(err)
		}
	})
	record := &advisoryv1.RejectedRecord{Id: "CVE-2024-12345", Reason: "invalid identity"}
	for i := range 4096 {
		redHatRejectedPackageName(record, fmt.Sprintf("long-component-name-%04d", i))
	}
	vendor := &redHatRejectedRecordError{record: record, cause: errors.New("invalid identity")}
	doc := new(advisoryv1.FeedDocument)
	if err := acceptRedHatDocument(source, redHatValidator(t), stage, doc, func() error { return vendor }); err == nil || len(doc.RejectedRecords) != 0 {
		t.Fatalf("oversized metadata was silently truncated or accepted: err=%v doc=%v", err, doc)
	}
}

func redHatRequireOnlyQuarantine(t *testing.T, rejected *advisoryv1.RejectedRecord, claims []*advisoryv1.Advisory) {
	t.Helper()
	if len(claims) != 2*len(rejected.PackageNames) {
		t.Fatalf("native/source quarantine incomplete: claims=%d names=%d", len(claims), len(rejected.PackageNames))
	}
	type identity struct {
		name   string
		source bool
	}
	seen := make(map[identity]bool)
	for _, claim := range claims {
		key := identity{claim.PackageName, claim.SourcePackage}
		if seen[key] || !slices.Contains(rejected.PackageNames, claim.PackageName) || !claim.SourceRecordRejected || !claim.AssessmentUnknown || claim.NotAffected || len(claim.Cves) != 0 || claim.ModuleName != "" || claim.ModuleStream != "" || claim.Architecture != "" || claim.FixedVersion != "" || claim.IntroducedVersion != "" || claim.LastAffectedVersion != "" {
			t.Fatalf("rejected document retained a claim or invented identity: %v", claim)
		}
		seen[key] = true
	}
}

func TestRedHatModuleFamilyQuarantineRequiresExhaustiveGraphAuthority(t *testing.T) {
	family := func(t *testing.T) suseCSAF {
		t.Helper()
		notice := redHatRejectionSpecimen(t)
		redHatRejectionTestPackage(&notice, "source", "pkg:rpm/redhat/nginx?arch=src&rpmmod=nginx:1.22", "rhel9")
		marker := redHatRejectionTestPackage(&notice, "marker", "pkg:rpm/redhat/nginx:1.24?arch=src", "rhel9")
		notice.Vulnerabilities[0].Status = map[string][]string{"known_affected": {marker}}
		return notice
	}
	check := func(t *testing.T, notice suseCSAF, unscoped bool) *advisoryv1.RejectedRecord {
		t.Helper()
		raw, err := json.Marshal(notice)
		if err != nil {
			t.Fatal(err)
		}
		var claims []*advisoryv1.Advisory
		doc, err := stageRedHatStream(t.Context(), redHatSource("9.8", "standard"), redHatValidator(t), bytes.NewReader(raw), func(record *advisoryv1.Advisory) error {
			claims = append(claims, record)
			return nil
		})
		if err != nil || doc == nil || len(doc.RejectedRecords) != 1 || doc.RejectedRecords[0].Unscoped != unscoped {
			t.Fatalf("incomplete graph established bounded quarantine: doc=%v err=%v wantUnscoped=%t", doc, err, unscoped)
		}
		redHatRequireOnlyQuarantine(t, doc.RejectedRecords[0], claims)
		return doc.RejectedRecords[0]
	}
	for _, stream := range []string{"1.24", "1.26"} {
		for _, moduleID := range []string{"", "nginx:" + stream, "httpd:2.4", "invalid-module"} {
			t.Run("same-family-marker-"+stream+"-"+moduleID, func(t *testing.T) {
				notice := family(t)
				alias := redHatRejectionTestPackage(&notice, "different-opaque-marker", "pkg:rpm/redhat/nginx:"+stream+"?arch=src", "rhel9")
				notice.Vulnerabilities[0].Status["known_affected"] = append(notice.Vulnerabilities[0].Status["known_affected"], alias)
				if moduleID != "" {
					module := suseProduct{ID: moduleID, Name: "opaque module"}
					notice.Tree.Branches[0].Branches = append(notice.Tree.Branches[0].Branches, suseBranch{Category: "product_version", Name: "module", Product: &module})
					notice.Tree.Relationships[len(notice.Tree.Relationships)-1].Platform = "alias-module-edge"
					notice.Tree.Relationships = append(notice.Tree.Relationships, suseRelationship{Category: "default_component_of", Component: module.ID, Platform: "rhel9", Product: suseProduct{ID: "alias-module-edge", Name: "module edge"}})
				}
				rejected := check(t, notice, moduleID != "" && moduleID != "nginx:"+stream)
				if !rejected.Unscoped && !slices.Equal(rejected.PackageNames, []string{"nginx"}) {
					t.Fatalf("same-family markers lost their shared independent family proof: %v", rejected)
				}
			})
		}
	}
	for _, referenced := range []bool{false, true} {
		for _, proved := range []bool{false, true} {
			t.Run(fmt.Sprintf("other-family-referenced-%t-proved-%t", referenced, proved), func(t *testing.T) {
				notice := family(t)
				other := redHatRejectionTestPackage(&notice, "other-family-marker", "pkg:rpm/redhat/httpd:2.6?arch=src", "rhel9")
				if proved {
					redHatRejectionTestPackage(&notice, "other-family-source", "pkg:rpm/redhat/httpd?arch=src&rpmmod=httpd:2.4", "rhel9")
				}
				if referenced {
					notice.Vulnerabilities[0].Status["known_affected"] = append(notice.Vulnerabilities[0].Status["known_affected"], other)
				}
				rejected := check(t, notice, referenced && !proved)
				if referenced && proved && !slices.Equal(rejected.PackageNames, []string{"httpd", "nginx"}) {
					t.Fatalf("independent families did not retain their separate quarantine names: %v", rejected)
				}
				if !referenced && !slices.Equal(rejected.PackageNames, []string{"nginx"}) {
					t.Fatalf("unreferenced different-family marker poisoned selected scope: %v", rejected)
				}
			})
		}
	}
	for _, test := range []struct {
		module   string
		unscoped bool
	}{
		{"nginx:1.24", false},
		{"httpd:2.4", true},
		{"nginx:1.26", true},
		{"invalid-module", true},
	} {
		t.Run("enclosing-"+test.module, func(t *testing.T) {
			notice := family(t)
			module := suseProduct{ID: test.module, Name: "opaque module"}
			notice.Tree.Branches[0].Branches = append(notice.Tree.Branches[0].Branches, suseBranch{Category: "product_version", Name: "module", Product: &module})
			notice.Tree.Relationships[1].Platform = "enclosing-module-edge"
			notice.Tree.Relationships = append(notice.Tree.Relationships, suseRelationship{Category: "default_component_of", Component: module.ID, Platform: "rhel9", Product: suseProduct{ID: "enclosing-module-edge", Name: "module edge"}})
			check(t, notice, test.unscoped)
		})
	}
	// Neither declaration order may hide an alternative family member.
	// Explicit off-stream alternatives, however, remain irrelevant.
	for _, kind := range []string{"component", "relationship"} {
		for _, reverse := range []bool{false, true} {
			for _, platform := range []string{"rhel9", "rhel8"} {
				t.Run(fmt.Sprintf("ambiguous-%s-reverse-%t-%s", kind, reverse, platform), func(t *testing.T) {
					notice := family(t)
					purls := []string{"pkg:rpm/redhat/unrelated", "pkg:rpm/redhat/nginx-addon?rpmmod=nginx:1.26"}
					if reverse {
						slices.Reverse(purls)
					}
					first := redHatRejectionTestPackage(&notice, "candidate", purls[0], platform)
					if kind == "component" {
						redHatRejectionTestPackage(&notice, "candidate", purls[1], platform)
					} else {
						redHatRejectionTestPackage(&notice, "alternative", purls[1], platform)
						notice.Tree.Relationships[len(notice.Tree.Relationships)-1].Product.ID = first
					}
					check(t, notice, platform == "rhel9")
				})
			}
		}
	}
	for _, test := range []struct {
		name, purl string
		unscoped   bool
	}{
		{"malformed-evr", "pkg:rpm/redhat/nginx-addon@invalid?arch=x86_64&rpmmod=nginx:1.26", false},
		{"malformed-name", "pkg:rpm/redhat/nginx-addon%2Fhidden@invalid?arch=x86_64&rpmmod=nginx:1.26", true},
		{"malformed-module", "pkg:rpm/redhat/nginx-addon@invalid?arch=x86_64&rpmmod=nginx", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			notice := family(t)
			// The status names only the marker. This independent declaration
			// must not disappear from family enumeration on an EVR error.
			redHatRejectionTestPackage(&notice, "addon", test.purl, "rhel9")
			rejected := check(t, notice, test.unscoped)
			if !test.unscoped && !slices.Contains(rejected.PackageNames, "nginx-addon") {
				t.Fatalf("malformed family member's authoritative native name omitted: %v", rejected)
			}
		})
	}
}
