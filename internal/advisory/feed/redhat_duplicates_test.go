// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

func redHatDuplicateX86Product(t *testing.T, notice *suseCSAF, mutate func(*suseProduct)) {
	t.Helper()
	for index := range notice.Tree.Branches[0].Branches {
		branch := &notice.Tree.Branches[0].Branches[index]
		if branch.Category != "architecture" || branch.Name != "x86_64" {
			continue
		}
		if len(branch.Branches) == 0 || branch.Branches[0].Product == nil {
			t.Fatal("missing native fixture product")
		}
		duplicate := branch.Branches[0]
		product := *duplicate.Product
		mutate(&product)
		duplicate.Product = &product
		duplicate.Name = "opaque duplicate display label"
		branch.Branches = append(branch.Branches, duplicate)
		return
	}
	t.Fatal("missing native fixture architecture")
}

func redHatAppendTestPlatform(notice *suseCSAF, id, cpe string) {
	product := suseProduct{ID: id, Name: id}
	product.Helper.CPE = cpe
	notice.Tree.Branches[0].Branches = append(notice.Tree.Branches[0].Branches, suseBranch{Category: "product_name", Name: id, Product: &product})
}

func TestRedHatIdenticalDeclarationsAndUnusedAmbiguityPreserveClaims(t *testing.T) {
	validator := redHatValidator(t)
	config := redHatSource("9.4", "standard")
	raw := redHatFixture(t, "rhsa-2024_6783")
	baseline, err := parseRedHat(config, raw, validator)
	if err != nil {
		t.Fatal(err)
	}
	want := redHatSemanticClaims(t, baseline.Advisories)
	for _, test := range []struct {
		name   string
		mutate func(*suseCSAF)
	}{
		{"identical-relationships", func(notice *suseCSAF) {
			notice.Tree.Relationships = append(notice.Tree.Relationships, notice.Tree.Relationships...)
		}},
		{"opaque-relationship-label", func(notice *suseCSAF) {
			duplicate := notice.Tree.Relationships[0]
			duplicate.Product.Name = "opaque duplicate display label"
			notice.Tree.Relationships = append(notice.Tree.Relationships, duplicate)
		}},
		{"identical-products", func(notice *suseCSAF) {
			root := &notice.Tree.Branches[0]
			root.Branches = append(root.Branches, root.Branches...)
		}},
		{"opaque-product-label", func(notice *suseCSAF) {
			redHatDuplicateX86Product(t, notice, func(product *suseProduct) { product.Name = "opaque product label" })
		}},
		{"unused-conflicting-relationship", func(notice *suseCSAF) {
			first := notice.Tree.Relationships[0]
			first.Product.ID = "unused-ambiguous-relationship"
			second := first
			second.Component = "missing-component"
			notice.Tree.Relationships = append(notice.Tree.Relationships, first, second)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var notice suseCSAF
			if err := json.Unmarshal(raw, &notice); err != nil {
				t.Fatal(err)
			}
			test.mutate(&notice)
			changed, err := json.Marshal(notice)
			if err != nil {
				t.Fatal(err)
			}
			doc, err := parseRedHat(config, changed, validator)
			if err != nil || doc == nil || len(doc.RejectedRecords) != 0 {
				t.Fatalf("irrelevant redeclaration poisoned native source: %v, %v", doc, err)
			}
			if got := redHatSemanticClaims(t, doc.Advisories); !slices.Equal(got, want) {
				t.Fatalf("redeclaration changed native claims: got %v, want %v", got, want)
			}
		})
	}
}

func TestRedHatConflictingRelationshipRequiresAllAlternativesOffScope(t *testing.T) {
	validator := redHatValidator(t)
	config := redHatSource("9.4", "standard")
	raw := redHatFixture(t, "rhsa-2024_6783")
	baseline, err := parseRedHat(config, raw, validator)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, first, second string
		reject              bool
	}{
		{"same-foreign-platform", "foreign-eight", "foreign-eight", false},
		{"both-foreign-platforms", "foreign-eight", "foreign-seven", false},
		{"foreign-then-native", "foreign-eight", "native", true},
		{"native-then-foreign", "native", "foreign-eight", true},
		{"unknown-alternative", "foreign-eight", "undeclared", true},
		{"cyclic-alternative", "foreign-eight", "ambiguous-edge", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var notice suseCSAF
			if err := json.Unmarshal(raw, &notice); err != nil {
				t.Fatal(err)
			}
			redHatAppendTestPlatform(&notice, "foreign-eight", "cpe:/o:redhat:enterprise_linux:8")
			redHatAppendTestPlatform(&notice, "foreign-seven", "cpe:/o:redhat:enterprise_linux:7")
			redHatAppendTestPlatform(&notice, "native", "cpe:/o:redhat:enterprise_linux:9")
			first := notice.Tree.Relationships[0]
			first.Product.ID, first.Platform = "ambiguous-edge", test.first
			second := first
			second.Platform, second.Component = test.second, "conflicting-component"
			notice.Tree.Relationships = append(notice.Tree.Relationships, first, second)
			notice.Vulnerabilities[0].Status["known_affected"] = append(notice.Vulnerabilities[0].Status["known_affected"], first.Product.ID)
			changed, err := json.Marshal(notice)
			if err != nil {
				t.Fatal(err)
			}
			var claims []*advisoryv1.Advisory
			doc, err := stageRedHatStream(t.Context(), config, validator, bytes.NewReader(changed), func(record *advisoryv1.Advisory) error {
				claims = append(claims, record)
				return nil
			})
			if err != nil || doc == nil {
				t.Fatalf("vendor semantic classification failed: %v, %v", doc, err)
			}
			if test.reject {
				if len(doc.RejectedRecords) != 1 || !doc.RejectedRecords[0].Unscoped {
					t.Fatalf("ambiguous native dependency retained claims: claims=%v metadata=%v", claims, doc)
				}
				redHatRequireOnlyQuarantine(t, doc.RejectedRecords[0], claims)
			} else if len(doc.RejectedRecords) != 0 || !slices.Equal(redHatSemanticClaims(t, claims), redHatSemanticClaims(t, baseline.Advisories)) {
				t.Fatalf("proven foreign ambiguity poisoned native claims: claims=%v metadata=%v", claims, doc)
			}
		})
	}
}

func TestRedHatPotentialScopeIncludesEveryAmbiguousPlatformCPE(t *testing.T) {
	validator := redHatValidator(t)
	for _, firstRelease := range []string{"8", "9"} {
		t.Run("first-release-"+firstRelease, func(t *testing.T) {
			var notice suseCSAF
			if err := json.Unmarshal(redHatFixture(t, "rhsa-2024_6783"), &notice); err != nil {
				t.Fatal(err)
			}
			notice.Tree.Branches = []suseBranch{{Category: "vendor", Name: "Red Hat"}}
			secondRelease := "9"
			if firstRelease == "9" {
				secondRelease = "8"
			}
			redHatAppendTestPlatform(&notice, "ambiguous-platform", "cpe:/o:redhat:enterprise_linux:"+firstRelease)
			redHatAppendTestPlatform(&notice, "ambiguous-platform", "cpe:/o:redhat:enterprise_linux:"+secondRelease)
			component := suseProduct{ID: "native-component", Name: "opaque component label"}
			component.Helper.PURL = "pkg:rpm/redhat/openssl@3.0.7-28.el9_4?arch=x86_64&epoch=1"
			notice.Tree.Branches[0].Branches = append(notice.Tree.Branches[0].Branches, suseBranch{Category: "product_version", Name: component.Name, Product: &component})
			relation := suseRelationship{Category: "default_component_of", Component: component.ID, Platform: "ambiguous-platform", Product: suseProduct{ID: "native-edge", Name: "opaque edge label"}}
			notice.Tree.Relationships = []suseRelationship{relation}
			notice.Vulnerabilities[0].Status = map[string][]string{"fixed": {relation.Product.ID}}
			changed, err := json.Marshal(notice)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			doc, err := stageRedHatStream(t.Context(), redHatSource("9.4", "standard"), validator, bytes.NewReader(changed), func(*advisoryv1.Advisory) error { calls++; return nil })
			if err != nil || doc == nil || calls != 0 || len(doc.RejectedRecords) != 1 || !doc.RejectedRecords[0].Unscoped {
				t.Fatalf("first/last declaration hid native platform ambiguity: metadata=%v calls=%d err=%v", doc, calls, err)
			}
		})
	}
}

func TestRedHatOffScopeProofMemoPreservesTraversalBound(t *testing.T) {
	config := redHatSource("9.4", "standard")
	foreign := redHatProduct{}
	foreign.product.Helper.CPE = "cpe:/o:redhat:enterprise_linux:8"
	products := map[string]redHatProduct{"foreign": foreign}
	relations := make(map[string]redHatRelationship)
	ids := [...]string{"a", "b", "c", "d", "e", "f", "g", "h"}
	for index, id := range ids {
		next := "foreign"
		if index+1 < len(ids) {
			next = ids[index+1]
		}
		relations[id] = redHatRelationship{suseRelationship: suseRelationship{Category: "default_component_of", Platform: next}}
	}
	var memo map[string]redHatScopeProof
	if !redHatReferenceOffScope(config, ids[0], products, relations, 0, &memo) {
		t.Fatal("eight-edge foreign dependency was not proven off-scope")
	}
	if len(memo) > len(products)+len(relations) {
		t.Fatal("scope proof retained more entries than the bounded product index")
	}
	if redHatReferenceOffScope(config, ids[0], products, relations, 1, &memo) {
		t.Fatal("cached proof bypassed the eight-edge traversal bound")
	}
	if !redHatReferenceOffScope(config, ids[0], products, relations, 0, &memo) {
		t.Fatal("deeper traversal changed an independently bounded scope proof")
	}
	relations["cycle"] = redHatRelationship{suseRelationship: suseRelationship{Platform: "cycle"}}
	if redHatReferenceOffScope(config, "cycle", products, relations, 0, &memo) {
		t.Fatal("cyclic alternatives proved off-scope")
	}
}
