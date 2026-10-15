// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

func TestRedHatDiskReconciliationMatchesNativeRules(t *testing.T) {
	base := &advisoryv1.Advisory{Id: "RHSA-test", Cves: []string{"CVE-2024-12345"}, PackageName: "kernel", Architecture: "x86_64", PlatformRelease: "9", PlatformStream: "standard", SourceUrl: "https://vendor.example/advisory"}
	variant := func(fixed, arch string, unknown, source bool) *advisoryv1.Advisory {
		r := proto.CloneOf(base)
		r.FixedVersion = fixed
		r.Architecture = arch
		r.AssessmentUnknown = unknown
		r.SourcePackage = source
		return r
	}
	claims := []*advisoryv1.Advisory{
		variant("", "x86_64", false, false), variant("0:2-1", "x86_64", false, false), variant("0:1-1", "x86_64", false, false), variant("0:1-1", "x86_64", false, false), variant("", "aarch64", false, false), variant("", "", true, false), variant("", "x86_64", false, true),
	}
	for range 501 {
		claims = append(claims, variant("0:3-1", "x86_64", false, false))
	}
	exact := variant("", "x86_64", false, false)
	exact.IntroducedVersion = "0:0-1"
	exact.LastAffectedVersion = "0:0-1"
	claims = append(claims, exact)
	notAffected := variant("", "x86_64", false, false)
	notAffected.NotAffected = true
	claims = append(claims, notAffected)
	expected := &advisoryv1.FeedDocument{Advisories: append([]*advisoryv1.Advisory(nil), claims...)}
	redHatReconcile(expected)
	stage, err := newRedHatStager(t.Context(), redHatSource("9", "standard"))
	if err != nil {
		t.Fatal(err)
	}
	directory := stage.directory
	for _, claim := range claims {
		if err := stage.add(claim); err != nil {
			t.Fatal(err)
		}
	}
	var actual []*advisoryv1.Advisory
	if err := stage.emit(t.Context(), func(record *advisoryv1.Advisory) error { actual = append(actual, record); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(actual) != len(expected.Advisories) {
		t.Fatalf("kept %d expected%d", len(actual), len(expected.Advisories))
	}
	for i, record := range actual {
		if !proto.Equal(record, expected.Advisories[i]) {
			t.Fatalf("reconciliation mismatch at%d: %v != %v", i, record, expected.Advisories[i])
		}
	}
	if err := stage.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging directory retained: %v", err)
	}
}

func TestRedHatParsedSourceArchitecturesReconcileIndependently(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		name := "nosrc-first"
		if reverse {
			name = "src-first"
		}
		t.Run(name, func(t *testing.T) {
			notice := redHatRejectionSpecimen(t)
			src := redHatRejectionTestPackage(&notice, "source", "pkg:rpm/redhat/pkg@3-1?arch=src", "rhel9")
			nosrc := redHatRejectionTestPackage(&notice, "no-source", "pkg:rpm/redhat/pkg@1-1?arch=nosrc", "rhel9")
			fixed := []string{nosrc, src}
			if reverse {
				slices.Reverse(fixed)
			}
			notice.Vulnerabilities[0].Status = map[string][]string{"fixed": fixed}
			raw, err := json.Marshal(notice)
			if err != nil {
				t.Fatal(err)
			}
			var claims []*advisoryv1.Advisory
			doc, err := stageRedHatStream(t.Context(), redHatSource("9.8", "standard"), redHatValidator(t), bytes.NewReader(raw), func(record *advisoryv1.Advisory) error {
				claims = append(claims, record)
				return nil
			})
			if err != nil || len(doc.GetRejectedRecords()) != 0 || len(claims) != 2 {
				t.Fatalf("source roles merged before matching: claims=%v metadata=%v err=%v", claims, doc, err)
			}
			want := map[string]string{"src": "0:3-1", "nosrc": "0:1-1"}
			for _, record := range claims {
				if !record.SourcePackage || record.FixedVersion != want[record.Architecture] || record.ComponentVersion != record.FixedVersion {
					t.Fatalf("source role or independent fix erased: %v", record)
				}
				delete(want, record.Architecture)
			}
			if len(want) != 0 {
				t.Fatalf("source roles lost: %v", want)
			}
		})
	}
}

func TestRedHatRejectedDocumentRollsBackWinningFixAndBatchPrefix(t *testing.T) {
	stage, err := newRedHatStager(t.Context(), redHatSource("9", "standard"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stage.close(); err != nil {
			t.Error(err)
		}
	})
	prior := &advisoryv1.Advisory{Id: "RHSA-prior", Cves: []string{"CVE-2024-12345"}, PackageName: "kernel", FixedVersion: "0:3-1"}
	if err := stage.add(prior); err != nil {
		t.Fatal(err)
	}
	rejected := errors.New("rejected document")
	if err := stage.documentClaims(func() error {
		for range 501 {
			claim := proto.CloneOf(prior)
			claim.Id = "RHSA-rejected"
			claim.FixedVersion = "0:1-1"
			if err := stage.add(claim); err != nil {
				return err
			}
		}
		return rejected
	}); !errors.Is(err, rejected) {
		t.Fatalf("document rejection: %v", err)
	}
	if stage.count != 1 {
		t.Fatalf("rejected prefix retained: %d", stage.count)
	}
	var retained []*advisoryv1.Advisory
	if err := stage.emit(t.Context(), func(record *advisoryv1.Advisory) error {
		retained = append(retained, record)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(retained) != 1 || !proto.Equal(retained[0], prior) {
		t.Fatalf("rejected document changed winning native fix: %v", retained)
	}
}

func TestRedHatDiskReconciliationBudgetAndConsumerFailure(t *testing.T) {
	config := redHatSource("9", "standard")
	config.TotalClaimsLimit = proto.Uint64(1)
	stage, err := newRedHatStager(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := stage.close(); err != nil {
			t.Error(err)
		}
	}()
	record := &advisoryv1.Advisory{Id: "RHSA-test", Cves: []string{"CVE-2024-12345"}, PackageName: "kernel", FixedVersion: "0:1-1", Architecture: "x86_64"}
	if err := stage.add(record); err != nil {
		t.Fatal(err)
	}
	if err := stage.add(record); err == nil {
		t.Fatal("claim cap bypassed")
	}
	failure := errors.New("consumer failed")
	if err := stage.emit(t.Context(), func(*advisoryv1.Advisory) error { return failure }); !errors.Is(err, failure) {
		t.Fatalf("consumer error=%v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := stage.emit(ctx, func(*advisoryv1.Advisory) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation=%v", err)
	}
}

// Reconcile the same CVE/package/module and selected product before publishing.
// Keep the earliest fixed EVR, not later rebuilds which would falsely label an
// already backported build vulnerable. Binary and source evidence stay separate.
func redHatReconcile(doc *advisoryv1.FeedDocument) {
	type key struct {
		cve, name, module, stream, release, platform string
		source                                       bool
	}
	identity := func(r *advisoryv1.Advisory) key {
		return key{r.Cves[0], r.PackageName, r.ModuleName, r.ModuleStream, r.PlatformRelease, r.PlatformStream, r.SourcePackage}
	}
	fixes := make(map[key]map[string]*advisoryv1.Advisory)
	for _, r := range doc.Advisories {
		if r.FixedVersion == "" || r.AssessmentUnknown {
			continue
		}
		k := identity(r)
		if fixes[k] == nil {
			fixes[k] = make(map[string]*advisoryv1.Advisory)
		}
		prior := fixes[k][r.Architecture]
		if prior == nil {
			fixes[k][r.Architecture] = r
		} else if cmp, err := Compare("rpm", r.FixedVersion, prior.FixedVersion); err == nil && cmp < 0 {
			fixes[k][r.Architecture] = r
		}
	}
	kept := doc.Advisories[:0]
	for _, r := range doc.Advisories {
		matches := fixes[identity(r)]
		if r.FixedVersion != "" && !r.AssessmentUnknown {
			if matches[r.Architecture] != r {
				continue
			}
		} else if r.IntroducedVersion == "" && r.LastAffectedVersion == "" && !r.NotAffected && len(matches) != 0 {
			if r.Architecture == "" || matches[r.Architecture] != nil || matches["noarch"] != nil {
				continue
			}
		}
		kept = append(kept, r)
	}
	clear(doc.Advisories[len(kept):])
	doc.Advisories = kept
}
