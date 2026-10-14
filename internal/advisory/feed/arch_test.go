// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"buf.build/go/protovalidate"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

func archSource() *advisoryv1.FeedSource {
	config := source("arch", "rolling", advisoryv1.FeedFormat_FEED_FORMAT_ARCH_JSON)
	config.Url = "https://security.archlinux.org/issues/all.json"
	config.Architecture = "x86_64"
	return config
}

func TestArchBackportedFixAndPublication(t *testing.T) {
	config := archSource()
	raw := fixture(t, "synthetic-arch-backport.json")
	doc, err := Parse(config, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(doc.GetSourceSha256()); got != "0010d5e7403b7fbe36fdc10fc58b248dae51e988de8d117fe0ff3015c4d4a49e" {
		t.Fatalf("Arch issue fixture digest = %s", got)
	}
	if doc.GetCompleteSnapshot() || len(doc.GetAdvisories()) != 1 {
		t.Fatalf("wrong Arch coverage: %v", doc)
	}
	record := doc.GetAdvisories()[0]
	if record.GetId() != "AVG-99001" || record.GetPackageName() != "synthetic-arch-radio" || record.GetFixedVersion() != "4:8.3-8" || record.GetSourcePackage() || record.GetArchitecture() != "" {
		t.Fatalf("wrong backported-fix identity: %v", record)
	}
	if record.GetPublishedAt() != nil || record.GetIntroducedVersion() != "" || record.GetLastAffectedVersion() != "" || record.GetAssessmentUnknown() || record.GetNotAffected() {
		t.Fatalf("invented Arch metadata or incorrect assessment: %v", record)
	}
	if len(record.GetCves()) != 1 || record.GetCves()[0] != "CVE-2099-99010" || record.GetSeverity() != "high" || record.GetSourceUrl() != "https://security.archlinux.org/AVG-99001" {
		t.Fatalf("lost authored issue metadata: %v", record)
	}
	for _, test := range []struct {
		version string
		want    int
	}{
		{"4:8.3-7", -1},
		{"4:8.3-8", 0},
		{"4:8.3-9", 1},
		{"3:99.0-99", -1},
	} {
		got, err := Compare("pacman", test.version, record.GetFixedVersion())
		if err != nil || got != test.want {
			t.Errorf("Arch backport %s = %d, %v; want %d", test.version, got, err, test.want)
		}
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(&advisoryv1.Advisory{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := applyArchAdvisoryDates(doc, fixture(t, "synthetic-arch-advisories.json"), validator); err != nil {
		t.Fatal(err)
	}
	if record.GetPublishedAt() == nil || !record.GetPublishedAt().AsTime().Equal(time.Date(2099, 2, 12, 0, 0, 0, 0, time.UTC)) || record.GetSourceUrl() != "https://security.archlinux.org/ASA-209902-99" {
		t.Fatalf("lost authoritative ASA date and source: %v", record)
	}
	if doc.GetCompleteSnapshot() {
		t.Fatal("publication dates manufactured complete repository coverage")
	}
}

func TestArchAssessmentStates(t *testing.T) {
	doc, err := Parse(archSource(), bytes.NewReader(fixture(t, "synthetic-arch-statuses.json")))
	if err != nil {
		t.Fatal(err)
	}
	if doc.GetCompleteSnapshot() || len(doc.GetAdvisories()) != 4 {
		t.Fatalf("wrong partial Arch coverage: %v", doc)
	}
	records := make(map[string]*advisoryv1.Advisory)
	for _, record := range doc.GetAdvisories() {
		records[record.GetPackageName()] = record
		if record.GetPublishedAt() != nil || record.GetSourcePackage() || record.GetArchitecture() != "" {
			t.Fatalf("invented Arch metadata: %v", record)
		}
	}
	unknown := records["synthetic-arch-editor"]
	if unknown == nil || !unknown.GetAssessmentUnknown() || unknown.GetNotAffected() || unknown.GetFixedVersion() != "" || unknown.GetIntroducedVersion() != "" || unknown.GetLastAffectedVersion() != "" {
		t.Fatalf("undetermined vendor status became authoritative affected/fixed: %v", unknown)
	}
	vulnerable := records["synthetic-arch-reader"]
	if vulnerable == nil || vulnerable.GetAssessmentUnknown() || vulnerable.GetNotAffected() || vulnerable.GetFixedVersion() != "" || vulnerable.GetIntroducedVersion() != "6.5.28-6" || vulnerable.GetLastAffectedVersion() != "6.5.28-6" {
		t.Fatalf("unfixed record escaped its known-affected build: %v", vulnerable)
	}
	notAffected := records["synthetic-arch-desktop"]
	if notAffected == nil || !notAffected.GetNotAffected() || notAffected.GetAssessmentUnknown() || notAffected.GetFixedVersion() != "" {
		t.Fatalf("vendor not-affected record became a vulnerability: %v", notAffected)
	}
	fixed := records["synthetic-arch-compressor"]
	if fixed == nil || fixed.GetFixedVersion() != "3:6.2.12-3" || fixed.GetAssessmentUnknown() || fixed.GetNotAffected() {
		t.Fatalf("lost synthetic epoch/pkgrel fix without ASA: %v", fixed)
	}
}

func TestArchProductAndArchitectureNegatives(t *testing.T) {
	for _, test := range []struct{ distro, release, arch string }{
		{"manjaro", "rolling", "x86_64"},
		{"archlinuxarm", "rolling", "aarch64"},
		{"ubuntu", "24.04", "x86_64"},
		{"arch", "2026.10", "x86_64"},
		{"arch", "rolling", "aarch64"},
		{"arch", "rolling", "i686"},
		{"arch", "rolling", ""},
	} {
		config := archSource()
		config.Distro, config.Release, config.Architecture = test.distro, test.release, test.arch
		if _, err := Parse(config, bytes.NewReader(fixture(t, "synthetic-arch-backport.json"))); err == nil {
			t.Errorf("Arch export accepted foreign/unbound product: %+v", test)
		}
	}
	config := archSource()
	if !Applies(config, "arch", "rolling", "x86_64") || Applies(config, "arch", "rolling", "aarch64") || Applies(config, "manjaro", "rolling", "x86_64") || Applies(config, "arch", "2026.10", "x86_64") {
		t.Fatal("Arch applicability escaped exact distro/release/architecture")
	}
}

func TestArchUnreleasedAndTestingFixRemainConservative(t *testing.T) {
	// The tracker derives these statuses from the repositories containing its
	// fixed version. They affirm an affected build but not a stable-channel fix.
	for _, status := range []string{"Vulnerable", "Testing"} {
		raw := bytes.Replace(fixture(t, "synthetic-arch-backport.json"), []byte(`"status": "Fixed"`), []byte(`"status": "`+status+`"`), 1)
		doc, err := Parse(archSource(), bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		record := doc.GetAdvisories()[0]
		if record.GetAssessmentUnknown() || record.GetNotAffected() || record.GetFixedVersion() != "" || record.GetIntroducedVersion() != "4:8.3-7" || record.GetLastAffectedVersion() != "4:8.3-7" {
			t.Fatalf("%s discarded a known affected build or advertised an unavailable fix: %v", status, record)
		}
	}
}

func TestArchRejectsUnsupportedVendorConstraints(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*archIssue)
	}{
		{"unknown-status", func(issue *archIssue) { issue.Status = "Investigating" }},
		{"missing-fix", func(issue *archIssue) { issue.Fixed = "" }},
		{"missing-affected", func(issue *archIssue) { issue.Affected = "" }},
		{"inverted-fix", func(issue *archIssue) { issue.Fixed = "4:8.3-6" }},
		{"equal-fix", func(issue *archIssue) { issue.Fixed = issue.Affected }},
		{"invalid-version", func(issue *archIssue) { issue.Fixed = ">=4:8.3-8" }},
		{"missing-package", func(issue *archIssue) { issue.Packages = nil }},
		{"duplicate-package", func(issue *archIssue) { issue.Packages = append(issue.Packages, issue.Packages[0]) }},
		{"invalid-cve", func(issue *archIssue) { issue.Issues = []string{"not-a-CVE"} }},
		{"invalid-reference", func(issue *archIssue) { issue.Advisories = []string{"../../advisory"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var issues []archIssue
			if err := json.Unmarshal(fixture(t, "synthetic-arch-backport.json"), &issues); err != nil {
				t.Fatal(err)
			}
			test.mutate(&issues[0])
			raw, err := json.Marshal(issues)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Parse(archSource(), bytes.NewReader(raw)); err == nil {
				t.Fatal("unsupported Arch input accepted")
			}
		})
	}
	raw := fixture(t, "synthetic-arch-backport.json")
	for _, input := range [][]byte{
		[]byte(`[]`),
		[]byte(`{}`),
		[]byte(`[null]`),
		append(bytes.Clone(raw), []byte(`[]`)...),
		bytes.Replace(raw, []byte(`"name":`), []byte(`"repository":"third-party","name":`), 1),
		bytes.Replace(raw, []byte(`"name":`), []byte(`"architecture":"aarch64","name":`), 1),
	} {
		if _, err := Parse(archSource(), bytes.NewReader(input)); err == nil {
			t.Fatalf("unsupported Arch JSON shape accepted: %.100s", input)
		}
	}
}

func TestArchPublicationJoinCannotInventDates(t *testing.T) {
	validator, err := protovalidate.New(protovalidate.WithMessages(&advisoryv1.Advisory{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, from, to string
		wantError      bool
	}{
		{"foreign-package", "synthetic-arch-radio", "another-package", false},
		{"foreign-group", "AVG-99001", "AVG-99006", false},
		{"invalid-date", "2099-02-12", "2099-02-30", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			doc, err := Parse(archSource(), bytes.NewReader(fixture(t, "synthetic-arch-backport.json")))
			if err != nil {
				t.Fatal(err)
			}
			raw := bytes.ReplaceAll(fixture(t, "synthetic-arch-advisories.json"), []byte(test.from), []byte(test.to))
			err = applyArchAdvisoryDates(doc, raw, validator)
			if (err != nil) != test.wantError {
				t.Fatalf("date enrichment error = %v; wantError %v", err, test.wantError)
			}
			if doc.GetAdvisories()[0].GetPublishedAt() != nil {
				t.Fatal("unrelated or invalid publication metadata supplied a date")
			}
		})
	}
}

func TestArchUpstreamALPMVersionVectors(t *testing.T) {
	// This is the unmodified upstream test source at the pinned pacman release,
	// not comparator-generated expectations. Do not execute the shell fixture.
	raw := fixture(t, "arch-vercmptest.txt")
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "dfe61f66ef31756f7b02a045c0ab396bfa6dfb30c12e27fbaac849f650e62061" {
		t.Fatal("upstream Arch version fixture changed")
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	count := 0
	for scanner.Scan() {
		if !strings.HasPrefix(scanner.Text(), "tap_runtest ") {
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) != 4 {
			t.Fatalf("invalid upstream Arch vector: %q", scanner.Text())
		}
		want, err := strconv.Atoi(fields[3])
		if err != nil {
			t.Fatal(err)
		}
		got, err := Compare("pacman", fields[1], fields[2])
		if err != nil || got != want {
			t.Errorf("ALPM(%q,%q) = %d, %v; want %d", fields[1], fields[2], got, err, want)
		}
		reverse, err := Compare("pacman", fields[2], fields[1])
		if err != nil || reverse != -want {
			t.Errorf("reverse ALPM(%q,%q) = %d, %v; want %d", fields[2], fields[1], reverse, err, -want)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 46 {
		t.Fatalf("read %d upstream Arch vectors; want 46", count)
	}
}

func TestArchNativeEpochPkgrelAndSeparators(t *testing.T) {
	for _, test := range []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0-2", 0},
		{"1.0rc1", "1.0", -1},
		{"1.0~rc1", "1.0", 1},
		{"2___a", "2_a", 1},
		{"1.0-1.2", "1.0-1.10", -1},
		{"4:8.3-8", "3:99.0-99", 1},
		{"18446744073709551616:1-1", "18446744073709551615:99-99", 1},
	} {
		got, err := compareArch(test.a, test.b)
		if err != nil || got != test.want {
			t.Errorf("ALPM(%q,%q) = %d, %v; want %d", test.a, test.b, got, err, test.want)
		}
	}
	for _, invalid := range []string{"", ":1", "a:1", "1::2", "1-", "-1", "1-a-b", "1/2", "1\n", "é1"} {
		if _, err := compareArch(invalid, "1"); err == nil {
			t.Errorf("ALPM accepted invalid package version %q", invalid)
		}
	}
}
