// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

func debianTrackerSource(release string) *advisoryv1.FeedSource {
	config := source("debian", release, advisoryv1.FeedFormat_FEED_FORMAT_DEBIAN_TRACKER_JSON)
	config.Url = "https://security-tracker.debian.org/tracker/data/json"
	return config
}

func TestDebianTrackerSyntheticSubset(t *testing.T) {
	raw := fixture(t, "synthetic-debian-tracker-subset.json")
	doc, err := Parse(debianTrackerSource("12"), bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(doc.GetSourceSha256()); got != "43e03fbf230a25f87054e765a136a57826e30b9da215884d3a071ce05e44c47e" {
		t.Fatalf("tracker fixture digest %s", got)
	}
	if doc.GetCompleteSnapshot() {
		t.Fatal("tracker issue list manufactured package-universe coverage")
	}
	if len(doc.GetAdvisories()) != 6 {
		t.Fatalf("got %d assessments; want 6", len(doc.GetAdvisories()))
	}
	for _, want := range []struct {
		id, name, fixed, severity string
		unknown, notAffected      bool
	}{
		{"CVE-2099-99001", "synthetic-deb-source", "3:7.4-2+deb12u3", "unknown", false, false},
		{"CVE-2099-99002", "synthetic-deb-source", "", "negligible", false, true},
		{"CVE-2099-99003", "synthetic-deb-source", "", "unknown", false, false},
		{"CVE-2099-99004", "synthetic-deb-widget", "", "unknown", true, false},
		{"TEMP-0999001-ABCDEF", "synthetic-deb-account", "8.77", "low", false, false},
		{"CVE-2099-99005", "synthetic-deb-directory", "", "negligible", false, false},
	} {
		t.Run(want.id, func(t *testing.T) {
			var got *advisoryv1.Advisory
			for _, record := range doc.GetAdvisories() {
				if record.GetId() == want.id {
					got = record
					break
				}
			}
			if got == nil {
				t.Fatal("missing synthetic assessment")
			}
			if got.GetPackageName() != want.name || !got.GetSourcePackage() || got.GetArchitecture() != "" {
				t.Fatalf("source identity replaced by inferred binary/architecture map: %v", got)
			}
			if got.GetFixedVersion() != want.fixed || got.GetSeverity() != want.severity || got.GetAssessmentUnknown() != want.unknown || got.GetNotAffected() != want.notAffected {
				t.Fatalf("wrong native assessment: %v", got)
			}
			if got.GetIntroducedVersion() != "" || got.GetLastAffectedVersion() != "" || got.GetPublishedAt() != nil {
				t.Fatalf("invented constraint or publication time: %v", got)
			}
			if got.GetSourceUrl() != "https://security-tracker.debian.org/tracker/"+want.id {
				t.Fatalf("lost authoritative reference: %s", got.GetSourceUrl())
			}
			if strings.HasPrefix(want.id, "TEMP-") {
				if len(got.GetCves()) != 0 {
					t.Fatal("provisional tracker ID promoted to CVE")
				}
			} else if len(got.GetCves()) != 1 || got.GetCves()[0] != want.id {
				t.Fatalf("lost CVE: %v", got.GetCves())
			}
		})
	}
}

func TestDebianTrackerBackportBoundaryAndScope(t *testing.T) {
	raw := fixture(t, "synthetic-debian-tracker-subset.json")
	for _, release := range []struct {
		number, fixed string
	}{
		{"12", "3:7.4-2+deb12u3"},
		{"13", "3:8.1-7"},
	} {
		config := debianTrackerSource(release.number)
		config.Architecture = "amd64"
		doc, err := Parse(config, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		var backport *advisoryv1.Advisory
		for _, record := range doc.GetAdvisories() {
			if record.GetId() == "CVE-2099-99001" {
				backport = record
			}
		}
		if backport == nil || backport.GetFixedVersion() != release.fixed {
			t.Fatalf("release %s used foreign release or archive version instead of first fixed version: %v", release.number, backport)
		}
		if !Applies(config, "debian", release.number, "x86_64") {
			t.Fatal("configured Debian architecture alias rejected")
		}
		if Applies(config, "ubuntu", release.number, "amd64") || Applies(config, "debian", "14", "amd64") || Applies(config, "debian", release.number, "arm64") {
			t.Fatal("tracker coverage leaked across distro/release/architecture")
		}
		if release.number != "12" {
			continue
		}
		// Controlled source versions deliberately differ from binary versions.
		// A binNMU must not replace the captured SourceVersion used by the
		// advisory matcher, regardless of the binary's newer-looking version.
		for _, comparison := range []struct {
			sourceVersion string
			order         int
		}{
			{"3:7.4-2+deb12u2", -1},
			{"3:7.4-2+deb12u3~deb12u1", -1},
			{"3:7.4-2+deb12u3", 0},
			{"3:7.4-2+deb12u4", 1},
			{"4:7.4-2+deb12u1", 1},
		} {
			got, err := Compare("dpkg", comparison.sourceVersion, backport.GetFixedVersion())
			if err != nil || got != comparison.order {
				t.Errorf("native source %s: order=%d err=%v; want %d", comparison.sourceVersion, got, err, comparison.order)
			}
		}
	}
}

func TestDebianTrackerRejectsUnsupportedInputs(t *testing.T) {
	raw := fixture(t, "synthetic-debian-tracker-subset.json")
	var selected map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &selected); err != nil {
		t.Fatal(err)
	}
	issue := string(selected["synthetic-deb-source"]["CVE-2099-99001"])
	packageValue := `{"CVE-2099-99001":` + issue + `}`
	for _, test := range []struct {
		name, input string
	}{
		{"array", `[]`},
		{"null", `null`},
		{"empty", `{}`},
		{"empty-package", `{"synthetic-deb-source":{}}`},
		{"null-issue", `{"synthetic-deb-source":{"CVE-2099-99001":null}}`},
		{"missing-releases", `{"synthetic-deb-source":{"CVE-2099-99001":{}}}`},
		{"unknown-status", strings.Replace(string(raw), `"status":"resolved"`, `"status":"future-status"`, 1)},
		{"resolved-no-fix", strings.Replace(string(raw), `"fixed_version":"3:7.4-2+deb12u3",`, "", 1)},
		{"resolved-empty-fix", strings.Replace(string(raw), `"fixed_version":"3:7.4-2+deb12u3"`, `"fixed_version":""`, 1)},
		{"open-with-fix", strings.Replace(string(raw), `"status":"resolved"`, `"status":"open"`, 1)},
		{"undetermined-with-fix", strings.Replace(string(raw), `"status":"resolved"`, `"status":"undetermined"`, 1)},
		{"invalid-native-fix", strings.Replace(string(raw), `"fixed_version":"3:7.4-2+deb12u3"`, `"fixed_version":"<unfixed>"`, 1)},
		{"unknown-constraint", strings.Replace(string(raw), `"status":"resolved"`, `"architecture":"arm64","status":"resolved"`, 1)},
		{"missing-repository", `{"synthetic-deb-source":{"CVE-2099-99001":{"releases":{"bookworm":{"status":"open","urgency":"low"}}}}}`},
		{"duplicate-package", `{"synthetic-deb-source":` + packageValue + `,"synthetic-deb-source":` + packageValue + `}`},
		{"duplicate-issue", `{"synthetic-deb-source":{"CVE-2099-99001":` + issue + `,"CVE-2099-99001":` + issue + `}}`},
		{"invalid-issue-id", strings.Replace(string(raw), `"CVE-2099-99001":`, `"not-a-tracker-issue":`, 1)},
		{"truncated", string(raw[:len(raw)-2])},
		{"trailing-object", string(raw) + `{}`},
		{"oversized-issue", strings.Replace(string(raw), `"description":"`, `"description":"`+strings.Repeat("x", maxRecordBytes), 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Parse(debianTrackerSource("12"), strings.NewReader(test.input)); err == nil {
				t.Fatal("unsupported tracker document accepted")
			}
		})
	}
	for _, release := range []string{"11", "12.1", "14", "bookworm", "stable"} {
		t.Run("release-"+release, func(t *testing.T) {
			if _, err := Parse(debianTrackerSource(release), bytes.NewReader(raw)); err == nil {
				t.Fatal("missing or unsupported suite accepted")
			}
		})
	}
	config := debianTrackerSource("12")
	config.Distro = "ubuntu"
	if _, err := Parse(config, bytes.NewReader(raw)); err == nil {
		t.Fatal("Debian tracker applied to another distro")
	}
}
