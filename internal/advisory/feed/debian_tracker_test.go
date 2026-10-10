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

func TestDebianTrackerVendorSubset(t *testing.T) {
	raw := fixture(t, "debian-tracker-subset.json")
	doc, err := Parse(debianTrackerSource("12"), bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(doc.GetSourceSha256()); got != "02e84a980e3834906ca41fbbd5ec456cdb19c97e6f77341d263cb37198dc910a" {
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
		{"CVE-2024-6387", "openssh", "1:9.2p1-2+deb12u3", "unknown", false, false},
		{"CVE-2024-6409", "openssh", "", "negligible", false, true},
		{"CVE-2026-59995", "openssh", "", "unknown", false, false},
		{"CVE-2026-27970", "angular.js", "", "unknown", true, false},
		{"TEMP-0331720-9168FE", "adduser", "3.77", "low", false, false},
		{"CVE-2016-5416", "389-ds-base", "", "negligible", false, false},
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
				t.Fatal("missing vendor assessment")
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
	raw := fixture(t, "debian-tracker-subset.json")
	for _, release := range []struct {
		number, fixed string
	}{
		{"12", "1:9.2p1-2+deb12u3"},
		{"13", "1:9.7p1-7"},
	} {
		config := debianTrackerSource(release.number)
		config.Architecture = "amd64"
		doc, err := Parse(config, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		var backport *advisoryv1.Advisory
		for _, record := range doc.GetAdvisories() {
			if record.GetId() == "CVE-2024-6387" {
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
		// These are installed source versions, not openssh-server binary
		// versions or upstream OpenSSH releases. A binNMU must not replace
		// the captured SourceVersion used by the advisory matcher.
		for _, comparison := range []struct {
			sourceVersion string
			order         int
		}{
			{"1:9.2p1-2+deb12u2", -1},
			{"1:9.2p1-2+deb12u3~deb12u1", -1},
			{"1:9.2p1-2+deb12u3", 0},
			{"1:9.2p1-2+deb12u4", 1},
			{"2:9.2p1-2+deb12u1", 1},
		} {
			got, err := Compare("dpkg", comparison.sourceVersion, backport.GetFixedVersion())
			if err != nil || got != comparison.order {
				t.Errorf("native source %s: order=%d err=%v; want %d", comparison.sourceVersion, got, err, comparison.order)
			}
		}
	}
}

func TestDebianTrackerRejectsUnsupportedInputs(t *testing.T) {
	raw := fixture(t, "debian-tracker-subset.json")
	var selected map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &selected); err != nil {
		t.Fatal(err)
	}
	issue := string(selected["openssh"]["CVE-2024-6387"])
	packageValue := `{"CVE-2024-6387":` + issue + `}`
	for _, test := range []struct {
		name, input string
	}{
		{"array", `[]`},
		{"null", `null`},
		{"empty", `{}`},
		{"empty-package", `{"openssh":{}}`},
		{"null-issue", `{"openssh":{"CVE-2024-6387":null}}`},
		{"missing-releases", `{"openssh":{"CVE-2024-6387":{}}}`},
		{"unknown-status", strings.Replace(string(raw), `"status":"resolved"`, `"status":"future-status"`, 1)},
		{"resolved-no-fix", strings.Replace(string(raw), `"fixed_version":"1:9.2p1-2+deb12u3",`, "", 1)},
		{"resolved-empty-fix", strings.Replace(string(raw), `"fixed_version":"1:9.2p1-2+deb12u3"`, `"fixed_version":""`, 1)},
		{"open-with-fix", strings.Replace(string(raw), `"status":"resolved"`, `"status":"open"`, 1)},
		{"undetermined-with-fix", strings.Replace(string(raw), `"status":"resolved"`, `"status":"undetermined"`, 1)},
		{"invalid-native-fix", strings.Replace(string(raw), `"fixed_version":"1:9.2p1-2+deb12u3"`, `"fixed_version":"<unfixed>"`, 1)},
		{"unknown-constraint", strings.Replace(string(raw), `"status":"resolved"`, `"architecture":"arm64","status":"resolved"`, 1)},
		{"missing-repository", `{"openssh":{"CVE-2024-6387":{"releases":{"bookworm":{"status":"open","urgency":"low"}}}}}`},
		{"duplicate-package", `{"openssh":` + packageValue + `,"openssh":` + packageValue + `}`},
		{"duplicate-issue", `{"openssh":{"CVE-2024-6387":` + issue + `,"CVE-2024-6387":` + issue + `}}`},
		{"invalid-issue-id", strings.Replace(string(raw), `"CVE-2024-6387":`, `"not-a-tracker-issue":`, 1)},
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
