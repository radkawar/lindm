// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

const rejectedUbuntuID = "UBUNTU-CVE-2023-25812"
const rejectedUbuntuPackage = "golang-github-minio-minio-go"

func rejectedUbuntuOSV(id string) []byte {
	return []byte(fmt.Sprintf(`{"id":%q,"schema_version":"1.7.3","published":"2023-03-01T00:00:00Z","affected":[{"package":{"name":"golang-github-minio-minio-go","ecosystem":"Ubuntu:24.04:LTS","purl":"pkg:deb/ubuntu/golang-github-minio-minio-go?arch=src?distro=noble"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"7.0.23-1ubuntu1"}]}]}]}`, id))
}

func assertRetainedUbuntuNotice(t *testing.T, doc *advisoryv1.FeedDocument) {
	t.Helper()
	baseline, err := Parse(source("ubuntu", "24.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON), bytes.NewReader(fixture(t, "ubuntu-USN-6859-1.json")))
	if err != nil {
		t.Fatal(err)
	}
	var retained []*advisoryv1.Advisory
	for _, advisory := range doc.GetAdvisories() {
		if advisory.GetId() == "USN-6859-1" {
			retained = append(retained, advisory)
		}
	}
	if len(retained) != len(baseline.GetAdvisories()) || len(retained) == 0 {
		t.Fatalf("retained valid findings = %d, want %d nonempty findings", len(retained), len(baseline.GetAdvisories()))
	}
	for i, advisory := range retained {
		if !proto.Equal(advisory, baseline.Advisories[i]) {
			t.Fatalf("valid finding changed: got %v, want %v", advisory, baseline.Advisories[i])
		}
	}
}

func assertRejectedUnknownMappings(t *testing.T, doc *advisoryv1.FeedDocument, id string, names []string) {
	t.Helper()
	type mapping struct {
		name   string
		source bool
	}
	seen := make(map[mapping]bool)
	for _, advisory := range doc.GetAdvisories() {
		if advisory.GetId() != id {
			continue
		}
		if !advisory.GetSourceRecordRejected() || !advisory.GetAssessmentUnknown() {
			t.Fatalf("rejected record retained a native finding: %v", advisory)
		}
		if advisory.GetArchitecture() != "" || advisory.GetIntroducedVersion() != "" || advisory.GetFixedVersion() != "" || advisory.GetLastAffectedVersion() != "" {
			t.Fatalf("rejected identity was normalized into native scope or version bounds: %v", advisory)
		}
		if !slices.Contains(names, advisory.GetPackageName()) {
			t.Fatalf("unexpected inferred package name: %v", advisory)
		}
		key := mapping{advisory.GetPackageName(), advisory.GetSourcePackage()}
		if seen[key] {
			t.Fatalf("duplicate rejection mapping: %v", advisory)
		}
		seen[key] = true
	}
	for _, name := range names {
		for _, sourcePackage := range []bool{false, true} {
			if !seen[mapping{name, sourcePackage}] {
				t.Errorf("missing conservative unknown mapping for %q source=%t", name, sourcePackage)
			}
		}
	}
}

func TestOSVRejectedMalformedUbuntuIdentity(t *testing.T) {
	config := source("ubuntu", "24.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP)
	config.Url = "https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip"
	raw := osvZip(t, map[string][]byte{
		"notice.json": fixture(t, "ubuntu-USN-6859-1.json"),
		"broken.json": rejectedUbuntuOSV(rejectedUbuntuID),
	}, zip.Store)
	doc, err := Parse(config, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	assertRetainedUbuntuNotice(t, doc)
	if !doc.GetCompleteSnapshot() {
		t.Fatal("named rejection unnecessarily removed coverage for unrelated packages")
	}
	if len(doc.GetRejectedRecords()) != 1 {
		t.Fatalf("rejected records = %v, want one", doc.GetRejectedRecords())
	}
	rejected := doc.RejectedRecords[0]
	if rejected.GetId() != rejectedUbuntuID || rejected.GetReason() != "feed: unsupported OSV architecture" || rejected.GetUnscoped() || !slices.Equal(rejected.GetPackageNames(), []string{rejectedUbuntuPackage}) {
		t.Fatalf("rejection lost original identity, reason or package names: %v", rejected)
	}
	assertRejectedUnknownMappings(t, doc, rejectedUbuntuID, []string{rejectedUbuntuPackage})
}

func TestOSVRejectedRecordThreshold(t *testing.T) {
	for _, test := range []struct {
		name     string
		limit    *uint32
		count    int
		wantFail bool
	}{
		{name: "default allows individual rejection", count: 1},
		{name: "zero accepts valid archive", limit: proto.Uint32(0)},
		{name: "zero fails first rejection", limit: proto.Uint32(0), count: 1, wantFail: true},
		{name: "one accepts one rejected record", limit: proto.Uint32(1), count: 1},
		{name: "one fails second rejection", limit: proto.Uint32(1), count: 2, wantFail: true},
		{name: "two accepts two rejected records", limit: proto.Uint32(2), count: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := source("ubuntu", "24.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP)
			config.MaxRejectedRecords = test.limit
			entries := map[string][]byte{"notice.json": fixture(t, "ubuntu-USN-6859-1.json")}
			for i := range test.count {
				entries[fmt.Sprintf("broken-%d.json", i)] = rejectedUbuntuOSV(fmt.Sprintf("UBUNTU-CVE-2023-%d", 25812+i))
			}
			doc, err := Parse(config, bytes.NewReader(osvZip(t, entries, zip.Store)))
			if test.wantFail {
				if err == nil || !strings.Contains(err.Error(), "rejected record limit") {
					t.Fatalf("error = %v, want rejected record limit", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(doc.GetRejectedRecords()) != test.count {
				t.Fatalf("rejected records = %d, want %d", len(doc.GetRejectedRecords()), test.count)
			}
			assertRetainedUbuntuNotice(t, doc)
		})
	}
}

func TestOSVRejectedRecordAtomicity(t *testing.T) {
	var valid, broken osvRecord
	if err := json.Unmarshal(fixture(t, "ubuntu-USN-6859-1.json"), &valid); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rejectedUbuntuOSV(rejectedUbuntuID), &broken); err != nil {
		t.Fatal(err)
	}
	var affected []osvAffected
	names := []string{rejectedUbuntuPackage}
	for _, item := range valid.Affected {
		if item.Package.Ecosystem == "Ubuntu:24.04:LTS" {
			affected = append(affected, item)
			names = append(names, item.Package.Name)
		}
	}
	if len(affected) == 0 {
		t.Fatal("fixture has no matching affected product")
	}
	// Force native source and binary findings to be appended before the defect.
	broken.Affected = append(affected, broken.Affected...)
	payload, err := json.Marshal(&broken)
	if err != nil {
		t.Fatal(err)
	}
	raw := osvZip(t, map[string][]byte{"notice.json": fixture(t, "ubuntu-USN-6859-1.json"), "broken.json": payload}, zip.Store)
	doc, err := Parse(source("ubuntu", "24.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP), bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	assertRetainedUbuntuNotice(t, doc)
	if len(doc.GetRejectedRecords()) != 1 || doc.RejectedRecords[0].GetId() != rejectedUbuntuID {
		t.Fatalf("multi-affected record was not rejected atomically: %v", doc.GetRejectedRecords())
	}
	gotNames := slices.Clone(doc.RejectedRecords[0].GetPackageNames())
	slices.Sort(gotNames)
	slices.Sort(names)
	if !slices.Equal(gotNames, names) {
		t.Fatalf("rejected package names = %v, want %v", gotNames, names)
	}
	assertRejectedUnknownMappings(t, doc, rejectedUbuntuID, names)
}

func TestOSVRejectedPackageLessRecordDegradesCoverage(t *testing.T) {
	broken := []byte(`{"id":"UBUNTU-CVE-2023-25812","schema_version":"1.7.3","published":"2023-03-01T00:00:00Z","affected":[{"package":{"ecosystem":"Ubuntu:24.04:LTS"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`)
	raw := osvZip(t, map[string][]byte{"notice.json": fixture(t, "ubuntu-USN-6859-1.json"), "broken.json": broken}, zip.Store)
	doc, err := Parse(source("ubuntu", "24.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP), bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	assertRetainedUbuntuNotice(t, doc)
	if doc.GetCompleteSnapshot() {
		t.Fatal("package-less rejection falsely retained complete coverage")
	}
	if len(doc.GetRejectedRecords()) != 1 {
		t.Fatalf("rejected records = %v, want one", doc.GetRejectedRecords())
	}
	rejected := doc.RejectedRecords[0]
	if rejected.GetId() != rejectedUbuntuID || rejected.GetReason() == "" || !rejected.GetUnscoped() || len(rejected.GetPackageNames()) != 0 {
		t.Fatalf("package-less rejection metadata = %v", rejected)
	}
	assertRejectedUnknownMappings(t, doc, rejectedUbuntuID, nil)
}
