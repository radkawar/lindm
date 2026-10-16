// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

func TestRedHatIndexedDocumentConfinement(t *testing.T) {
	for _, test := range []struct {
		path, distribution string
		valid              bool
	}{
		{"2024/cve-2024-6119.json", "vex", true},
		{"2024/rhsa-2024_6783.json", "advisories", true},
		{"2024/rhba-2024_6783.json", "advisories", true},
		{"2002/rhsa-2001_164.json", "advisories", true},
		{"2006/rhba-2007_0331.json", "advisories", true},
		{"2024/rhsa-2023_7197.json", "advisories", true},
		{"2024/rhea-2024_0001.json", "advisories", true},
		{"2024/rhsa-2024_.json", "advisories", false},
		{"2024/rhsa-2024_12invalid.json", "advisories", false},
		{"2024/rhsa-2024_1234.json", "unknown", false},
		{"2024/cve-2024-123invalid.json", "vex", false},
		{"../2024/cve-2024-6119.json", "vex", false},
		{"/2024/cve-2024-6119.json", "vex", false},
		{"2024/../2024/cve-2024-6119.json", "vex", false},
		{"2024/cve-2024-6119.json?x=1", "vex", false},
		{"2024/cve-2024-6119.json#fragment", "vex", false},
		{"2024/cve-2024-6119%2ejson", "vex", false},
		{"2024/cve-2024-6119.json\n", "vex", false},
		{"2023/cve-2024-6119.json", "vex", true},
		{"2024/rhsa-2024_6783.json", "vex", false},
	} {
		if got := redHatDocumentPath(test.path, test.distribution); got != test.valid {
			t.Errorf("path %q (%s): got %t", test.path, test.distribution, got)
		}
	}
}

func snapshotStager(t *testing.T) *redHatStager {
	t.Helper()
	stager, err := newRedHatStager(t.Context(), redHatSource("9.8", "standard"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stager.close(); err != nil {
			t.Error(err)
		}
	})
	return stager
}

func TestRedHatIndexClosureChangesDeletionsAndDigest(t *testing.T) {
	stager := snapshotStager(t)
	checkpoint := &redHatCheckpoint{
		distribution: "vex",
		index:        []byte("2024/cve-2024-6119.json\n2024/cve-2024-21892.json\n2026/cve-2026-12345.json\n"),
		changes: []byte("\"2024/cve-2024-21892.json\",\"2026-10-13T00:00:00Z\"\n" +
			"\"2024/cve-2024-6119.json\",\"2026-10-01T00:00:00Z\"\n"),
	}
	if err := checkpoint.stage(t.Context(), stager); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	if _, err := checkpoint.summary(t.Context(), stager); err == nil {
		t.Fatal("missing indexed documents asserted a closed snapshot")
	}
	for _, test := range []struct {
		path string
		use  bool
	}{
		{"2024/cve-2024-6119.json", true},
		{"2024/cve-2024-21892.json", false}, // Replacement after the archive.
		{"2023/cve-2023-44487.json", false}, // Deleted from captured universe.
	} {
		got, err := checkpoint.archived(t.Context(), stager, test.path, at)
		if err != nil || got != test.use {
			t.Fatalf("archived %s: use=%t err=%v", test.path, got, err)
		}
	}
	if _, err := checkpoint.archived(t.Context(), stager, "2024/cve-2024-6119.json", at); err == nil {
		t.Fatal("duplicate archive member accepted")
	}
	for _, name := range []string{"2024/cve-2024-6119.json", "2024/cve-2024-21892.json", "2026/cve-2026-12345.json"} {
		digest := sha256.Sum256([]byte(name))
		if err := checkpoint.record(t.Context(), stager, name, digest[:]); err != nil {
			t.Fatal(err)
		}
	}
	summary, err := checkpoint.summary(t.Context(), stager)
	if err != nil || summary.GetDocumentCount() != 3 || len(summary.GetDocumentManifestSha256()) != sha256.Size {
		t.Fatalf("closed snapshot summary=%v err=%v", summary, err)
	}
	before := bytes.Clone(summary.DocumentManifestSha256)
	changed := sha256.Sum256([]byte("replacement original bytes"))
	if err := checkpoint.record(t.Context(), stager, "2024/cve-2024-21892.json", changed[:]); err != nil {
		t.Fatal(err)
	}
	summary, err = checkpoint.summary(t.Context(), stager)
	if err != nil || bytes.Equal(before, summary.GetDocumentManifestSha256()) {
		t.Fatalf("replacement bytes did not change snapshot identity: %v %v", summary, err)
	}
}

func TestRedHatInvalidIndexNeverEstablishesCoverage(t *testing.T) {
	for _, test := range []struct {
		name, index, changes string
	}{
		{"empty", "", "\"2024/cve-2024-6119.json\",\"2026-10-01T00:00:00Z\"\n"},
		{"duplicate", "2024/cve-2024-6119.json\n2024/cve-2024-6119.json\n", ""},
		{"unsafe", "../2024/cve-2024-6119.json\n", ""},
		{"empty-changes", "2024/cve-2024-6119.json\n", ""},
		{"invalid-time", "2024/cve-2024-6119.json\n", "\"2024/cve-2024-6119.json\",\"yesterday\"\n"},
		{"future-time", "2024/cve-2024-6119.json\n", "\"2024/cve-2024-6119.json\",\"2099-01-01T00:00:00Z\"\n"},
		{"unsafe-change", "2024/cve-2024-6119.json\n", "\"../2024/cve-2024-6119.json\",\"2026-10-01T00:00:00Z\"\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			checkpoint := &redHatCheckpoint{distribution: "vex", index: []byte(test.index), changes: []byte(test.changes)}
			if err := checkpoint.stage(t.Context(), snapshotStager(t)); err == nil {
				t.Fatal("invalid vendor inventory established coverage")
			}
		})
	}
}

func TestRedHatCheckpointRequiresStableVerifiedTLSMetadata(t *testing.T) {
	for _, mode := range []string{"stable", "index-race", "changes-race"} {
		t.Run(mode, func(t *testing.T) {
			counts := map[string]int{}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				counts[r.URL.Path]++
				var text string
				switch r.URL.Path {
				case "/provider/vex/index.txt":
					text = "2024/cve-2024-6119.json\n"
					if mode == "index-race" && counts[r.URL.Path] > 1 {
						text += "2024/cve-2024-21892.json\n"
					}
				case "/provider/vex/changes.csv":
					text = "\"2024/cve-2024-6119.json\",\"2026-10-01T00:00:00Z\"\n"
					if mode == "changes-race" && counts[r.URL.Path] > 1 {
						text += "\"2024/cve-2024-21892.json\",\"2026-10-02T00:00:00Z\"\n"
					}
				default:
					http.NotFound(w, r)
					return
				}
				if _, err := fmt.Fprint(w, text); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			client, err := New(server.Client())
			if err != nil {
				t.Fatal(err)
			}
			root, err := url.Parse(server.URL + "/provider/")
			if err != nil {
				t.Fatal(err)
			}
			checkpoint, err := client.redHatCheckpoint(t.Context(), root, "vex")
			if mode == "stable" {
				if err != nil || len(checkpoint.artifacts()) != 2 || checkpoint.artifacts()[0].GetSignerFingerprint() != "" {
					t.Fatalf("TLS checkpoint incorrectly signed or incomplete: %v %v", checkpoint, err)
				}
			} else if err == nil || checkpoint != nil {
				t.Fatal("racing vendor checkpoint acquired completeness")
			}
			root.Scheme = "http"
			if _, err := client.redHatCheckpoint(t.Context(), root, "vex"); err == nil || !strings.Contains(err.Error(), "HTTPS") {
				t.Fatalf("unverified index accepted: %v", err)
			}
		})
	}
}

func TestRedHatSnapshotDigestBindsDocumentUniverse(t *testing.T) {
	artifact := &advisoryv1.FeedArtifact{Url: "https://example.test/archive.tar.zst", Sha256: make([]byte, sha256.Size)}
	index := &advisoryv1.FeedArtifact{Url: "https://example.test/index.txt", Sha256: make([]byte, sha256.Size)}
	doc := &advisoryv1.FeedDocument{RedhatSnapshot: &advisoryv1.RedHatSnapshot{Distributions: []*advisoryv1.RedHatDistributionSnapshot{{Distribution: "vex", DocumentCount: 1, DocumentManifestSha256: make([]byte, sha256.Size)}}}}
	if err := bindArtifacts(doc, []*advisoryv1.FeedArtifact{artifact, index}); err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(doc.SourceSha256)
	doc.RedhatSnapshot.Distributions[0].DocumentManifestSha256[0] = 1
	if err := bindArtifacts(doc, doc.Artifacts); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, doc.SourceSha256) {
		t.Fatal("two different applied document universes shared a feed revision")
	}
}

func TestRedHatArchiveContentFloorPrecedesAssembly(t *testing.T) {
	signedAt := time.Date(2026, 10, 11, 13, 0, 0, 0, time.UTC)
	floor, err := redHatArchiveContentFloor("/vex/csaf_vex_2026-10-11.tar.zst", "vex", signedAt)
	if err != nil || floor.Hour() != 0 || floor.Day() != 11 {
		t.Fatalf("archive content floor=%s err=%v", floor, err)
	}
	stager := snapshotStager(t)
	checkpoint := &redHatCheckpoint{
		distribution: "vex",
		index:        []byte("2024/cve-2024-6119.json\n"),
		changes:      []byte("\"2024/cve-2024-6119.json\",\"2026-10-11T12:00:00Z\"\n"),
	}
	if err := checkpoint.stage(t.Context(), stager); err != nil {
		t.Fatal(err)
	}
	if use, err := checkpoint.archived(t.Context(), stager, "2024/cve-2024-6119.json", floor); err != nil || use {
		t.Fatalf("change during archive assembly retained old claims: use=%t err=%v", use, err)
	}
	if _, err := redHatArchiveContentFloor("/vex/csaf_vex_2026-10-12.tar.zst", "vex", signedAt); err == nil {
		t.Fatal("archive claimed content checkpoint after its own signature")
	}
}

func TestRedHatReplacementSignatureMustReachCapturedChange(t *testing.T) {
	raw := fixture(t, "redhat-cve-2024-6119.json")
	proof := fixture(t, "redhat-cve-2024-6119.json.asc")
	trust, err := newVendorTrust()
	if err != nil {
		t.Fatal(err)
	}
	_, signedAt, err := trust.verify(t.Context(), redHatFingerprint, bytes.NewReader(raw), proof, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	for _, delta := range []time.Duration{0, time.Nanosecond, time.Second} {
		t.Run(delta.String(), func(t *testing.T) {
			checkpoint := &redHatCheckpoint{
				distribution: "vex",
				index:        []byte("2024/cve-2024-6119.json\n"),
				changes:      fmt.Appendf(nil, "\"2024/cve-2024-6119.json\",\"%s\"\n", signedAt.Add(delta).Format(time.RFC3339Nano)),
			}
			stager := snapshotStager(t)
			if err := checkpoint.stage(t.Context(), stager); err != nil {
				t.Fatal(err)
			}
			err := checkpoint.recordReplacement(t.Context(), stager, "2024/cve-2024-6119.json", digest[:], signedAt.Add(delta).UnixNano(), signedAt)
			if delta == 0 {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := checkpoint.summary(t.Context(), stager); err != nil {
					t.Fatalf("current authenticated replacement failed closure: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("genuine but older signed original satisfied a newer change checkpoint")
				}
				if _, err := checkpoint.summary(t.Context(), stager); err == nil {
					t.Fatal("stale signed replacement made the inventory complete")
				}
			}
		})
	}
}

func TestRedHatSnapshotCompletionRequiresNativePackageAuthority(t *testing.T) {
	for _, test := range []struct {
		distro, release string
		complete        bool
	}{
		{"rhel", "9", true},
		{"rhel", "9.8", true},
		{"rhel", "10.2", true},
		{"rhel", "8.10", false},
		{"rocky", "9.8", false},
		{"fedora", "44", false},
	} {
		source := &advisoryv1.FeedSource{Distro: test.distro, Release: test.release}
		scoped := []*advisoryv1.RejectedRecord{{Id: "CVE-2023-44487", PackageNames: []string{"nginx"}}}
		if got := redHatSnapshotComplete(source, scoped); got != test.complete {
			t.Fatalf("%s %s scoped completion=%v, want %v", test.distro, test.release, got, test.complete)
		}
		for _, rejected := range [][]*advisoryv1.RejectedRecord{
			{{Id: "CVE-2023-44487", Unscoped: true, PackageNames: []string{"nginx"}}},
			{{Id: "CVE-2023-44487"}},
		} {
			if redHatSnapshotComplete(source, rejected) {
				t.Fatalf("%s %s accepted unbounded rejected document", test.distro, test.release)
			}
		}
	}
}

func TestRedHatCrossYearIndexClosurePreservesPublisherPaths(t *testing.T) {
	stager := snapshotStager(t)
	paths := []string{"2002/rhsa-2001_164.json", "2006/rhba-2007_0331.json"}
	checkpoint := &redHatCheckpoint{
		distribution: "advisories",
		index:        []byte(strings.Join(paths, "\n") + "\n"),
		changes: []byte("\"2002/rhsa-2001_164.json\",\"2026-10-01T00:00:00Z\"\n" +
			"\"2006/rhba-2007_0331.json\",\"2026-10-01T00:00:00Z\"\n"),
	}
	if err := checkpoint.stage(t.Context(), stager); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	for _, indexed := range paths {
		if use, err := checkpoint.archived(t.Context(), stager, indexed, at); err != nil || !use {
			t.Fatalf("publisher path %s rejected: use=%v err=%v", indexed, use, err)
		}
		digest := sha256.Sum256([]byte(indexed))
		if err := checkpoint.record(t.Context(), stager, indexed, digest[:]); err != nil {
			t.Fatal(err)
		}
	}
	if use, err := checkpoint.archived(t.Context(), stager, "2001/rhsa-2001_164.json", at); err != nil || use {
		t.Fatalf("invented identity-year path admitted: use=%v err=%v", use, err)
	}
	summary, err := checkpoint.summary(t.Context(), stager)
	if err != nil || summary.GetDocumentCount() != 2 || len(summary.GetDocumentManifestSha256()) != sha256.Size {
		t.Fatalf("cross-year closure summary=%v err=%v", summary, err)
	}
}
