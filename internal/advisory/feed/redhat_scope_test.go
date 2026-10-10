package feed

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/klauspost/compress/zstd"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

func TestRedHatStreamScopesMetadataPolicyWithoutAcceptingRelevantUnsupportedDocuments(t *testing.T) {
	// The signed weekly distribution contains RHSA-2006:0661 as a final
	// csaf_informational_advisory with no vulnerabilities and only RHEL 3/4
	// products. Its category is not authority for a configured RHEL 9 host.
	// Mutations exercise off-scope filtering without accepting malformed or
	// unsupported metadata for an applicable product.
	validator := redHatValidator(t)
	for _, test := range []struct {
		name   string
		mutate func(*suseCSAF)
	}{
		{"informational-with-null-vulnerabilities", func(notice *suseCSAF) {
			notice.Document.Category = "csaf_informational_advisory"
			notice.Vulnerabilities = nil
		}},
		{"unsupported-category", func(notice *suseCSAF) { notice.Document.Category = "csaf_unsupported" }},
		{"unsupported-version", func(notice *suseCSAF) { notice.Document.Version = "1.0" }},
		{"draft", func(notice *suseCSAF) { notice.Document.Tracking.Status = "draft" }},
		{"nonvendor-publisher", func(notice *suseCSAF) { notice.Document.Publisher.Category = "other" }},
		{"foreign-publisher", func(notice *suseCSAF) { notice.Document.Publisher.Namespace = "https://example.com" }},
		{"invalid-publication-time", func(notice *suseCSAF) { notice.Document.Tracking.Published = "invalid" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var notice suseCSAF
			if err := json.Unmarshal(redHatFixture(t, "rhsa-2024_6783"), &notice); err != nil {
				t.Fatal(err)
			}
			test.mutate(&notice)
			raw, err := json.Marshal(notice)
			if err != nil {
				t.Fatal(err)
			}
			for _, release := range []string{"8.8", "9.4"} {
				t.Run(release, func(t *testing.T) {
					calls := 0
					doc, err := stageRedHatStream(t.Context(), redHatSource(release, "standard"), validator, bytes.NewReader(raw), func(*advisoryv1.Advisory) error {
						calls++
						return nil
					})
					if doc != nil || calls != 0 || err == nil {
						t.Fatalf("unsupported document emitted claims: doc=%v calls=%d err=%v", doc, calls, err)
					}
					if offScope := errors.Is(err, errRedHatNotApplicable); offScope != (release == "8.8") {
						t.Fatalf("metadata policy crossed product scope: release=%s err=%v", release, err)
					}
				})
			}
		})
	}
}

func TestRedHatGenuineInformationalAdvisoryContributesNoClaims(t *testing.T) {
	raw := redHatFixture(t, "rhsa-2023_6529")
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "77457519f52e8451607b3448253b7eaadf3ad5845c43b5a45f4c5dcd4f10a001" {
		t.Fatal("retained informational advisory differs from the signed archive member")
	}
	config := redHatSource("9.4", "standard")
	validator := redHatValidator(t)
	calls := 0
	doc, err := stageRedHatStream(t.Context(), config, validator, bytes.NewReader(raw), func(*advisoryv1.Advisory) error {
		calls++
		return nil
	})
	if !errors.Is(err, errRedHatNotApplicable) || doc != nil || calls != 0 {
		t.Fatalf("informational document gained vulnerability authority: doc=%v calls=%d err=%v", doc, calls, err)
	}

	// The same real informational member must not poison another document's
	// claims when encountered in the authenticated distribution.
	var compressed bytes.Buffer
	z, err := zstd.NewWriter(&compressed, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	archive := tar.NewWriter(z)
	for _, name := range []string{"rhsa-2023_6529", "rhsa-2024_6783"} {
		body := redHatFixture(t, name)
		if err := archive.WriteHeader(&tar.Header{Name: name + ".json", Typeflag: tar.TypeReg, Mode: 0600, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	doc, err = parseRedHatArchive(t.Context(), config, bytes.NewReader(compressed.Bytes()), validator)
	if err != nil {
		t.Fatal(err)
	}
	record := redHatRecord(t, doc, "openssl-libs", "CVE-2024-6119", "", false)
	if record.FixedVersion != "1:3.0.7-28.el9_4" || doc.CompleteSnapshot {
		t.Fatalf("informational member changed security-advisory authority: %v", doc)
	}
}

func TestRedHatInformationalProfileRejectsVulnerabilitiesAndMalformedTree(t *testing.T) {
	validator := redHatValidator(t)
	for _, test := range []struct {
		name, key, value string
	}{
		{"null", "vulnerabilities", "null"},
		{"empty", "vulnerabilities", "[]"},
		{"nonempty", "vulnerabilities", `[{"cve":"CVE-2024-6119"}]`},
		{"wrong-type", "vulnerabilities", "{}"},
		{"missing-root", "product_tree", `{"branches":[]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var document map[string]json.RawMessage
			if err := json.Unmarshal(redHatFixture(t, "rhsa-2023_6529"), &document); err != nil {
				t.Fatal(err)
			}
			document[test.key] = json.RawMessage(test.value)
			raw, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			doc, err := stageRedHatStream(t.Context(), redHatSource("9.4", "standard"), validator, bytes.NewReader(raw), func(*advisoryv1.Advisory) error {
				calls++
				return nil
			})
			if err == nil || errors.Is(err, errRedHatNotApplicable) || doc != nil || calls != 0 {
				t.Fatalf("malformed informational profile suppressed: doc=%v calls=%d err=%v", doc, calls, err)
			}
		})
	}
}
