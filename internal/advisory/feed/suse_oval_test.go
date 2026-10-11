package feed

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

func ovalSource(arch string) *advisoryv1.FeedSource {
	return &advisoryv1.FeedSource{Id: "tumbleweed", Distro: "opensuse-tumbleweed", Release: "rolling", Architecture: arch, Url: "https://ftp.suse.com/pub/projects/security/oval/opensuse.tumbleweed.xml.gz", Format: advisoryv1.FeedFormat_FEED_FORMAT_SUSE_OVAL, MaxAgeSeconds: 604800}
}

func ovalCompressed(t *testing.T, raw []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	z := gzip.NewWriter(&out)
	if _, err := z.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestSUSEOVALRetainsNativeProductAndAllInstances(t *testing.T) {
	raw := fixture(t, "suse-tumbleweed-subset.xml")
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "c9c3e7e57b424f0bc16df400831fc7e5be1344da6ae899b87dd73d53a6ad2b42" {
		t.Fatal("projected vendor record bytes changed")
	}
	for _, arch := range []string{"x86_64", "aarch64"} {
		t.Run(arch, func(t *testing.T) {
			compressed := ovalCompressed(t, raw)
			var records []*advisoryv1.Advisory
			doc, err := ParseStream(t.Context(), ovalSource(arch), bytes.NewReader(compressed), func(a *advisoryv1.Advisory) error { records = append(records, a); return nil }, nil)
			if err != nil {
				t.Fatal(err)
			}
			wantTime := time.Date(2026, 10, 9, 17, 30, 35, 0, time.UTC)
			if doc.GetCompleteSnapshot() || len(records) != 8 || !doc.GetSnapshotAt().AsTime().Equal(wantTime) {
				t.Fatalf("lost partial coverage or conservative generation time: claims=%d doc=%v", len(records), doc)
			}
			compressedDigest := sha256.Sum256(compressed)
			if !bytes.Equal(doc.SourceSha256, compressedDigest[:]) || len(doc.Artifacts) != 1 || doc.Artifacts[0].SignerFingerprint != "" {
				t.Fatalf("wrong byte custody or invented signature: %v", doc)
			}
			for _, record := range records {
				if record.Architecture != arch || record.PrerequisitePackage != "openSUSE-release" || record.PrerequisiteMinVersion != "0:20210101-0" {
					t.Fatalf("lost native applicability: %v", record)
				}
				kernel := strings.HasPrefix(record.PackageName, "kernel-source")
				if record.AllInstalledInstances != kernel || kernel && len(record.InstanceArchitectures) != 4 {
					t.Fatalf("lost all-instances semantics: %v", record)
				}
			}
		})
	}
}

func TestSUSEOVALRejectsApplicabilityChanges(t *testing.T) {
	raw := string(fixture(t, "suse-tumbleweed-subset.xml"))
	for _, test := range []struct{ name, from, to string }{
		{"product", "cpe:/o:opensuse:tumbleweed", "cpe:/o:opensuse:leap:16.0"},
		{"negation", "<criteria operator=\"AND\">", "<criteria operator=\"AND\" negate=\"true\">"},
		{"conjunction", "<criteria operator=\"OR\">", "<criteria operator=\"AND\">"},
		{"unknown-check", "check=\"all\"", "check=\"none satisfy\""},
		{"product-boundary", "operation=\"greater than or equal\"", "operation=\"less than\""},
		{"package-boundary", "operation=\"less than\"", "operation=\"not equal\""},
		{"object-variable", "<name>tar</name>", "<name var_ref=\"unknown\">tar</name>"},
		{"regex", "(aarch64|ppc64le|s390x|x86_64)", ".*"},
		{"foreign-namespace", "oval-definitions-5#linux", "oval-definitions-5#foreign"},
		{"missing-reference", "test_ref=\"oval:org.opensuse.security:tst:2009634834\"", "test_ref=\"missing\""},
		{"trailing", "</oval_definitions>", "</oval_definitions><extra/>"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if !strings.Contains(raw, test.from) {
				t.Fatal("mutation target missing")
			}
			changed := strings.ReplaceAll(raw, test.from, test.to)
			_, err := ParseStream(t.Context(), ovalSource("x86_64"), bytes.NewReader(ovalCompressed(t, []byte(changed))), func(*advisoryv1.Advisory) error { return nil }, nil)
			if err == nil {
				t.Fatal("unsupported applicability accepted")
			}
		})
	}
}

func TestSUSEOVALPinsCancellationAndClaimBound(t *testing.T) {
	compressed := ovalCompressed(t, fixture(t, "suse-tumbleweed-subset.xml"))
	config := ovalSource("x86_64")
	config.ExpectedSha256 = make([]byte, sha256.Size)
	calls := 0
	consume := func(*advisoryv1.Advisory) error { calls++; return nil }
	if _, err := ParseStream(t.Context(), config, bytes.NewReader(compressed), consume, nil); err == nil || calls != 0 {
		t.Fatalf("pin checked after publication: calls=%d err=%v", calls, err)
	}
	config.ExpectedSha256 = nil
	limit := uint64(1)
	config.TotalClaimsLimit = &limit
	if _, err := ParseStream(t.Context(), config, bytes.NewReader(compressed), consume, nil); err == nil {
		t.Fatal("claim bound ignored")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := ParseStream(ctx, config, bytes.NewReader(compressed), consume, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}
