package feed

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

func TestRedHatRPMNameUsesSinglePathDecoding(t *testing.T) {
	for _, test := range []struct {
		name, encoded string
		valid         bool
	}{
		{"escaped-plus", "gnutls-c%2B%2B", true},
		{"literal-plus", "gnutls-c++", true},
		{"lowercase-hex", "gnutls-c%2b%2b", true},
		{"double-encoding", "gnutls-c%252B%252B", false},
		{"escaped-slash", "gnutls-c%2F%2B", false},
		{"invalid-encoding", "gnutls-c%2X%2B", false},
		{"truncated-encoding", "gnutls-c%2", false},
		{"escaped-space", "gnutls-c%20%2B", false},
		{"escaped-at", "gnutls-c%40%2B", false},
		{"identity-mismatch", "gnutls-c%2B", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			component := redHatProduct{arch: "x86_64"}
			component.product.Name = "gnutls-c++-0:3.7.6-12.el9_0.x86_64"
			component.product.Helper.PURL = "pkg:rpm/redhat/" + test.encoded + "@3.7.6-12.el9_0?arch=x86_64"
			pkg, err := redHatPackage(component)
			if !test.valid {
				if err == nil {
					t.Fatalf("invalid or mismatched native name accepted: %+v", pkg)
				}
				return
			}
			if err != nil || pkg.name != "gnutls-c++" || pkg.version != "0:3.7.6-12.el9_0" || pkg.arch != "x86_64" {
				t.Fatalf("normative PURL path decoding changed RPM identity: %+v, %v", pkg, err)
			}
		})
	}
}

func TestRedHatGenuineEscapedRPMName(t *testing.T) {
	raw := redHatFixture(t, "rhsa-2022_6854")
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "e8195ce6334f405c4401e413feb7843be1cb147e99f689473a53788cd4e07fea" {
		t.Fatal("retained RPM advisory differs from signed archive member")
	}
	var claims advisoryv1.FeedDocument
	_, err := stageRedHatStream(t.Context(), redHatSource("9.4", "standard"), redHatValidator(t), bytes.NewReader(raw), func(record *advisoryv1.Advisory) error {
		claims.Advisories = append(claims.Advisories, record)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	record := redHatRecord(t, &claims, "gnutls-c++", "CVE-2022-2509", "", false)
	if record.FixedVersion != "0:3.7.6-12.el9_0" || record.Architecture != "x86_64" || record.PlatformStream != "standard" || record.AssessmentUnknown {
		t.Fatalf("genuine encoded package name lost native applicability: %v", record)
	}
}
