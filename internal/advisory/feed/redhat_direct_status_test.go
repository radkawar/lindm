// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

func TestRedHatGenuineVEXDirectOffScopeStatus(t *testing.T) {
	raw := redHatFixture(t, "cve-2002-0059")
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "e95683aa7013ca999b984ee6c048fb9b8737a9b088ec104e23bbd8ccdeb4f512" {
		t.Fatal("retained VEX differs from the original vendor document")
	}
	trust, err := newVendorTrust()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := trust.verify(t.Context(), redHatFingerprint, bytes.NewReader(raw), fixture(t, "redhat-cve-2002-0059.json.asc"), time.Now()); err != nil {
		t.Fatalf("retained vendor VEX signature: %v", err)
	}
	checksum, err := vendorChecksum(fixture(t, "redhat-cve-2002-0059.json.sha256"), "https://security.access.redhat.com/data/csaf/v2/vex/2002/cve-2002-0059.json")
	if err != nil || !bytes.Equal(checksum, digest[:]) {
		t.Fatalf("retained vendor VEX checksum: %x, %v", checksum, err)
	}
	var claims advisoryv1.FeedDocument
	_, err = stageRedHatStream(t.Context(), redHatSource("9.4", "standard"), redHatValidator(t), bytes.NewReader(raw), func(record *advisoryv1.Advisory) error {
		claims.Advisories = append(claims.Advisories, record)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(claims.Advisories) != 4 {
		t.Fatalf("off-scope historical platform fixes changed RHEL 9 claims: %d", len(claims.Advisories))
	}
	for _, test := range []struct {
		name   string
		source bool
	}{{"zlib", false}, {"zlib-devel", false}, {"zlib-static", false}, {"zlib", true}} {
		record := redHatRecord(t, &claims, test.name, "CVE-2002-0059", "", test.source)
		if !record.NotAffected || record.AssessmentUnknown || record.FixedVersion != "" {
			t.Fatalf("direct legacy fix displaced authoritative package not-affected: %v", record)
		}
	}
}

func TestRedHatDirectStatusRequiresProvenOffScopeIdentity(t *testing.T) {
	validator := redHatValidator(t)
	for _, test := range []struct {
		name, status, id, cpe string
		valid                 bool
	}{
		{"declared-legacy-fixed", "fixed", "Red Hat Linux 6.2", "", true},
		{"declared-legacy-unknown-status", "first_affected", "Red Hat Linux 6.2", "", true},
		{"missing-product", "fixed", "missing-product", "", false},
		{"unbound-rpm", "known_not_affected", "zlib", "", false},
		{"relevant-platform-negative", "known_not_affected", "red_hat_enterprise_linux_9", "", false},
		{"relevant-platform-fixed", "fixed", "red_hat_enterprise_linux_9", "", false},
		{"relevant-platform-affected", "known_affected", "red_hat_enterprise_linux_9", "", false},
		{"relevant-platform-investigation", "under_investigation", "red_hat_enterprise_linux_9", "", false},
		{"relevant-platform-unknown-status", "first_affected", "red_hat_enterprise_linux_9", "", false},
		{"nonnative-any-version", "fixed", "Red Hat Linux 6.2", "cpe:/a:redhat:red_hat_single_sign_on", true},
		{"nonnative-empty-version", "fixed", "Red Hat Linux 6.2", "cpe:/a:redhat:red_hat_single_sign_on:", true},
		{"nonnative-uppercase-version", "fixed", "Red Hat Linux 6.2", "cpe:/a:redhat:amq_clients:2026.Q3", true},
		{"native-case-ambiguity", "fixed", "Red Hat Linux 6.2", "cpe:/o:redhat:Enterprise_Linux:9", false},
		{"native-nonnumeric-version", "fixed", "Red Hat Linux 6.2", "cpe:/o:redhat:enterprise_linux:9.Q3", false},
		{"native-empty-version", "fixed", "Red Hat Linux 6.2", "cpe:/o:redhat:enterprise_linux:", false},
		{"native-any-version", "fixed", "Red Hat Linux 6.2", "cpe:/o:redhat:enterprise_linux", false},
		{"escaped-cpe", "fixed", "Red Hat Linux 6.2", "cpe:/o:redhat:enterprise_linux:%39", false},
		{"unknown-native-release", "fixed", "Red Hat Linux 6.2", "cpe:/o:redhat:enterprise_linux:unknown", false},
		{"relevant-unknown-edition", "fixed", "Red Hat Linux 6.2", "cpe:/o:redhat:enterprise_linux:9::unsupported", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var notice suseCSAF
			if err := json.Unmarshal(redHatFixture(t, "cve-2002-0059"), &notice); err != nil {
				t.Fatal(err)
			}
			if test.cpe != "" && !redHatReplaceProductCPE(notice.Tree.Branches, test.id, test.cpe) {
				t.Fatal("missing mutation target")
			}
			notice.Vulnerabilities[0].Status[test.status] = append(notice.Vulnerabilities[0].Status[test.status], test.id)
			raw, err := json.Marshal(notice)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			doc, err := stageRedHatStream(t.Context(), redHatSource("9.4", "standard"), validator, bytes.NewReader(raw), func(*advisoryv1.Advisory) error {
				calls++
				return nil
			})
			if test.valid {
				if err != nil || doc == nil || calls != 4 {
					t.Fatalf("proven off-scope product poisoned native claims: calls=%d err=%v", calls, err)
				}
				return
			}
			if err != nil || doc == nil || calls != 0 || len(doc.RejectedRecords) != 1 || !doc.RejectedRecords[0].Unscoped {
				t.Fatalf("unscoped or relevant status gained clean authority: doc=%v calls=%d err=%v", doc, calls, err)
			}
		})
	}
}

func redHatReplaceProductCPE(branches []suseBranch, id, cpe string) bool {
	for i := range branches {
		if product := branches[i].Product; product != nil && product.ID == id {
			product.Helper.CPE = cpe
			return true
		}
		if redHatReplaceProductCPE(branches[i].Branches, id, cpe) {
			return true
		}
	}
	return false
}

func TestRedHatGenuineVEXVersionlessLayeredProduct(t *testing.T) {
	raw := redHatFixture(t, "cve-2020-25649")
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "0a7e085939a42fa85359f91dc5e1fc76b8166d4bdf80d8c1f0660dc3efd7c37d" {
		t.Fatal("retained versionless-product VEX differs from original vendor bytes")
	}
	trust, err := newVendorTrust()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := trust.verify(t.Context(), redHatFingerprint, bytes.NewReader(raw), fixture(t, "redhat-cve-2020-25649.json.asc"), time.Now()); err != nil {
		t.Fatalf("retained vendor VEX signature: %v", err)
	}
	checksum, err := vendorChecksum(fixture(t, "redhat-cve-2020-25649.json.sha256"), "https://security.access.redhat.com/data/csaf/v2/vex/2020/cve-2020-25649.json")
	if err != nil || !bytes.Equal(checksum, digest[:]) {
		t.Fatalf("retained vendor VEX checksum: %x, %v", checksum, err)
	}
	var claims advisoryv1.FeedDocument
	_, err = stageRedHatStream(t.Context(), redHatSource("9.4", "standard"), redHatValidator(t), bytes.NewReader(raw), func(record *advisoryv1.Advisory) error {
		claims.Advisories = append(claims.Advisories, record)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(claims.Advisories) != 2 {
		t.Fatalf("layered versionless product changed RHEL 9 claims: %d", len(claims.Advisories))
	}
	for _, test := range []struct {
		name   string
		source bool
	}{{"jackson-databind", true}, {"pki-jackson-databind", false}} {
		record := redHatRecord(t, &claims, test.name, "CVE-2020-25649", "", test.source)
		if !record.NotAffected || record.AssessmentUnknown || record.FixedVersion != "" {
			t.Fatalf("layered product fix displaced native package not-affected: %v", record)
		}
	}
}
