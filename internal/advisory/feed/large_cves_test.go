// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

func TestLargestRealUbuntuKernelNoticePreservesCVEs(t *testing.T) {
	raw := fixture(t, "ubuntu-USN-8728-1.json")
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "e3ac740c07cc0c15e50c63bfc71cf235070eaf1b4cc9125c15dfae0dc88f5a54" {
		t.Fatal("vendor fixture bytes changed")
	}
	config := source("ubuntu", "24.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP)
	count := 0
	doc, err := ParseStream(t.Context(), config, bytes.NewReader(osvZip(t, map[string][]byte{"USN-8728-1.json": raw}, zip.Store)), func(record *advisoryv1.Advisory) error {
		count++
		if record.Id != "USN-8728-1" || len(record.Cves) != 1416 || record.AssessmentUnknown || record.SourceRecordRejected {
			t.Fatalf("legitimate kernel notice degraded: id=%s cves=%d unknown=%t rejected=%t", record.Id, len(record.Cves), record.AssessmentUnknown, record.SourceRecordRejected)
		}
		return nil
	}, nil)

	if err != nil {
		t.Fatal(err)
	}
	if count == 0 || len(doc.RejectedRecords) != 0 {
		t.Fatalf("largest real notice rejected: count=%d rejections=%v", count, doc.RejectedRecords)
	}
}
