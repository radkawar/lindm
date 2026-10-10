package feed

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

func TestOSVStreamRetainsMetadataNotClaims(t *testing.T) {
	config := source("ubuntu", "24.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP)
	raw := osvZip(t, map[string][]byte{"notice.json": fixture(t, "ubuntu-USN-6859-1.json"), "broken.json": rejectedUbuntuOSV(rejectedUbuntuID)}, zip.Store)
	var count, rejected int
	doc, err := ParseStream(t.Context(), config, bytes.NewReader(raw), func(record *advisoryv1.Advisory) error {
		count++
		if record.SourceRecordRejected {
			rejected++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count <= 2 || rejected != 2 || len(doc.Advisories) != 0 || len(doc.RejectedRecords) != 1 || len(doc.SourceSha256) != 32 {
		t.Fatalf("stream metadata/count = %v/%d/%d", doc, count, rejected)
	}
}

func TestOSVStreamConsumerFailureAndClaimCap(t *testing.T) {
	config := source("ubuntu", "24.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP)
	raw := osvZip(t, map[string][]byte{"notice.json": fixture(t, "ubuntu-USN-6859-1.json")}, zip.Store)
	failure := errors.New("staging unavailable")
	calls := 0
	doc, err := ParseStream(t.Context(), config, bytes.NewReader(raw), func(*advisoryv1.Advisory) error { calls++; return failure })
	if !errors.Is(err, failure) || doc != nil || calls != 1 {
		t.Fatalf("consumer failure suppressed/rejected: doc=%v calls=%d err=%v", doc, calls, err)
	}
	config.TotalClaimsLimit = proto.Uint64(1)
	calls = 0
	doc, err = ParseStream(t.Context(), config, bytes.NewReader(raw), func(*advisoryv1.Advisory) error { calls++; return nil })
	if err == nil || !strings.Contains(err.Error(), "total claims limit") || doc != nil || calls != 1 {
		t.Fatalf("claim cap: calls=%d err=%v", calls, err)
	}
	config.ExpectedSha256 = make([]byte, 32)
	calls = 0
	_, err = ParseStream(t.Context(), config, bytes.NewReader(raw), func(*advisoryv1.Advisory) error { calls++; return nil })
	if err == nil || calls != 0 {
		t.Fatalf("unverified claims emitted: %d %v", calls, err)
	}
}

func TestOSVStreamCancellation(t *testing.T) {
	config := source("ubuntu", "24.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP)
	raw := osvZip(t, map[string][]byte{"notice.json": fixture(t, "ubuntu-USN-6859-1.json"), "notice2.json": fixture(t, "ubuntu-USN-6859-1.json")}, zip.Store)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	_, err := ParseStream(ctx, config, bytes.NewReader(raw), func(*advisoryv1.Advisory) error { cancel(); return ctx.Err() })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation = %v", err)
	}
}
