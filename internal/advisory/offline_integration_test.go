// SPDX-License-Identifier: Apache-2.0

//go:build integration

package advisory

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	"lindm/internal/advisory/advisorydb"
	"lindm/internal/testdb"
)

func TestImportSnapshotFreshnessAndMonotonicity(t *testing.T) {
	pool, _ := testdb.Open(t)
	s, source, doc := vendorService(t, pool, "fedora", "44", "synthetic-fedora44-updateinfo.xml")
	raw, err := os.ReadFile("feed/testdata/synthetic-fedora44-updateinfo.xml")
	if err != nil {
		t.Fatal(err)
	}
	// The same synthetic complete wrapper vendorService pins.
	raw = append(append([]byte("<updates>"), raw...), []byte("</updates>")...)
	digest := sha256.Sum256(raw)
	now := time.Now().UTC().Truncate(time.Microsecond)
	s.clock = func() time.Time { return now }
	maxAge := time.Duration(source.GetMaxAgeSeconds()) * time.Second
	snapshot := func(acquired time.Time, config *advisoryv1.FeedSource) Snapshot {
		return Snapshot{
			Source:     config,
			Input:      bytes.NewReader(raw),
			AcquiredAt: acquired,
			Artifacts:  []*advisoryv1.FeedArtifact{{Url: source.GetUrl(), Sha256: digest[:]}},
		}
	}

	newer := now.Add(-time.Hour)
	if err := s.ImportSnapshot(t.Context(), snapshot(newer, source)); err != nil {
		t.Fatal(err)
	}
	row, err := advisorydb.New(pool).GetAdvisoryFeed(t.Context(), source.Id)
	if err != nil {
		t.Fatal(err)
	}
	if !row.CheckedAt.Time.Equal(newer) || !row.ExpiresAt.Time.Equal(newer.Add(maxAge)) {
		t.Fatalf("checked_at %v expires_at %v; want %v and %v", row.CheckedAt.Time, row.ExpiresAt.Time, newer, newer.Add(maxAge))
	}
	if row.CompleteSnapshot != doc.GetCompleteSnapshot() || !row.CompleteSnapshot {
		t.Fatalf("coverage %v; parser established %v", row.CompleteSnapshot, doc.GetCompleteSnapshot())
	}
	if row.AttemptedAt.Valid || row.RequestRetryCount != 0 || row.VendorRaceRefetchCount != 0 {
		t.Fatalf("offline snapshot invented a network refresh attempt: %+v", row)
	}

	for name, acquired := range map[string]time.Time{
		"stale":  now.Add(-maxAge),
		"future": now.Add(time.Second),
	} {
		if err := s.ImportSnapshot(t.Context(), snapshot(acquired, source)); !errors.Is(err, ErrStale) {
			t.Fatalf("%s snapshot: %v", name, err)
		}
	}
	mismatched := proto.CloneOf(source)
	mismatched.MaxAgeSeconds++
	if err := s.ImportSnapshot(t.Context(), snapshot(newer, mismatched)); !errors.Is(err, ErrConflict) {
		t.Fatalf("mismatched source: %v", err)
	}
	unknown := proto.CloneOf(source)
	unknown.Id = "unknown"
	if err := s.ImportSnapshot(t.Context(), snapshot(newer, unknown)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown source: %v", err)
	}
	wrong := snapshot(newer, source)
	wrong.Artifacts = []*advisoryv1.FeedArtifact{{Url: source.GetUrl(), Sha256: make([]byte, sha256.Size)}}
	if err := s.ImportSnapshot(t.Context(), wrong); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mismatched primary artifact: %v", err)
	}

	if err := s.ImportSnapshot(t.Context(), snapshot(newer.Add(-time.Minute), source)); err != nil {
		t.Fatal(err)
	}
	after, err := advisorydb.New(pool).GetAdvisoryFeed(t.Context(), source.Id)
	if err != nil {
		t.Fatal(err)
	}
	if !after.CheckedAt.Time.Equal(newer) || !after.ExpiresAt.Time.Equal(newer.Add(maxAge)) || after.Revision != row.Revision {
		t.Fatalf("older snapshot replaced newer publication: %v", after)
	}

	for index, newerAttempt := range []bool{false, true} {
		acquired := newer.Add(time.Duration(index+1) * time.Minute)
		attempted := acquired.Add(-time.Second)
		wantError := ""
		if newerAttempt {
			attempted = acquired.Add(time.Second)
			wantError = "refresh_failed"
		}
		if _, err := pool.Exec(t.Context(), "UPDATE advisory_feeds SET attempted_at=$2,request_retry_count=7,vendor_race_refetch_count=9,error='refresh_failed' WHERE id=$1", source.Id, attempted); err != nil {
			t.Fatal(err)
		}
		if err := s.ImportSnapshot(t.Context(), snapshot(acquired, source)); err != nil {
			t.Fatal(err)
		}
		row, err := advisorydb.New(pool).GetAdvisoryFeed(t.Context(), source.Id)
		if err != nil {
			t.Fatal(err)
		}
		if row.RequestRetryCount != 7 || row.VendorRaceRefetchCount != 9 || !row.AttemptedAt.Valid || !row.AttemptedAt.Time.Equal(attempted) || row.Error != wantError || !row.CheckedAt.Time.Equal(acquired) {
			t.Fatalf("offline publication changed latest-refresh accounting or error fence (newer=%v): %+v", newerAttempt, row)
		}
	}
}
