//go:build integration

package advisory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	advisoryv1 "lindm/gen/lindm/advisory/v1"
	configv1 "lindm/gen/lindm/config/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/advisory/advisorydb"
	"lindm/internal/advisory/feed"
	"lindm/internal/testdb"
)

// These controlled normalized claims exercise real PostgreSQL COPY, publication
// visibility and findings. They do not claim native package or vendor execution.
func TestAdvisoryStreamPublicationBatchBoundaries(t *testing.T) {
	for _, count := range []int{499, 500, 501, 1001} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			f := newStreamPublicationFixture(t)
			doc := f.document("boundary")
			err := f.service.publishStream(t.Context(), f.source, f.before.CheckedAt.Time.Add(time.Second), func(_ context.Context, emit func(*advisoryv1.Advisory) error, _ func() error) (*advisoryv1.FeedDocument, error) {
				if err := f.emit("boundary", 0, count, emit); err != nil {
					return nil, err
				}
				return doc, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			f.assertPublished(t, "boundary", count)
			f.assertStorage(t, int64(count), int64(count), 0)
		})
	}
}

func TestAdvisoryStreamPublicationDeduplicatesAcrossBatches(t *testing.T) {
	f := newStreamPublicationFixture(t)
	doc := f.document("duplicates")
	err := f.service.publishStream(t.Context(), f.source, f.before.CheckedAt.Time.Add(time.Second), func(_ context.Context, emit func(*advisoryv1.Advisory) error, _ func() error) (*advisoryv1.FeedDocument, error) {
		// Each of the first two COPY batches contains the same 500 claims.
		for range 2 {
			if err := f.emit("duplicates", 0, 500, emit); err != nil {
				return nil, err
			}
		}
		// The final partial batch mixes duplicates with one genuinely new claim.
		for _, index := range []int{0, 499, 500} {
			if err := emit(f.claim("duplicates", index)); err != nil {
				return nil, err
			}
		}
		return doc, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	f.assertPublished(t, "duplicates", 501)
	f.assertStorage(t, 501, 501, 0)
}

func TestAdvisoryStreamPublicationStagesInvisiblyThenSwitches(t *testing.T) {
	f := newStreamPublicationFixture(t)
	release, _, result := f.startBlocked(t, "replacement", 1001, 500, nil)

	// A separate connection can see the committed staging batch, but legacy
	// advisory_records readers and device findings still see only the old feed.
	f.assertStorage(t, f.before.AdvisoryCount, f.before.AdvisoryCount+500, 500)
	f.assertUnchanged(t, f.before, f.findings)

	close(release)
	if err := awaitStreamPublication(t, result); err != nil {
		t.Fatal(err)
	}
	f.assertPublished(t, "replacement", 1001)
	f.assertStorage(t, 1001, 1001, 0)
	findings := f.listFindings(t)
	if len(findings.Findings) != 1 || findings.Findings[0].AdvisoryId != f.claim("replacement", 0).Id || findings.Findings[0].State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED {
		t.Fatalf("successful switch did not replace the old device finding: %v", findings)
	}
}

func TestAdvisoryStreamPublicationFailurePreservesActiveGeneration(t *testing.T) {
	producerErr := errors.New("controlled producer failure after partial COPY")
	for _, canceled := range []bool{false, true} {
		name := "producer-error"
		if canceled {
			name = "cancellation"
		}
		t.Run(name, func(t *testing.T) {
			f := newStreamPublicationFixture(t)
			failure := producerErr
			if canceled {
				failure = nil
			}
			release, cancel, result := f.startBlocked(t, "failed", 1001, 1000, failure)
			f.assertStorage(t, f.before.AdvisoryCount, f.before.AdvisoryCount+1000, 1000)
			f.assertUnchanged(t, f.before, f.findings)
			wantErr := producerErr
			if canceled {
				cancel()
				wantErr = context.Canceled
			} else {
				close(release)
			}
			if err := awaitStreamPublication(t, result); !errors.Is(err, wantErr) {
				t.Fatalf("publication error = %v, want %v", err, wantErr)
			}
			f.assertUnchanged(t, f.before, f.findings)
			f.assertStorage(t, f.before.AdvisoryCount, f.before.AdvisoryCount, 0)
		})
	}
}

// The watchdog aborts only when work stops: marked progress outlives several
// idle windows, then a silent producer is cancelled with the stall cause.
func TestAdvisoryStreamPublicationProgressWatchdog(t *testing.T) {
	f := newStreamPublicationFixture(t)
	source := proto.CloneOf(f.source)
	source.ProgressTimeoutSeconds = proto.Uint32(1)
	service, err := New(t.Context(), f.pool, &configv1.AdvisoryConfig{Feeds: []*advisoryv1.FeedSource{source}}, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	marked := 0
	err = service.publishStream(t.Context(), source, f.before.CheckedAt.Time.Add(time.Second), func(ctx context.Context, emit func(*advisoryv1.Advisory) error, progress func() error) (*advisoryv1.FeedDocument, error) {
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
			if err := progress(); err != nil {
				return nil, err
			}
			marked++
		}
		if err := f.emit("stalled", 0, 501, emit); err != nil {
			return nil, err
		}
		<-ctx.Done()
		return nil, context.Cause(ctx)
	})
	if !errors.Is(err, feed.ErrRefreshStalled) || marked < 10 {
		t.Fatalf("watchdog error = %v after %d marks, want stall after sustained progress", err, marked)
	}
	// Reconfiguration retired the fixture generation; the aborted staging
	// generation, including its committed batch, must not survive either.
	f.assertStorage(t, 0, 0, 0)
}

func TestAdvisoryStreamPublicationFencesInFlightWriters(t *testing.T) {
	for _, reconfigure := range []bool{false, true} {
		name := "newer-publication"
		if reconfigure {
			name = "changed-configuration"
		}
		t.Run(name, func(t *testing.T) {
			f := newStreamPublicationFixture(t)
			release, _, result := f.startBlocked(t, "obsolete", 501, 500, nil)
			f.assertStorage(t, f.before.AdvisoryCount, f.before.AdvisoryCount+500, 500)
			f.assertUnchanged(t, f.before, f.findings)

			winner, source := f.service, f.source
			if reconfigure {
				source = proto.CloneOf(f.source)
				source.MaxAgeSeconds /= 2
				var err error
				winner, err = New(t.Context(), f.pool, &configv1.AdvisoryConfig{Feeds: []*advisoryv1.FeedSource{source}}, http.DefaultClient)
				if err != nil {
					t.Fatal(err)
				}
			}
			err := winner.publishStream(t.Context(), source, f.before.CheckedAt.Time.Add(2*time.Second), func(_ context.Context, emit func(*advisoryv1.Advisory) error, _ func() error) (*advisoryv1.FeedDocument, error) {
				if err := f.emit("winner", 0, 501, emit); err != nil {
					return nil, err
				}
				return f.document("winner"), nil
			})
			if err != nil {
				t.Fatal(err)
			}
			f.assertPublished(t, "winner", 501)
			// Cleaning the superseded active generation must not delete another
			// writer's still-in-flight staging generation.
			f.assertStorage(t, 501, 1001, 500)
			published := f.feed(t)
			findings := f.listFindings(t)
			if len(findings.Findings) != 1 || findings.Findings[0].AdvisoryId != f.claim("winner", 0).Id {
				t.Fatalf("newer publication did not replace findings: %v", findings)
			}

			close(release)
			err = awaitStreamPublication(t, result)
			if reconfigure {
				if !errors.Is(err, ErrConflict) {
					t.Fatalf("obsolete configuration returned %v, want ErrConflict", err)
				}
			} else if err != nil {
				t.Fatalf("stale publication was not a no-op: %v", err)
			}
			f.assertUnchanged(t, published, findings)
			f.assertPublished(t, "winner", 501)
			f.assertStorage(t, 501, 501, 0)
		})
	}
}

type streamPublicationFixture struct {
	pool     *pgxpool.Pool
	service  *Service
	source   *advisoryv1.FeedSource
	original *advisoryv1.FeedDocument
	template *advisoryv1.Advisory
	deviceID uuid.UUID
	before   advisorydb.AdvisoryFeed
	findings *adminv1.ListDeviceFindingsResponse
}

func newStreamPublicationFixture(t *testing.T) *streamPublicationFixture {
	t.Helper()
	pool, _ := testdb.Open(t)
	s, source, doc := vendorService(t, pool, "fedora", "44", "fedora44-sudo.xml")
	f := &streamPublicationFixture{pool: pool, service: s, source: source, original: doc}
	for _, claim := range doc.Advisories {
		if claim.PackageName == "sudo" && claim.Architecture == "x86_64" {
			f.template = claim
			break
		}
	}
	if f.template == nil {
		t.Fatal("vendor fixture has no x86_64 sudo claim")
	}
	if err := s.publish(t.Context(), source, doc, time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	f.deviceID = seedInventory(t, pool, "fedora", "44", &inventoryv1.Package{Name: "sudo", Version: "0:1.9.17-9.p2.fc44", Architecture: "x86_64", Manager: "rpm"})
	f.before = f.feed(t)
	f.findings = f.listFindings(t)
	if len(f.findings.Findings) != 1 || f.findings.Findings[0].State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED {
		t.Fatalf("initial publication has no affected package finding: %v", f.findings)
	}
	return f
}

func (f *streamPublicationFixture) document(label string) *advisoryv1.FeedDocument {
	digest := sha256.Sum256([]byte(label))
	return &advisoryv1.FeedDocument{SourceSha256: digest[:], CompleteSnapshot: f.original.CompleteSnapshot}
}

func (f *streamPublicationFixture) claim(label string, index int) *advisoryv1.Advisory {
	claim := proto.CloneOf(f.template)
	claim.Id = fmt.Sprintf("stream-%s-%04d", label, index)
	if index != 0 {
		claim.PackageName = fmt.Sprintf("stream-package-%04d", index)
	}
	return claim
}

func (f *streamPublicationFixture) emit(label string, first, end int, emit func(*advisoryv1.Advisory) error) error {
	for index := first; index < end; index++ {
		if err := emit(f.claim(label, index)); err != nil {
			return err
		}
	}
	return nil
}

func (f *streamPublicationFixture) feed(t *testing.T) advisorydb.AdvisoryFeed {
	t.Helper()
	current, err := advisorydb.New(f.pool).GetAdvisoryFeed(t.Context(), f.source.Id)
	if err != nil {
		t.Fatal(err)
	}
	return current
}

func (f *streamPublicationFixture) listFindings(t *testing.T) *adminv1.ListDeviceFindingsResponse {
	t.Helper()
	response, err := f.service.ListDevice(t.Context(), &adminv1.ListDeviceFindingsRequest{DeviceId: f.deviceID.String()}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func (f *streamPublicationFixture) assertUnchanged(t *testing.T, before advisorydb.AdvisoryFeed, findings *adminv1.ListDeviceFindingsResponse) {
	t.Helper()
	if after := f.feed(t); !reflect.DeepEqual(before, after) {
		t.Fatalf("incomplete publication changed the active feed: before=%+v after=%+v", before, after)
	}
	if after := f.listFindings(t); !proto.Equal(findings, after) {
		t.Fatalf("incomplete publication changed active findings: before=%v after=%v", findings, after)
	}
}

func (f *streamPublicationFixture) assertStorage(t *testing.T, visible, total, inactive int64) {
	t.Helper()
	var gotVisible, gotTotal, gotInactive, batchRows int64
	err := f.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM advisory_records WHERE feed_id=$1),
		(SELECT count(*) FROM advisory_record_generations WHERE feed_id=$1),
		(SELECT count(*) FROM advisory_record_generations r
		 LEFT JOIN advisory_feeds f ON f.id=r.feed_id AND f.revision=r.generation
		 WHERE r.feed_id=$1 AND f.id IS NULL),
		(SELECT count(*) FROM advisory_publication_batch)`, f.source.Id).Scan(&gotVisible, &gotTotal, &gotInactive, &batchRows)
	if err != nil {
		t.Fatal(err)
	}
	if gotVisible != visible || gotTotal != total || gotInactive != inactive || batchRows != 0 {
		t.Fatalf("publication rows: visible=%d total=%d inactive=%d batch=%d; want visible=%d total=%d inactive=%d batch=0", gotVisible, gotTotal, gotInactive, batchRows, visible, total, inactive)
	}
}

func (f *streamPublicationFixture) assertPublished(t *testing.T, label string, count int) {
	t.Helper()
	current := f.feed(t)
	if current.Revision == f.before.Revision || current.AdvisoryCount != int64(count) || !bytes.Equal(current.SourceSha256, f.document(label).SourceSha256) {
		t.Fatalf("publication revision, unique count or source digest was not replaced: %+v", current)
	}
	rows, err := f.pool.Query(t.Context(), "SELECT id,advisory_id,record_bytes FROM advisory_records WHERE feed_id=$1 ORDER BY advisory_id", f.source.Id)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	namespace := uuid.NewSHA1(uuid.NameSpaceOID, []byte(f.source.Id))
	index := 0
	for rows.Next() {
		var id uuid.UUID
		var advisoryID string
		var payload []byte
		if err := rows.Scan(&id, &advisoryID, &payload); err != nil {
			t.Fatal(err)
		}
		claim := f.claim(label, index)
		expected, err := proto.MarshalOptions{Deterministic: true}.Marshal(claim)
		if err != nil {
			t.Fatal(err)
		}
		if advisoryID != claim.Id || !bytes.Equal(payload, expected) || id != uuid.NewSHA1(namespace, expected) {
			t.Fatalf("claim %d lost its normalized payload or deterministic identity: id=%s advisory=%q", index, id, advisoryID)
		}
		index++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if index != count {
		t.Fatalf("visible claims = %d, want %d", index, count)
	}
}

func (f *streamPublicationFixture) startBlocked(t *testing.T, label string, count, pauseAfter int, producerErr error) (chan<- struct{}, context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	staged := make(chan struct{})
	release := make(chan struct{})
	result := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		result <- f.service.publishStream(ctx, f.source, f.before.CheckedAt.Time.Add(time.Second), func(_ context.Context, emit func(*advisoryv1.Advisory) error, _ func() error) (*advisoryv1.FeedDocument, error) {
			if err := f.emit(label, 0, pauseAfter, emit); err != nil {
				return nil, err
			}
			close(staged)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			if err := f.emit(label, pauseAfter, count, emit); err != nil {
				return nil, err
			}
			if producerErr != nil {
				return nil, producerErr
			}
			return f.document(label), nil
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("stream publication did not stop after cancellation")
		}
	})
	select {
	case <-staged:
	case err := <-result:
		t.Fatalf("publication stopped before staging the requested batch: %v", err)
	case <-ctx.Done():
		t.Fatalf("publication never reached its staging boundary: %v", ctx.Err())
	}
	return release, cancel, result
}

func awaitStreamPublication(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(30 * time.Second):
		t.Fatal("stream publication did not complete")
		return nil
	}
}
