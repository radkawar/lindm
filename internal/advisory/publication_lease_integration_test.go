// SPDX-License-Identifier: Apache-2.0
//go:build integration

package advisory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"lindm/internal/advisory/advisorydb"
	"lindm/internal/advisory/feed"
)

// COPY waits on a real table lock after the batch transaction has renewed and
// locked its own generation row. A heartbeat must not time out against that row
// and cancel its own batch, even when the batch takes longer than five seconds.
func TestAdvisoryPublicationHeartbeatWaitsForOwnBatch(t *testing.T) {
	f, stager, parent, cancel := newLeasePublicationFixture(t, 0)
	blocker, err := f.pool.Begin(parent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blocker.Exec(parent, "LOCK TABLE advisory_publication_batch IN SHARE MODE"); err != nil {
		_ = blocker.Rollback(context.Background())
		t.Fatal(err)
	}
	ctx, stopHeartbeat := f.service.startAdvisoryLeaseHeartbeat(parent, stager.generation, 10*time.Millisecond, &stager.lease)
	result := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		result <- stager.flush(ctx)
	}()
	defer func() {
		cancel()
		_ = blocker.Rollback(context.Background())
		stopHeartbeat()
		<-done
	}()

	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
waitForCopy:
	for {
		select {
		case <-deadline.C:
			t.Fatal("native COPY did not wait on the held PostgreSQL table lock")
		case err := <-result:
			t.Fatalf("batch returned before its table lock was released: %v", err)
		case <-tick.C:
			var blocked bool
			if err := f.pool.QueryRow(parent, `SELECT EXISTS (
SELECT 1 FROM pg_stat_activity WHERE datname=current_database()
AND wait_event_type='Lock' AND query ILIKE 'copy "advisory_publication_batch"%'
)`).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if blocked {
				break waitForCopy
			}
		}
	}

	select {
	case <-ctx.Done():
		t.Fatalf("heartbeat cancelled its own locked batch: %v", context.Cause(ctx))
	case err := <-result:
		t.Fatalf("batch escaped the held PostgreSQL table lock: %v", err)
	case <-time.After(5500 * time.Millisecond):
	}
	if err := blocker.Rollback(parent); err != nil {
		t.Fatal(err)
	}
	if err := awaitStreamPublicationWithin(t, result, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if stager.unique != 1 {
		t.Fatalf("committed claim count = %d, want 1", stager.unique)
	}
	// Serialization must not turn a genuinely lost lease into success.
	if _, err := f.pool.Exec(parent, "DELETE FROM advisory_generation_cleanup WHERE generation=$1", stager.generation); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
		if !errors.Is(context.Cause(ctx), ErrConflict) {
			t.Fatalf("lost lease cause = %v, want conflict", context.Cause(ctx))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("heartbeat did not detect a genuinely lost generation lease")
	}
}

func TestAdvisoryPublicationHeartbeatDoesNotAdvanceWatchdog(t *testing.T) {
	f, stager, parent, cancel := newLeasePublicationFixture(t, 1)
	defer cancel()
	ctx, stopHeartbeat := f.service.startAdvisoryLeaseHeartbeat(parent, stager.generation, 10*time.Millisecond, &stager.lease)
	defer stopHeartbeat()
	select {
	case <-ctx.Done():
		if !errors.Is(context.Cause(ctx), feed.ErrRefreshStalled) {
			t.Fatalf("idle publisher cause = %v, want progress stall", context.Cause(ctx))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("successful lease heartbeats advanced the independent progress watchdog")
	}
}

func newLeasePublicationFixture(t *testing.T, progressTimeoutSeconds uint32) (*streamPublicationFixture, *publicationStager, context.Context, context.CancelFunc) {
	t.Helper()
	f := newStreamPublicationFixture(t)
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(f.source)
	if err != nil {
		t.Fatal(err)
	}
	generation := uuid.New()
	if err := advisorydb.New(f.pool).StartAdvisoryGeneration(t.Context(), advisorydb.StartAdvisoryGenerationParams{
		FeedID: f.source.Id, Generation: generation, StartedAt: timestamp(time.Now().UTC()), ConfigBytes: encoded,
	}); err != nil {
		t.Fatal(err)
	}
	parent, cancel := context.WithCancel(t.Context())
	progressSource := proto.CloneOf(f.source)
	if progressTimeoutSeconds != 0 {
		progressSource.ProgressTimeoutSeconds = proto.Uint32(progressTimeoutSeconds)
	}
	ctx, progress := feed.NewRefreshProgress(parent, progressSource)
	t.Cleanup(func() {
		cancel()
		progress.Close()
	})
	stager := &publicationStager{
		s: f.service, progress: progress, generation: generation, feedID: f.source.Id,
		namespace: uuid.NewSHA1(uuid.NameSpaceOID, []byte(f.source.Id)), limit: 1,
	}
	if err := stager.emit(ctx, f.claim("lease-contention", 0)); err != nil {
		t.Fatal(err)
	}
	return f, stager, ctx, cancel
}
