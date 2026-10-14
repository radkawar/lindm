// SPDX-License-Identifier: Apache-2.0

//go:build integration

package advisory

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"lindm/internal/advisory/advisorydb"
)

// Controlled retired generations exercise durable PostgreSQL cleanup work, not
// vendor acquisition or native package execution.
func TestAdvisoryGenerationCleanupResumesAfterCancellation(t *testing.T) {
	f := newStreamPublicationFixture(t)
	tracer := new(generationCleanupTracer)
	config := f.pool.Config()
	config.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	service, err := New(t.Context(), pool, f.service.config, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	retired := seedStreamCleanupGeneration(t, f, 5001)
	queueStreamGenerationCleanup(t, f, retired)

	bounded, cancelBatch := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelBatch()
	more, err := service.cleanupAdvisoryGenerationBatch(bounded)
	if err != nil || !more {
		t.Fatalf("first cleanup batch: more=%v err=%v", more, err)
	}
	assertGenerationCleanupPlan(t, f.pool, tracer.sql, f.source.Id, retired)
	assertStreamCleanupGeneration(t, f, retired, 1, 1)
	f.assertStorage(t, f.before.AdvisoryCount, f.before.AdvisoryCount+1, 1)
	f.assertUnchanged(t, f.before, f.findings)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := service.drainAdvisoryGenerationCleanup(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled cleanup returned %v, want context.Canceled", err)
	}
	assertStreamCleanupGeneration(t, f, retired, 1, 1)

	if err := service.drainAdvisoryGenerationCleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertStreamCleanupGeneration(t, f, retired, 0, 0)
	f.assertStorage(t, f.before.AdvisoryCount, f.before.AdvisoryCount, 0)
	f.assertUnchanged(t, f.before, f.findings)
	if more, err := service.cleanupAdvisoryGenerationBatch(t.Context()); err != nil || more {
		t.Fatalf("drained cleanup queue still has work: more=%v err=%v", more, err)
	}
}

func TestAdvisoryGenerationCleanupProtectsActiveAndLiveStaging(t *testing.T) {
	f := newStreamPublicationFixture(t)
	staging := seedStreamCleanupGeneration(t, f, 501)
	if err := advisorydb.New(f.pool).StartAdvisoryGeneration(t.Context(), advisorydb.StartAdvisoryGenerationParams{FeedID: f.source.Id, Generation: staging}); err != nil {
		t.Fatal(err)
	}
	// Even an erroneously queued active revision cannot be deleted. Future
	// staging ownership is retained while due work for the active key is drained.
	queueStreamGenerationCleanup(t, f, f.before.Revision)
	if err := f.service.drainAdvisoryGenerationCleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertStreamCleanupGeneration(t, f, f.before.Revision, f.before.AdvisoryCount, 0)
	assertStreamCleanupGeneration(t, f, staging, 501, 1)
	f.assertStorage(t, f.before.AdvisoryCount, f.before.AdvisoryCount+501, 501)
	f.assertUnchanged(t, f.before, f.findings)
	if more, err := f.service.cleanupAdvisoryGenerationBatch(t.Context()); err != nil || more {
		t.Fatalf("future staging lease was claimable: more=%v err=%v", more, err)
	}

	mustExec(t, t.Context(), f.pool, "UPDATE advisory_generation_cleanup SET cleanup_after=clock_timestamp()-interval '1 second' WHERE feed_id=$1 AND generation=$2", f.source.Id, staging)
	if err := f.service.drainAdvisoryGenerationCleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertStreamCleanupGeneration(t, f, staging, 0, 0)
	f.assertStorage(t, f.before.AdvisoryCount, f.before.AdvisoryCount, 0)
	f.assertUnchanged(t, f.before, f.findings)
}

func TestAdvisoryGenerationCleanupSkipsLockedWork(t *testing.T) {
	f := newStreamPublicationFixture(t)
	locked := seedStreamCleanupGeneration(t, f, 1)
	available := seedStreamCleanupGeneration(t, f, 1)
	queueStreamGenerationCleanup(t, f, locked)
	queueStreamGenerationCleanup(t, f, available)

	tx, err := f.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := rollbackAdvisoryPublication(t.Context(), tx); err != nil {
			t.Error(err)
		}
	}()
	var generation uuid.UUID
	if err := tx.QueryRow(t.Context(), "SELECT generation FROM advisory_generation_cleanup WHERE feed_id=$1 AND generation=$2 FOR UPDATE", f.source.Id, locked).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	// A second database transaction must make progress on the unlocked key,
	// rather than waiting on cleanup already owned by another worker.
	bounded, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if more, err := f.service.cleanupAdvisoryGenerationBatch(bounded); err != nil || !more {
		t.Fatalf("cleanup could not skip the locked key: more=%v err=%v", more, err)
	}
	assertStreamCleanupGeneration(t, f, locked, 1, 1)
	assertStreamCleanupGeneration(t, f, available, 0, 0)
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := f.service.drainAdvisoryGenerationCleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertStreamCleanupGeneration(t, f, locked, 0, 0)
	f.assertStorage(t, f.before.AdvisoryCount, f.before.AdvisoryCount, 0)
	f.assertUnchanged(t, f.before, f.findings)
}

func TestAdvisoryStreamPublicationCannotRenewExpiredGeneration(t *testing.T) {
	for _, boundary := range []struct {
		name  string
		count int
	}{
		{"final-switch", advisoryPublicationBatchSize},
		{"partial-batch", advisoryPublicationBatchSize + 1},
		{"full-batch", 2 * advisoryPublicationBatchSize},
	} {
		for _, reclaimed := range []bool{false, true} {
			name := boundary.name + "/expired"
			if reclaimed {
				name = boundary.name + "/reclaimed"
			}
			t.Run(name, func(t *testing.T) {
				f := newStreamPublicationFixture(t)
				release, _, result := f.startBlocked(t, "expired", boundary.count, advisoryPublicationBatchSize, nil)
				var staging uuid.UUID
				err := f.pool.QueryRow(t.Context(), "SELECT generation FROM advisory_generation_cleanup WHERE feed_id=$1 AND generation<>$2", f.source.Id, f.before.Revision).Scan(&staging)
				if err != nil {
					t.Fatal(err)
				}
				assertStreamCleanupGeneration(t, f, staging, advisoryPublicationBatchSize, 1)
				mustExec(t, t.Context(), f.pool, "UPDATE advisory_generation_cleanup SET cleanup_after=clock_timestamp()-interval '1 second' WHERE feed_id=$1 AND generation=$2", f.source.Id, staging)
				if reclaimed {
					if err := f.service.drainAdvisoryGenerationCleanup(t.Context()); err != nil {
						t.Fatal(err)
					}
					assertStreamCleanupGeneration(t, f, staging, 0, 0)
				}
				f.assertUnchanged(t, f.before, f.findings)
				close(release)
				if err := awaitStreamPublication(t, result); !errors.Is(err, ErrConflict) {
					t.Fatalf("writer with lost staging ownership returned %v, want ErrConflict", err)
				}
				assertStreamCleanupGeneration(t, f, staging, 0, 0)
				f.assertStorage(t, f.before.AdvisoryCount, f.before.AdvisoryCount, 0)
				f.assertUnchanged(t, f.before, f.findings)
			})
		}
	}
}

func seedStreamCleanupGeneration(t *testing.T, f *streamPublicationFixture, count int) uuid.UUID {
	t.Helper()
	generation := uuid.New()
	// Reuse a genuine normalized payload, with distinct storage identities for
	// the controlled retired rows. This fixture never becomes an active feed.
	mustExec(t, t.Context(), f.pool, `INSERT INTO advisory_record_generations
		(generation,id,feed_id,advisory_id,package_name,source_package,architecture,record_bytes)
		SELECT $2::uuid,md5($2::text || ':' || n::text)::uuid,$1,
		       r.advisory_id,r.package_name,r.source_package,r.architecture,r.record_bytes
		FROM (SELECT advisory_id,package_name,source_package,architecture,record_bytes
		      FROM advisory_records WHERE feed_id=$1 LIMIT 1) r
		CROSS JOIN generate_series(1,$3::integer) n`, f.source.Id, generation, count)
	return generation
}

func queueStreamGenerationCleanup(t *testing.T, f *streamPublicationFixture, generation uuid.UUID) {
	t.Helper()
	if err := advisorydb.New(f.pool).QueueAdvisoryGenerationCleanup(t.Context(), advisorydb.QueueAdvisoryGenerationCleanupParams{FeedID: f.source.Id, Generation: generation}); err != nil {
		t.Fatal(err)
	}
}

func assertStreamCleanupGeneration(t *testing.T, f *streamPublicationFixture, generation uuid.UUID, records, queued int64) {
	t.Helper()
	var gotRecords, gotQueued int64
	err := f.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM advisory_record_generations WHERE feed_id=$1 AND generation=$2),
		(SELECT count(*) FROM advisory_generation_cleanup WHERE feed_id=$1 AND generation=$2)`, f.source.Id, generation).Scan(&gotRecords, &gotQueued)
	if err != nil {
		t.Fatal(err)
	}
	if gotRecords != records || gotQueued != queued {
		t.Fatalf("generation %s: records=%d queued=%d; want records=%d queued=%d", generation, gotRecords, gotQueued, records, queued)
	}
}

// Capture the executed sqlc statement rather than duplicating its deletion SQL.
type generationCleanupTracer struct {
	sql string
}

func (c *generationCleanupTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(data.SQL, "-- name: DeleteInactiveAdvisoryGenerationBatch ") {
		c.sql = data.SQL
	}
	return ctx
}

func (*generationCleanupTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func assertGenerationCleanupPlan(t *testing.T, pool *pgxpool.Pool, statement, feedID string, generation uuid.UUID) {
	t.Helper()
	if statement == "" {
		t.Fatal("generation cleanup did not execute its bounded deletion")
	}
	var plan []byte
	if err := pool.QueryRow(t.Context(), "EXPLAIN (FORMAT JSON) "+statement, feedID, generation).Scan(&plan); err != nil {
		t.Fatal(err)
	}
	var root []struct{ Plan planNode }
	if err := json.Unmarshal(plan, &root); err != nil {
		t.Fatal(err)
	}
	if len(root) != 1 {
		t.Fatalf("unexpected generation cleanup plan:\n%s", plan)
	}
	// Fresh private generations need not have ANALYZE statistics. Even when
	// estimated as one row, deleting a batch must not repeat its bounded scan
	// as the inner side of a loop over every row in the generation. This also
	// rejects a materialized victim set repeatedly joined against those rows;
	// a scalar prefix boundary is instead computed once by an InitPlan.
	var scansBatch func(planNode, bool) bool
	scansBatch = func(node planNode, limited bool) bool {
		limited = limited || node.NodeType == "Limit"
		if node.NodeType == "CTE Scan" || limited && node.RelationName == "advisory_record_generations" {
			return true
		}
		for _, child := range node.Plans {
			if scansBatch(child, limited) {
				return true
			}
		}
		return false
	}
	var walk func(planNode)
	walk = func(node planNode) {
		if node.NodeType == "Nested Loop" && len(node.Plans) > 1 && scansBatch(node.Plans[len(node.Plans)-1], false) {
			t.Fatalf("generation cleanup rescans the victim batch for every generation row:\n%s", plan)
		}
		for _, child := range node.Plans {
			walk(child)
		}
	}
	walk(root[0].Plan)
}
