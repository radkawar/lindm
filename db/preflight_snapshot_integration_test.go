// SPDX-License-Identifier: Apache-2.0

//go:build integration

package db_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"lindm/db"
	"lindm/internal/testdb"
)

type historyReadKey struct{}

type historyReadBarrier struct {
	once   sync.Once
	read   chan struct{}
	resume chan struct{}
}

func (b *historyReadBarrier) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, historyReadKey{}, strings.Contains(data.SQL, "goose_db_version") && !strings.Contains(data.SQL, "to_regclass") && strings.HasPrefix(strings.ToUpper(strings.TrimSpace(data.SQL)), "SELECT"))
}

func (b *historyReadBarrier) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryEndData) {
	if history, _ := ctx.Value(historyReadKey{}).(bool); history {
		b.once.Do(func() {
			close(b.read)
			select {
			case <-b.resume:
			case <-ctx.Done():
			}
		})
	}
}

func TestPreflightUsesOneSnapshotDuringOnlineMigration(t *testing.T) {
	pool, _ := testdb.Open(t)
	initial, err := db.Preflight(t.Context(), pool)
	if err != nil {
		t.Fatal(err)
	}
	barrier := &historyReadBarrier{read: make(chan struct{}), resume: make(chan struct{})}
	cfg := pool.Config()
	cfg.ConnConfig.Tracer = barrier
	reader, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	type result struct {
		status db.SchemaStatus
		err    error
	}
	finished := make(chan result, 1)
	go func() { status, err := db.Preflight(ctx, reader); finished <- result{status, err} }()
	select {
	case <-barrier.read:
	case <-ctx.Done():
		t.Fatal("preflight never read migration history")
	}
	// A reviewed expand commits after the history read but before the policy read.
	tx, err := pool.Begin(ctx)
	if err != nil {
		close(barrier.resume)
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, "INSERT INTO goose_db_version(version_id,is_applied) VALUES($1,true);", initial.Target+1); err == nil {
		_, err = tx.Exec(ctx, "UPDATE lindm_schema_compatibility SET migration_versions=array_append(migration_versions,$1)", initial.Target+1)
	}
	if err == nil {
		err = tx.Commit(ctx)
	} else {
		_ = tx.Rollback(ctx)
	}
	close(barrier.resume)
	if err != nil {
		t.Fatal(err)
	}
	got := <-finished
	if got.err != nil {
		t.Fatalf("valid concurrent expansion rejected: %v", got.err)
	}
	if !got.status.Compatible || got.status.Current != initial.Current {
		t.Fatalf("preflight did not retain its original snapshot: %+v", got.status)
	}
	after, err := db.Preflight(ctx, pool)
	if err != nil || !after.Compatible || after.Current != initial.Target+1 {
		t.Fatalf("committed expansion = %+v, %v", after, err)
	}
}

func TestPreflightRequiresIntroducedCompatibilityMetadata(t *testing.T) {
	for _, mutation := range []string{"DROP TABLE lindm_schema_compatibility", "DELETE FROM lindm_schema_compatibility"} {
		t.Run(mutation, func(t *testing.T) {
			pool, _ := testdb.Open(t)
			if _, err := pool.Exec(t.Context(), mutation); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Preflight(t.Context(), pool); err == nil {
				t.Fatal("post-policy database without compatibility metadata passed preflight")
			}
			if err := db.Check(t.Context(), pool); err == nil {
				t.Fatal("post-policy database without compatibility metadata passed startup")
			}
		})
	}
}
