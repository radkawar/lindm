// SPDX-License-Identifier: Apache-2.0

//go:build integration

package advisory

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/advisory/advisorydb"
	"lindm/internal/testdb"
)

// Another device's committed audit must not invalidate a binding transaction
// that already owns its device row. The chain still commits exactly one event
// per changed evaluation, atomically with its outbox and hash-chain evidence.
func TestEvaluationWaitsForAuditHeadWithoutRestarting(t *testing.T) {
	pool, _ := testdb.Open(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	s, source, doc := vendorService(t, pool, "fedora", "44", "synthetic-fedora44-updateinfo.xml")
	if err := s.publish(ctx, source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	pkg := &inventoryv1.Package{Name: "synthetic-rpm-tool", Version: "0:8.4.2-11.p3.fc44", Architecture: "x86_64", Manager: "rpm"}
	warm := seedInventory(t, pool, "fedora", "44", pkg)
	if _, err := s.Evaluate(ctx, warm); err != nil {
		t.Fatal(err)
	}
	device := seedInventory(t, pool, "fedora", "44", pkg)
	var sequence int64
	if err := pool.QueryRow(ctx, "SELECT sequence FROM report_audit_head WHERE singleton").Scan(&sequence); err != nil {
		t.Fatal(err)
	}
	writer, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Rollback(ctx) }()
	if err := advisorydb.New(writer).InsertAdvisoryAudit(ctx, advisorydb.InsertAdvisoryAuditParams{ID: uuid.New(), Action: "advisory.findings.changed", ResourceID: warm.String(), Context: "Competing audit transaction"}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.evaluateOnce(ctx, device)
		done <- err
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
WHERE datname=current_database() AND $1::integer=ANY(pg_blocking_pids(pid))
AND query LIKE '-- name: InsertAdvisoryAudit%')`, writer.Conn().PgConn().PID()).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("evaluation ended before the competing writer committed: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
	}
	var visible bool
	if err := pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM advisory_evaluations WHERE device_id=$1)", device).Scan(&visible); err != nil || visible {
		t.Fatalf("uncommitted evaluation escaped the audit fence: visible=%v err=%v", visible, err)
	}
	if err := writer.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("one binding attempt failed after audit predecessor committed: %v", err)
	}
	if _, err := s.Evaluate(ctx, device); err != nil {
		t.Fatal(err)
	}
	var audits, evidence, outbox int
	if err := pool.QueryRow(ctx, `SELECT count(*),count(r.event_id),count(o.id) FROM audit_events a
LEFT JOIN report_audit_rows r ON r.event_id=a.id
LEFT JOIN integration_events o ON o.id=a.id
WHERE a.action='advisory.findings.changed' AND a.resource_id=$1`, device.String()).Scan(&audits, &evidence, &outbox); err != nil {
		t.Fatal(err)
	}
	var final int64
	var predecessorOK bool
	if err := pool.QueryRow(ctx, `SELECT h.sequence, r.previous_hash=p.row_hash AND h.row_hash=r.row_hash
FROM report_audit_head h JOIN report_audit_rows r ON r.sequence=h.sequence
JOIN report_audit_rows p ON p.sequence=r.sequence-1 WHERE h.singleton`).Scan(&final, &predecessorOK); err != nil {
		t.Fatal(err)
	}
	if audits != 1 || evidence != 1 || outbox != 1 || final != sequence+2 || !predecessorOK {
		t.Fatalf("audit chain changed or duplicated: audits=%d evidence=%d outbox=%d sequence=%d want=%d predecessor=%v", audits, evidence, outbox, final, sequence+2, predecessorOK)
	}
}
