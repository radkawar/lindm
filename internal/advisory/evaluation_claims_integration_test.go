// SPDX-License-Identifier: Apache-2.0

//go:build integration

package advisory

import (
	"errors"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	configv1 "lindm/gen/lindm/config/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/advisory/advisorydb"
	"lindm/internal/testdb"
)

// Replicas claiming at the same time receive disjoint batches: an in-flight
// claim's device rows are skipped, a committed unexpired claim is never taken
// over, and only an expired claim is reclaimed.
func TestReplicaClaimsAreDisjointUntilExpiry(t *testing.T) {
	pool, _ := testdb.Open(t)
	ctx := t.Context()
	pkg := &inventoryv1.Package{Name: "synthetic-rpm-tool", Version: "0:8.4.2-11.p3.fc44", Architecture: "x86_64", Manager: "rpm"}
	const batch = 3
	all := make([]uuid.UUID, 2*batch)
	for i := range all {
		all[i] = seedInventory(t, pool, "fedora", "44", pkg)
	}
	claim := func(q *advisorydb.Queries, token uuid.UUID) []uuid.UUID {
		t.Helper()
		ids, err := q.ClaimAdvisoryEvaluations(ctx, advisorydb.ClaimAdvisoryEvaluationsParams{LeaseToken: token, LeaseSeconds: 60, RowLimit: batch})
		if err != nil {
			t.Fatal(err)
		}
		return ids
	}
	first, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Rollback(ctx) }()
	a := claim(advisorydb.New(first), uuid.New())
	b := claim(advisorydb.New(pool), uuid.New())
	if len(a) != batch || len(b) != batch {
		t.Fatalf("concurrent claims not full: %d %d", len(a), len(b))
	}
	for _, id := range a {
		if slices.Contains(b, id) {
			t.Fatalf("device %s claimed twice", id)
		}
	}
	if err := first.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if again := claim(advisorydb.New(pool), uuid.New()); len(again) != 0 {
		t.Fatalf("unexpired claims taken over: %v", again)
	}
	mustExec(t, ctx, pool, "UPDATE advisory_evaluation_claims SET lease_until=clock_timestamp()-interval '1 second' WHERE device_id=ANY($1)", a)
	reclaimed := claim(advisorydb.New(pool), uuid.New())
	slices.SortFunc(a, func(x, y uuid.UUID) int { return slices.Compare(x[:], y[:]) })
	slices.SortFunc(reclaimed, func(x, y uuid.UUID) int { return slices.Compare(x[:], y[:]) })
	if !slices.Equal(a, reclaimed) {
		t.Fatalf("expired claims not reclaimed exactly: %v want %v", reclaimed, a)
	}
}

// Two replicas draining one cold fleet together build its finding set once,
// bind every device, append exactly one chained audit event per device and
// leave no claim behind.
func TestReplicasEvaluateColdFleetOnce(t *testing.T) {
	pool, _ := testdb.Open(t)
	ctx := t.Context()
	first, source, doc := vendorService(t, pool, "fedora", "44", "synthetic-fedora44-updateinfo.xml")
	if err := first.publish(ctx, source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	second, err := New(ctx, pool, &configv1.AdvisoryConfig{Feeds: []*advisoryv1.FeedSource{source}}, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	pkg := &inventoryv1.Package{Name: "synthetic-rpm-tool", Version: "0:8.4.2-11.p3.fc44", Architecture: "x86_64", Manager: "rpm"}
	devices := make([]uuid.UUID, 6*evaluationWorkers)
	for i := range devices {
		devices[i] = seedInventory(t, pool, "fedora", "44", pkg)
	}
	var start int64
	if err := pool.QueryRow(ctx, "SELECT sequence FROM report_audit_head WHERE singleton").Scan(&start); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, s := range []*Service{first, second} {
		wg.Go(func() {
			for time.Now().Before(deadline) {
				attempted, failures, err := s.evaluatePending(ctx, 4)
				if err != nil {
					errs[i] = err
					return
				}
				if attempted == 0 {
					var pending int
					if err := pool.QueryRow(ctx, "SELECT count(*) FROM devices d LEFT JOIN advisory_evaluations e ON e.device_id=d.id WHERE e.device_id IS NULL").Scan(&pending); err != nil {
						errs[i] = err
						return
					}
					if pending == 0 {
						return
					}
				}
				if failures == attempted && attempted > 0 {
					time.Sleep(20 * time.Millisecond) // the other replica is building the set
				}
			}
			errs[i] = errors.New("cold fleet not drained before deadline")
		})
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		t.Fatal(err)
	}
	var sets, bound, audits, claims int
	var head int64
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM advisory_finding_sets),
 (SELECT count(*) FROM advisory_evaluations WHERE state='evaluated' AND finding_set_id IS NOT NULL),
 (SELECT count(*) FROM audit_events a JOIN report_audit_rows r ON r.event_id=a.id WHERE a.action='advisory.findings.changed'),
 (SELECT count(*) FROM advisory_evaluation_claims),
 (SELECT sequence FROM report_audit_head WHERE singleton)`).Scan(&sets, &bound, &audits, &claims, &head); err != nil {
		t.Fatal(err)
	}
	if sets != 1 || bound != len(devices) || audits != len(devices) || claims != 0 || head != start+int64(len(devices)) {
		t.Fatalf("sets=%d bound=%d audits=%d claims=%d head=%d want 1/%d/%d/0/%d", sets, bound, audits, claims, head, len(devices), len(devices), start+int64(len(devices)))
	}
	var broken int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM report_audit_rows r JOIN report_audit_rows p ON p.sequence=r.sequence-1
WHERE r.sequence>$1 AND r.previous_hash<>p.row_hash`, start).Scan(&broken); err != nil || broken != 0 {
		t.Fatalf("audit chain broken: %d %v", broken, err)
	}
}

// Another instance's in-progress build of the same finding set defers the
// device as busy instead of repeating the cold match; once that lock is gone
// the device is built and bound normally.
func TestFindingSetBuildDefersToAnotherInstance(t *testing.T) {
	pool, _ := testdb.Open(t)
	ctx := t.Context()
	s, source, doc := vendorService(t, pool, "fedora", "44", "synthetic-fedora44-updateinfo.xml")
	if err := s.publish(ctx, source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	device := seedInventory(t, pool, "fedora", "44", &inventoryv1.Package{Name: "synthetic-rpm-tool", Version: "0:8.4.2-11.p3.fc44", Architecture: "x86_64", Manager: "rpm"})
	_, err := s.evaluateOnce(ctx, device)
	missing, ok := errors.AsType[*missingFindingSet](err)
	if !ok {
		t.Fatalf("cold device did not report a missing set: %v", err)
	}
	other, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Rollback(ctx) }()
	if locked, err := advisorydb.New(other).TryLockAdvisoryFindingSetBuild(ctx, findingSetBuildKey(missing.feedID, missing.digest)); err != nil || !locked {
		t.Fatalf("lock build: %v %v", locked, err)
	}
	if _, err := s.Evaluate(ctx, device); !errors.Is(err, ErrDeviceBusy) {
		t.Fatalf("build owned elsewhere: %v", err)
	}
	var sets int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM advisory_finding_sets").Scan(&sets); err != nil || sets != 0 {
		t.Fatalf("set built under another instance's lock: %d %v", sets, err)
	}
	if err := other.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if evaluation, err := s.Evaluate(ctx, device); err != nil || evaluation.State != "evaluated" || evaluation.FindingSetID == nil {
		t.Fatalf("device not bound after build lock released: %+v %v", evaluation, err)
	}
}
