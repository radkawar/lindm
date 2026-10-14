// SPDX-License-Identifier: Apache-2.0

//go:build integration

package offlinebundle

import (
	"errors"
	"testing"
	"time"

	"lindm/internal/testdb"
)

func TestLedgerAdmitsOnlyNewerSequences(t *testing.T) {
	pool, _ := testdb.Open(t)
	importer := &Importer{cfg: ImporterConfig{Pool: pool, Clock: time.Now}}
	authority := newTestAuthority(t)
	now := time.Now().UTC()
	open := func(sequence uint64) *Bundle {
		t.Helper()
		bundle, err := Open(t.Context(), writeTestBundle(t, authority, sequence, now.Add(-time.Minute), time.Hour), authority.verifier, now)
		if err != nil {
			t.Fatal(err)
		}
		return bundle
	}
	conn, err := pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	first := open(1)
	if already, err := importer.admit(t.Context(), conn, first); err != nil || already {
		t.Fatalf("first admission: already=%t err=%v", already, err)
	}
	if err := importer.finish(t.Context(), conn, first); err != nil {
		t.Fatal(err)
	}
	if already, err := importer.admit(t.Context(), conn, first); err != nil || !already {
		t.Fatalf("identical resubmission: already=%t err=%v", already, err)
	}
	third := open(3)
	if already, err := importer.admit(t.Context(), conn, third); err != nil || already {
		t.Fatalf("newer admission: already=%t err=%v", already, err)
	}
	// An interrupted import resumes only with the identical signed manifest.
	if already, err := importer.admit(t.Context(), conn, third); err != nil || already {
		t.Fatalf("resume: already=%t err=%v", already, err)
	}
	if _, err := importer.admit(t.Context(), conn, open(2)); !errors.Is(err, ErrReplayed) {
		t.Fatalf("older never-imported sequence: %v", err)
	}
	if _, err := importer.admit(t.Context(), conn, open(3)); !errors.Is(err, ErrEquivocation) {
		t.Fatalf("different manifest at an admitted sequence: %v", err)
	}
	if err := importer.finish(t.Context(), conn, third); err != nil {
		t.Fatal(err)
	}
	if err := importer.finish(t.Context(), conn, third); err == nil {
		t.Fatal("completed import finished twice")
	}
	var audited int
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM audit_events WHERE action = 'offline_bundle.imported'").Scan(&audited); err != nil || audited != 2 {
		t.Fatalf("audit events %d, %v", audited, err)
	}
}
