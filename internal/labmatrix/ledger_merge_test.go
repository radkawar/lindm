package labmatrix

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
)

func TestMergeLedgerComposesConcurrentChanges(t *testing.T) {
	at := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	pass, fail := labv1.MatrixVerdict_MATRIX_VERDICT_PASS, labv1.MatrixVerdict_MATRIX_VERDICT_FAIL
	old := entry("ubuntu-24.04", "lifecycle", "x86_64", fail, at)
	shared := entry("debian-12", "inventory", "x86_64", pass, at)
	mine := entry("debian-12", "lifecycle", "aarch64", pass, at.Add(time.Hour))
	other := entry("fedora-43", "lifecycle", "x86_64", pass, at.Add(2*time.Hour))
	ledger := func(entries ...*labv1.MatrixLedgerEntry) []byte {
		t.Helper()
		data, err := Marshal(&labv1.MatrixLedger{Entries: entries})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	decode := func(data []byte) []*labv1.MatrixLedgerEntry {
		t.Helper()
		out := new(labv1.MatrixLedger)
		if err := decodeBytes("merged", data, out); err != nil {
			t.Fatal(err)
		}
		return out.GetEntries()
	}
	same := func(got, want []*labv1.MatrixLedgerEntry) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if !proto.Equal(got[i], want[i]) {
				return false
			}
		}
		return true
	}
	base := ledger(old, shared)
	// Main gained another landing's entry while this worktree appended its
	// own and dropped a superseded one: both changes survive, in order.
	current := ledger(old, shared, other)
	theirs := ledger(shared, mine)
	merged, err := MergeLedger(current, base, theirs)
	if err != nil {
		t.Fatal(err)
	}
	if got := decode(merged); !same(got, []*labv1.MatrixLedgerEntry{shared, other, mine}) {
		t.Fatalf("merged %v", got)
	}
	// Merging again changes nothing, and a missing base is an empty ledger.
	if again, err := MergeLedger(merged, base, theirs); err != nil || string(again) != string(merged) {
		t.Fatalf("merge not idempotent: %v", err)
	}
	if created, err := MergeLedger(nil, nil, ledger(mine)); err != nil || !same(decode(created), []*labv1.MatrixLedgerEntry{mine}) {
		t.Fatalf("new ledger: %v", err)
	}
	if _, err := MergeLedger(current, base, []byte("{not json")); err == nil {
		t.Fatal("an unreadable ledger was merged")
	}
}
