//go:build linux

package connectivityguard

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestUnconfiguredSupervisorOnlyAdmitsEmptyCustody(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("private root custody test requires root")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	state, err := openStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := state.close(); err != nil {
			t.Error(err)
		}
	}()
	if err := recoverRecord(t.Context(), state, nil, true); err != nil {
		t.Fatalf("disabled empty supervisor failed: %v", err)
	}
	file, err := state.open(recordName, true)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.Write([]byte{0xff})
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		t.Fatal(err)
	}
	if err := recoverRecord(t.Context(), state, nil, true); err == nil {
		t.Fatal("retained malformed recovery custody was treated as empty disabled configuration")
	}
	file, err = state.open(recordName, false)
	if err != nil {
		t.Fatal("failed recovery removed retained custody")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

// The supervisor's 100ms non-blocking recovery poll briefly holds the record
// lock. A worker hitting that window must wait within its deadline, not fail
// an already-applied native batch as outcome-unknown (seen on Fedora 44).
func TestWorkerRecordLockWaitsForSupervisorPoll(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("private root custody test requires root")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	state, err := openStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := state.close(); err != nil {
			t.Error(err)
		}
	}()
	held, err := state.lock("record.lock")
	if err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if lock, err := state.lockWorker(short, "record.lock"); err == nil || !errors.Is(err, context.DeadlineExceeded) {
		_ = lock.Close()
		t.Fatalf("worker took a held record lock or failed without waiting: %v", err)
	}
	released := make(chan error, 1)
	go func() {
		time.Sleep(30 * time.Millisecond)
		released <- held.Close()
	}()
	wait, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	lock, err := state.lockWorker(wait, "record.lock")
	if err != nil {
		t.Fatalf("worker failed on transient supervisor contention: %v", err)
	}
	if err := errors.Join(<-released, lock.Close()); err != nil {
		t.Fatal(err)
	}
}
