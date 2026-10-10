//go:build linux

package connectivityguard

import (
	"errors"
	"os"
	"testing"
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
