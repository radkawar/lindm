//go:build linux

package recovery

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestJournalConsumptionSurvivesRestart(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := OpenJournal(directory); err == nil {
		_ = other.Close()
		t.Fatal("parallel recovery runner accepted")
	}
	if err := journal.Consume(); err != nil {
		t.Fatal(err)
	}
	if err := journal.Consume(); !errors.Is(err, ErrConsumed) {
		t.Fatalf("second consumption: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err = OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := journal.Close(); err != nil {
			t.Error(err)
		}
	}()
	consumed, err := journal.Consumed()
	if err != nil || !consumed {
		t.Fatalf("lost effect reservation: %v %v", consumed, err)
	}
	if err := journal.Consume(); !errors.Is(err, ErrConsumed) {
		t.Fatalf("restart replay: %v", err)
	}
}

func TestJournalAtomicCheckpointAndUnsafeFiles(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := journal.Close(); err != nil {
			t.Error(err)
		}
	}()
	before := &agentv1.DeviceActionStatus{ActionId: "31710192-8e38-4e34-a5f6-2ef14d252d1a", State: agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING}
	if err := journal.Save(before); err != nil {
		t.Fatal(err)
	}
	loaded := new(agentv1.DeviceActionStatus)
	found, err := journal.Load(loaded)
	if err != nil || !found || !proto.Equal(loaded, before) {
		t.Fatalf("checkpoint round trip: %v %v %v", found, loaded, err)
	}
	before.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN
	if err := journal.Save(before); err != nil {
		t.Fatal(err)
	}
	found, err = journal.Load(loaded)
	if err != nil || !found || !proto.Equal(loaded, before) {
		t.Fatalf("checkpoint replacement: %v %v %v", found, loaded, err)
	}
	if err := os.Chmod(filepath.Join(directory, "journal.pb"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Load(loaded); err == nil {
		t.Fatal("public checkpoint accepted")
	}
	if err := journal.Save(before); err == nil {
		t.Fatal("unsafe checkpoint overwritten")
	}
}

func TestJournalRejectsCorruptionAndSymlinkReservation(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := journal.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := os.WriteFile(filepath.Join(directory, "journal.pb"), []byte{0xff}, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Load(new(agentv1.DeviceActionStatus)); err == nil {
		t.Fatal("corrupt checkpoint accepted")
	}
	if err := os.Symlink("journal.pb", filepath.Join(directory, "effect.consumed")); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Consumed(); err == nil {
		t.Fatal("symlink effect reservation accepted")
	}
	if err := journal.Consume(); !errors.Is(err, ErrConsumed) {
		t.Fatalf("unsafe existing marker did not block: %v", err)
	}
}
