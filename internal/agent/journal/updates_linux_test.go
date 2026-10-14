// SPDX-License-Identifier: Apache-2.0

package journal

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func updateTransaction() *agentv1.AgentUpdateTransaction {
	return &agentv1.AgentUpdateTransaction{Id: uuid.NewString(), Version: "0.2.0", NativeVersion: "0.2.0-1", PreviousNativeVersion: "0.1.0-1", PreviousVersion: "0.1.0", Manager: agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_APT, Architecture: "amd64", Sha256: strings.Repeat("a", 64), Length: 123, AdmittedAt: timestamppb.Now(), VerifiedExpiresAt: timestamppb.New(time.Now().Add(time.Hour))}
}

func TestUpdateJournalRestartFencesVersionAndTransaction(t *testing.T) {
	directory := protectedDirectory(t)
	store, err := OpenUpdates(directory)
	if err != nil {
		t.Fatal(err)
	}
	state := store.Load()
	state.InstalledVersion = "0.1.0"
	state.Transaction, state.Phase = updateTransaction(), "applying"
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenUpdates(directory); !errors.Is(err, ErrAlreadyOpen) {
		t.Fatalf("concurrent update owner: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenUpdates(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if got := store.Load(); !proto.Equal(got, state) {
		t.Fatal("acknowledged native transaction lost across restart")
	}
	mutated := store.Load()
	mutated.Transaction.Version = "0.3.0"
	if err := store.Save(mutated); err == nil {
		t.Fatal("unresolved transaction was replaceable")
	}
	mutated = store.Load()
	mutated.InstalledVersion = "0.0.9"
	if err := store.Save(mutated); err == nil {
		t.Fatal("installed high-water mark rolled back")
	}
	state.InstalledVersion, state.Phase = state.GetTransaction().GetVersion(), "installed"
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	got := store.Load()
	got.Transaction.NativeVersion = "0.2.0-evil"
	if store.Load().GetTransaction().GetNativeVersion() != "0.2.0-1" {
		t.Fatal("caller mutated durable transaction by alias")
	}
}

func TestUpdateJournalDamageCannotReinitialize(t *testing.T) {
	for _, damage := range []string{"missing", "corrupt", "symlink", "oversized", "unknown phase"} {
		t.Run(damage, func(t *testing.T) {
			directory := protectedDirectory(t)
			store, err := OpenUpdates(directory)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(store.Directory, "state.pb")
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			switch damage {
			case "missing":
				err = os.Remove(path)
			case "corrupt":
				err = os.WriteFile(path, []byte{255, 255, 255}, 0600)
			case "oversized":
				err = os.WriteFile(path, []byte(strings.Repeat("a", 65537)), 0600)
			case "symlink":
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(path+".old", path)
			case "unknown phase":
				err = WriteUpdateRecord(filepath.Dir(path), "state.pb", &agentv1.AgentUpdateJournal{FormatVersion: 1, Phase: "success", ObservedAt: timestamppb.Now()})
			}
			if err != nil {
				t.Fatal(err)
			}
			if opened, err := OpenUpdates(directory); err == nil {
				_ = opened.Close()
				t.Fatal("damaged checkpoint reinitialized")
			}
		})
	}
}

func TestUpdateJournalRejectsFalseSuccessShape(t *testing.T) {
	store, err := OpenUpdates(protectedDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	state := store.Load()
	state.Phase = "installed"
	if err := store.Save(state); err == nil {
		t.Fatal("success without a transaction accepted")
	}
	state.Transaction = updateTransaction()
	state.InstalledVersion = "0.1.0"
	if err := store.Save(state); err == nil {
		t.Fatal("success with the predecessor version accepted")
	}
}

func TestUpdateCheckpointWriteFailureLatchesUntilReopen(t *testing.T) {
	store, err := OpenUpdates(protectedDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	original := store.Directory
	// Simulate a lost storage mount without modifying the committed checkpoint.
	store.Directory = filepath.Join(original, "unavailable")
	if err := store.Save(store.Load()); err == nil {
		t.Fatal("unavailable storage acknowledged")
	}
	store.Directory = original
	if err := store.Save(store.Load()); !errors.Is(err, ErrRecoveryHold) {
		t.Fatalf("ambiguous checkpoint failure did not latch: %v", err)
	}
}

func TestRejectedUnstartedUpdateCanBeReplacedWithoutVersionRollback(t *testing.T) {
	store, err := OpenUpdates(protectedDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	state := store.Load()
	state.InstalledVersion, state.Transaction, state.Phase = "0.1.0", updateTransaction(), "staged"
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	state.Phase, state.LastOutcome = "rejected", "rejected"
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	state.Transaction, state.Phase = updateTransaction(), "staged"
	if err := store.Save(state); err != nil {
		t.Fatal("fresh admission was blocked by a safely rejected unstarted transaction:", err)
	}
	state.InstalledVersion = "0.0.9"
	if err := store.Save(state); err == nil {
		t.Fatal("rejection reset the installed-version floor")
	}
}
