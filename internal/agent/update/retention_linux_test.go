package update

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/statefs"
)

func protectedRetentionDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func retentionFixture(t *testing.T, root, phase string) *agentv1.AgentUpdateTransaction {
	t.Helper()
	tx := &agentv1.AgentUpdateTransaction{Id: uuid.NewString(), Version: "0.2.0", NativeVersion: "0.2.0-1", PreviousNativeVersion: "0.1.0-1", PreviousVersion: "0.1.0", Manager: agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_APT, Architecture: "amd64", Sha256: strings.Repeat("a", 64), Length: 123, AdmittedAt: timestamppb.Now(), VerifiedExpiresAt: timestamppb.New(time.Now().Add(time.Hour))}
	path := filepath.Join(root, tx.GetId())
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := journal.WriteUpdateRecord(path, "transaction.pb", tx); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(packagePath(path, tx), []byte("owned staged payload"), 0600); err != nil {
		t.Fatal(err)
	}
	if phase != "" {
		if err := journal.WriteUpdateRecord(path, "helper.pb", &agentv1.AgentUpdateHelperState{Phase: phase, ObservedAt: timestamppb.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	return tx
}

func noRetentionHelper(string) (bool, error) { return false, nil }

func TestRetentionReclaimsTerminalAndOrphanButKeepsCurrent(t *testing.T) {
	root := protectedRetentionDirectory(t)
	current := retentionFixture(t, root, "installing")
	for _, phase := range []string{"installed", "rejected", "installed", ""} {
		retentionFixture(t, root, phase)
	}
	orphan := filepath.Join(root, uuid.NewString())
	if err := os.Mkdir(orphan, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(orphan, ".target-interrupted"), []byte("partial download"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := reclaimTransactions(root, current.GetId(), noRetentionHelper); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 || entries[0].Name() != current.GetId() {
		t.Fatalf("retention did not preserve exactly the current transaction: %v %v", entries, err)
	}
}

func TestRetentionRequiresInactiveOwnedResolvedState(t *testing.T) {
	for _, scenario := range []string{"active", "locked", "ambiguous", "symlink", "hardlink", "mismatched"} {
		t.Run(scenario, func(t *testing.T) {
			root := protectedRetentionDirectory(t)
			tx := retentionFixture(t, root, "installed")
			path := filepath.Join(root, tx.GetId())
			active := noRetentionHelper
			switch scenario {
			case "active":
				active = func(string) (bool, error) { return true, nil }
			case "locked":
				fd, err := statefs.OpenDirectory(path)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = unix.Close(fd) }()
				if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
					t.Fatal(err)
				}
			case "ambiguous":
				if err := journal.WriteUpdateRecord(path, "helper.pb", &agentv1.AgentUpdateHelperState{Phase: "recovery_required", ObservedAt: timestamppb.Now()}); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(t.TempDir(), filepath.Join(path, "outside")); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(packagePath(path, tx), filepath.Join(path, "duplicate")); err != nil {
					t.Fatal(err)
				}
			case "mismatched":
				tx.Id = uuid.NewString()
				if err := journal.WriteUpdateRecord(path, "transaction.pb", tx); err != nil {
					t.Fatal(err)
				}
			}
			if err := reclaimTransactions(root, "", active); err == nil {
				t.Fatal("ambiguous transaction was reclaimed")
			}
			if _, err := os.Stat(packagePath(path, tx)); err != nil {
				t.Fatal("rejected reclamation removed recovery payload:", err)
			}
		})
	}
}

func TestRetentionReplaysPartialDeletionWithoutCrossingCurrent(t *testing.T) {
	root := protectedRetentionDirectory(t)
	current := retentionFixture(t, root, "installing")
	retired := retentionFixture(t, root, "installed")
	oldPath := filepath.Join(root, retired.GetId())
	retiredPath := filepath.Join(root, retiredPrefix+retired.GetId())
	if err := os.Rename(oldPath, retiredPath); err != nil {
		t.Fatal(err)
	}
	if err := syncDirectory(root); err != nil {
		t.Fatal(err)
	}
	// Emulate power loss after the retirement boundary and partial unlink.
	if err := os.Remove(filepath.Join(retiredPath, "transaction.pb")); err != nil {
		t.Fatal(err)
	}
	if err := reclaimTransactions(root, current.GetId(), noRetentionHelper); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(retiredPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("retired deletion was not replayed:", err)
	}
	if _, err := os.Stat(packagePath(filepath.Join(root, current.GetId()), current)); err != nil {
		t.Fatal("replay touched current recovery material:", err)
	}
}

func TestRetentionFollowsDurableJournalCutover(t *testing.T) {
	root := protectedRetentionDirectory(t)
	store, err := journal.OpenUpdates(root)
	if err != nil {
		t.Fatal(err)
	}
	old := retentionFixture(t, store.Directory, "installed")
	state := store.Load()
	state.Transaction, state.Phase, state.InstalledVersion = old, "installed", old.GetVersion()
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	// A staged-but-unadmitted UUID is an orphan; the installed receipt and
	// package for the durable current UUID cannot yet be reclaimed.
	orphan := retentionFixture(t, store.Directory, "")
	if err := reclaimTransactions(store.Directory, store.Load().GetTransaction().GetId(), noRetentionHelper); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(store.Directory, orphan.GetId())); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unadmitted staging was retained:", err)
	}
	if _, err := os.Stat(filepath.Join(store.Directory, old.GetId())); err != nil {
		t.Fatal("old current deleted before durable cutover:", err)
	}
	next := retentionFixture(t, store.Directory, "")
	state.Transaction, state.Phase = next, "staged"
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	// Reopen models a crash after journal cutover but before retirement.
	store, err = journal.OpenUpdates(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if err := reclaimTransactions(store.Directory, store.Load().GetTransaction().GetId(), noRetentionHelper); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(store.Directory, old.GetId())); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("superseded terminal material was not reclaimed:", err)
	}
	if _, err := os.Stat(packagePath(filepath.Join(store.Directory, next.GetId()), next)); err != nil {
		t.Fatal("durably admitted package was reclaimed:", err)
	}
}

func TestRetentionRefusesPersistentRecoveryOwnership(t *testing.T) {
	for _, kind := range []string{"unit", "dangling-link"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			if err := recoveryUnitAbsent(root); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, recoveryUnit)
			if kind == "unit" {
				if err := os.WriteFile(path, recoveryUnitBytes("/some/other/transaction"), 0644); err != nil {
					t.Fatal(err)
				}
			} else {
				wants := filepath.Join(root, "multi-user.target.wants")
				if err := os.Mkdir(wants, 0755); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(wants, recoveryUnit)
				if err := os.Symlink("../"+recoveryUnit, path); err != nil {
					t.Fatal(err)
				}
			}
			if err := recoveryUnitAbsent(root); err == nil {
				t.Fatal("another transaction's boot recovery was ignored")
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatal("reclamation changed another transaction's unit:", err)
			}
		})
	}
}
