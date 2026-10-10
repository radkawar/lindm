package journal

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func accountLedgerFixture() *agentv1.AccountLockLedger {
	prior := &agentv1.AccountLockSnapshot{Username: "alice", Uid: 1000, PasswdEntry: "alice:x:1000:1000:Alice:/home/alice:/bin/bash", ShadowEntry: "alice:$6$private-test-hash:20000:0:99999:7:::"}
	expected := proto.CloneOf(prior)
	expected.ShadowEntry = "alice:!$6$private-test-hash:20000:0:99999:7::1:"
	return &agentv1.AccountLockLedger{LockActionId: uuid.NewString(), Accounts: []*agentv1.AccountLockEntry{{Prior: prior, Expected: expected, Phase: agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_DISABLE_PENDING}}}
}

func TestAccountLockJournalDurableOwnershipAndTransitions(t *testing.T) {
	directory := protectedDirectory(t)
	store, err := Initialize(t.Context(), directory, pendingState(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	ledger := accountLedgerFixture()
	revision, err := store.CreateAccountLock(t.Context(), ledger)
	if err != nil || revision != 1 {
		t.Fatalf("create ledger: revision=%d err=%v", revision, err)
	}
	if _, err := store.CreateAccountLock(t.Context(), ledger); !errors.Is(err, ErrAccountLockRejected) {
		t.Fatalf("same action replay: %v", err)
	}
	for _, collision := range []string{"name", "uid", "already-disabled"} {
		other := proto.CloneOf(ledger)
		other.LockActionId = uuid.NewString()
		switch collision {
		case "uid":
			for _, snapshot := range []*agentv1.AccountLockSnapshot{other.Accounts[0].Prior, other.Accounts[0].Expected} {
				snapshot.Username = "alias"
				snapshot.PasswdEntry = strings.Replace(snapshot.PasswdEntry, "alice:", "alias:", 1)
				snapshot.ShadowEntry = strings.Replace(snapshot.ShadowEntry, "alice:", "alias:", 1)
			}
		case "already-disabled":
			other.Accounts[0].Prior = proto.CloneOf(other.Accounts[0].Expected)
			other.Accounts[0].Phase = agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_PRESERVED
		}
		if _, err := store.CreateAccountLock(t.Context(), other); !errors.Is(err, ErrAccountLockRejected) {
			t.Fatalf("%s overlap accepted: %v", collision, err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(t.Context(), directory)
	if err != nil {
		t.Fatal(err)
	}
	loaded, revision, err := store.LoadAccountLock(t.Context(), ledger.GetLockActionId())
	if err != nil || revision != 1 || !proto.Equal(ledger, loaded) {
		t.Fatalf("pending state lost on reopen: %v", err)
	}
	for _, tamper := range []string{"prior", "expected", "release-without-pending"} {
		next := proto.CloneOf(loaded)
		switch tamper {
		case "prior":
			next.Accounts[0].Prior.ShadowEntry = "alice:$6$changed:20000:0:99999:7:::"
		case "expected":
			next.Accounts[0].Expected.ShadowEntry = "alice:!$6$changed:20000:0:99999:7::1:"
		case "release-without-pending":
			next.Accounts[0].Phase = agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_RELEASED
			next.Accounts[0].ReleaseActionId = uuid.NewString()
		}
		if _, err := store.UpdateAccountLock(t.Context(), revision, next); !errors.Is(err, ErrAccountLockRejected) {
			t.Fatalf("%s accepted: %v", tamper, err)
		}
	}
	loaded.Accounts[0].Phase = agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_RELEASE_PENDING
	loaded.Accounts[0].ReleaseActionId = uuid.NewString()
	revision, err = store.UpdateAccountLock(t.Context(), revision, loaded)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Accounts[0].Phase = agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_RELEASED
	if _, err := store.UpdateAccountLock(t.Context(), revision-1, loaded); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale phase revision accepted: %v", err)
	}
	if _, err := store.UpdateAccountLock(t.Context(), revision, loaded); err != nil {
		t.Fatal(err)
	}
	// A distinct future lock can own the restored account, but never reuse the
	// old lock identity or mutate its retained snapshots.
	other := accountLedgerFixture()
	if _, err := store.CreateAccountLock(t.Context(), other); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(t.Context(), directory)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAccountLockJournalBoundsAndPrivateErrors(t *testing.T) {
	store, err := Initialize(t.Context(), protectedDirectory(t), pendingState(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	invalid := accountLedgerFixture()
	invalid.Accounts[0].Prior.ShadowEntry = "alice:" + strings.Repeat("secret", 1000)
	if _, err := store.CreateAccountLock(t.Context(), invalid); !errors.Is(err, ErrAccountLockRejected) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("invalid private record error: %v", err)
	}
	for range maximumAccountLocks {
		if _, err := store.CreateAccountLock(t.Context(), &agentv1.AccountLockLedger{LockActionId: uuid.NewString()}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.CreateAccountLock(t.Context(), &agentv1.AccountLockLedger{LockActionId: uuid.NewString()}); !errors.Is(err, ErrAccountLockCapacity) {
		t.Fatalf("unbounded ledger admission: %v", err)
	}
}

func TestAccountLockJournalRejectsDamagedOwnership(t *testing.T) {
	directory := protectedDirectory(t)
	store, err := Initialize(t.Context(), directory, pendingState(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateAccountLock(t.Context(), accountLedgerFixture()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(t.Context(), "DELETE FROM account_lock_owners"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(t.Context(), directory)
	if reopened != nil {
		_ = reopened.Close()
	}
	if !errors.Is(err, ErrRecoveryHold) {
		t.Fatalf("lost ownership opened: %v", err)
	}
}

func TestAccountLockAbsenceDistinguishesPreEffectCrashFromDeletion(t *testing.T) {
	f := newServiceJournalFixture(t)
	record := journalActionRecord(t, f, 1)
	record.Intent.Spec.GetLockSessions().Usernames = []string{"alice"}
	record.Intent.SpecSha256 = journalActionDigest(t, record.Intent.GetSpec())
	record.NativePlan.Spec = proto.CloneOf(record.Intent.GetSpec())
	record.Challenge.SpecSha256 = record.Intent.GetSpecSha256()
	record.Challenge.NativePlan = proto.CloneOf(record.NativePlan)
	record.Challenge.NativePlanSha256 = journalActionDigest(t, record.NativePlan)
	if _, err := f.store.AcceptDeviceAction(t.Context(), 1, 2, record); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.UpdateDeviceAction(t.Context(), 1, 1, 2, journalActionRunning(record)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(t.Context(), f.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if _, _, err := store.LoadAccountLock(t.Context(), record.GetIntent().GetActionId()); !errors.Is(err, ErrAccountLockNotFound) {
		t.Fatalf("pre-ledger crash invented account ownership: %v", err)
	}
	ledger := &agentv1.AccountLockLedger{LockActionId: record.GetIntent().GetActionId()}
	if _, err := store.CreateAccountLock(t.Context(), ledger); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(t.Context(), "DELETE FROM account_locks"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.LoadAccountLock(t.Context(), ledger.GetLockActionId()); !errors.Is(err, ErrRecoveryHold) {
		t.Fatalf("deleted ledger treated as clean absence: %v", err)
	}
}
