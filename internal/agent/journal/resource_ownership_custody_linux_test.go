package journal

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/privatecustody"
)

const privateBaselineToken = "$6$never-in-sqlite$exact-password-baseline"

func claimedPrivateAccount(t *testing.T, f serviceJournalFixture) *agentv1.ResourceOwnershipLedger {
	t.Helper()
	record := queueOwnershipAction(t, f, accountResourceRecord(t, f, resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER))
	baseline := ownershipSnapshot(record)
	baseline.Observation.GetLocalUser().Exists = true
	baseline.Observation.GetLocalUser().Uid = proto.Uint32(1200)
	baseline.AccountPrivate.PasswordToken = proto.String(privateBaselineToken)
	ledger, err := f.store.ClaimResourceOwnership(t.Context(), record.GetIntent().GetActionId(), 0, baseline)
	if err != nil {
		t.Fatal(err)
	}
	return ledger
}

func TestAccountOwnershipDiskNeverContainsPasswordBaseline(t *testing.T) {
	f := newServiceJournalFixture(t)
	ledger := claimedPrivateAccount(t, f)
	if ledger.GetBaseline().GetAccountPrivate().GetPasswordToken() != privateBaselineToken {
		t.Fatal("caller did not retain exact process-local baseline")
	}
	var encoded []byte
	if err := f.store.db.QueryRow("SELECT record FROM resource_ownership").Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(privateBaselineToken)) {
		t.Fatal("plaintext password baseline persisted in SQLite record")
	}
	disk := new(agentv1.ResourceOwnershipLedger)
	if err := proto.Unmarshal(encoded, disk); err != nil {
		t.Fatal(err)
	}
	private := disk.GetBaseline().GetAccountPrivate()
	if private.PasswordToken != nil || private.GetEncryptedPasswordToken() == nil {
		t.Fatal("disk wire did not use typed encrypted secret custody")
	}
	beforeDigest, err := ResourceOwnershipDigest(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	database, err := os.ReadFile(filepath.Join(f.directory, databaseName))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(database, []byte(privateBaselineToken)) {
		t.Fatal("plaintext password leaked through SQLite pages or WAL checkpoint")
	}
	reopened, err := Open(t.Context(), f.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	loaded, err := reopened.LoadResourceOwnership(t.Context(), ledger.GetDeploymentId(), ledger.GetDeviceId(), ledger.GetEnrollmentGeneration(), ledger.GetRef())
	if err != nil || loaded.GetBaseline().GetAccountPrivate().GetPasswordToken() != privateBaselineToken {
		t.Fatal("encrypted baseline did not restore exact process-local token")
	}
	afterDigest, err := ResourceOwnershipDigest(loaded)
	if err != nil || beforeDigest != afterDigest {
		t.Fatal("encrypted custody changed signed ownership digest across restart")
	}
	unsealed := proto.CloneOf(loaded)
	unsealed.Baseline.AccountPrivate.EncryptedPasswordToken = nil
	if _, err := ResourceOwnershipDigest(unsealed); err == nil {
		t.Fatal("public ledger digest accepted unkeyed secret digest")
	}
}

func TestAccountOwnershipCiphertextCorruptionAndKeyLossHold(t *testing.T) {
	for _, damage := range []string{"ciphertext", "nonce", "tag", "plaintext", "role", "revision", "missing_key", "wrong_key"} {
		t.Run(damage, func(t *testing.T) {
			f := newServiceJournalFixture(t)
			claimedPrivateAccount(t, f)
			var encoded []byte
			if err := f.store.db.QueryRow("SELECT record FROM resource_ownership").Scan(&encoded); err != nil {
				t.Fatal(err)
			}
			disk := new(agentv1.ResourceOwnershipLedger)
			if err := proto.Unmarshal(encoded, disk); err != nil {
				t.Fatal(err)
			}
			if err := f.store.Close(); err != nil {
				t.Fatal(err)
			}
			switch damage {
			case "missing_key":
				if err := os.Remove(filepath.Join(f.directory, privatecustody.KeyFileName)); err != nil {
					t.Fatal(err)
				}
			case "wrong_key":
				key, err := os.ReadFile(filepath.Join(f.directory, privatecustody.KeyFileName))
				if err != nil {
					t.Fatal(err)
				}
				key[len(key)-1]++
				if err := os.WriteFile(filepath.Join(f.directory, privatecustody.KeyFileName), key, 0600); err != nil {
					t.Fatal(err)
				}
				clear(key)
			default:
				secret := disk.Baseline.AccountPrivate.EncryptedPasswordToken
				switch damage {
				case "ciphertext":
					secret.Ciphertext[0]++
				case "nonce":
					secret.Nonce[0]++
				case "tag":
					secret.EqualityTag[0]++
				case "plaintext":
					disk.Baseline.AccountPrivate.PasswordToken = proto.String(privateBaselineToken)
				case "role":
					disk.LastApplied = disk.Baseline
					disk.Baseline = proto.CloneOf(disk.LastApplied)
				case "revision":
					disk.Revision++
				}
				encoded, err := proto.Marshal(disk)
				if err != nil {
					t.Fatal(err)
				}
				db := openFixtureDB(t, f.directory, "rw")
				if _, err := db.Exec("UPDATE resource_ownership SET record = ?", encoded); err != nil {
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if store, err := Open(t.Context(), f.directory); !errors.Is(err, ErrRecoveryHold) {
				if store != nil {
					_ = store.Close()
				}
				t.Fatalf("corrupt private custody reopened: %v", err)
			}
			if damage == "missing_key" {
				if _, err := os.Stat(filepath.Join(f.directory, privatecustody.KeyFileName)); !os.IsNotExist(err) {
					t.Fatal("journal regenerated lost key")
				}
			}
		})
	}
}

func TestImperativeAccountLockEncryptedAtRestAndRevisionBound(t *testing.T) {
	directory := protectedDirectory(t)
	store, err := Initialize(t.Context(), directory, pendingState(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	ledger := accountLedgerFixture()
	if _, err := store.CreateAccountLock(t.Context(), ledger); err != nil {
		t.Fatal(err)
	}
	var original []byte
	if err := store.db.QueryRow("SELECT record FROM account_locks").Scan(&original); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(original, []byte("$6$private-test-hash")) || bytes.Contains(original, []byte("alice:")) {
		t.Fatal("imperative account lock persisted raw shadow baseline")
	}
	envelope := new(agentv1.PrivateCustodyEnvelope)
	if err := proto.Unmarshal(original, envelope); err != nil || envelope.GetFormatVersion() != 1 {
		t.Fatal("account lock record did not use typed encrypted custody")
	}
	next := proto.CloneOf(ledger)
	next.Accounts[0].Phase = agentv1.AccountLockPhase_ACCOUNT_LOCK_PHASE_DISABLED
	if _, err := store.UpdateAccountLock(t.Context(), 1, next); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("UPDATE account_locks SET record = ?", original); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.LoadAccountLock(t.Context(), ledger.GetLockActionId()); !errors.Is(err, ErrRecoveryHold) {
		t.Fatalf("old ciphertext replayed under new ledger revision: %v", err)
	}
}
