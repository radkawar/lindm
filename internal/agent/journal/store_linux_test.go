package journal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func pendingState(t *testing.T) *agentv1.ExecutorJournalState {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	// Journal tests exercise durable typed storage, not bootstrap verification.
	// Signature/trust validation is a separate executor admission boundary.
	return &agentv1.ExecutorJournalState{FormatVersion: 1, InstallationId: uuid.NewString(), ExecutionRootJson: []byte("root-bytes"), BootstrapEnvelope: []byte("envelope-bytes"), BootstrapVerifiedAt: timestamppb.New(time.Now().UTC()), EnrollmentTransactionId: uuid.NewString(), IdentityPrivateKey: key, EnrollmentCsrPem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), PendingGrant: "test-only-grant-with-at-least-32-characters"}
}

func protectedDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestJournalDurableReopenAndCAS(t *testing.T) {
	ctx := t.Context()
	directory := protectedDirectory(t)
	if _, err := Open(ctx, directory); !errors.Is(err, ErrUnprovisioned) {
		t.Fatalf("empty directory: %v", err)
	}
	initial := pendingState(t)
	store, err := Initialize(ctx, directory, initial)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := Open(ctx, directory); !errors.Is(err, ErrAlreadyOpen) {
		t.Fatalf("second owner accepted: %v", err)
	}
	loaded, revision, err := store.Load(ctx)
	if err != nil || revision != 1 || !proto.Equal(initial, loaded) {
		t.Fatalf("initial authority changed: revision=%d err=%v", revision, err)
	}
	loaded.PendingGrant = "caller-mutation-is-not-a-durable-journal-update"
	again, _, err := store.Load(ctx)
	if err != nil || !proto.Equal(initial, again) {
		t.Fatal("caller alias mutated stored authority")
	}
	first, second := proto.CloneOf(initial), proto.CloneOf(initial)
	first.PendingGrant = "first-competing-durable-grant-for-test-only"
	second.PendingGrant = "second-competing-durable-grant-for-test-only"
	type outcome struct {
		state    *agentv1.ExecutorJournalState
		revision int64
		err      error
	}
	results := make(chan outcome, 2)
	var workers sync.WaitGroup
	for _, state := range []*agentv1.ExecutorJournalState{first, second} {
		workers.Go(func() { next, err := store.Update(ctx, revision, state); results <- outcome{state, next, err} })
	}
	workers.Wait()
	close(results)
	var accepted *agentv1.ExecutorJournalState
	conflicts := 0
	for result := range results {
		if errors.Is(result.err, ErrConflict) {
			conflicts++
			continue
		}
		if result.err != nil || result.revision != 2 || accepted != nil {
			t.Fatalf("concurrent state replacement: %v revision=%d", result.err, result.revision)
		}
		accepted = result.state
	}
	if accepted == nil || conflicts != 1 {
		t.Fatal("CAS did not select exactly one authority transition")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(ctx); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed store usable: %v", err)
	}
	reopened, err := Open(ctx, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	persisted, revision, err := reopened.Load(ctx)
	if err != nil || revision != 2 || !proto.Equal(accepted, persisted) {
		t.Fatalf("acknowledged authority lost on reopen: revision=%d err=%v", revision, err)
	}
	for _, name := range []string{markerName, databaseName, databaseName + "-wal", databaseName + "-shm"} {
		info, err := os.Lstat(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatalf("protected state exposed: %s %s", name, info.Mode())
		}
	}
}

func TestJournalRejectsPartialCorruptOrReplacedState(t *testing.T) {
	for _, failure := range []string{"missing database", "missing marker", "mismatched marker", "corrupt database", "corrupt protobuf", "wrong schema", "unknown fields", "invalid state", "unsafe database mode", "unsafe directory mode", "database symlink", "database hardlink"} {
		t.Run(failure, func(t *testing.T) {
			ctx := t.Context()
			directory := protectedDirectory(t)
			store, err := Initialize(ctx, directory, pendingState(t))
			if err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "corrupt protobuf":
				_, err = store.db.ExecContext(ctx, `UPDATE executor_state SET state=? WHERE id=1`, []byte{0xff})
			case "wrong schema":
				// Version 2 is the execution-trust schema. A later version stays hold.
				_, err = store.db.ExecContext(ctx, `PRAGMA user_version = 3`)
			case "unknown fields", "invalid state":
				state, _, loadErr := store.Load(ctx)
				if loadErr != nil {
					t.Fatal(loadErr)
				}
				if failure == "unknown fields" {
					state.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
				} else {
					state.SessionEpoch = 1
				}
				encoded, encodeErr := proto.Marshal(state)
				if encodeErr != nil {
					t.Fatal(encodeErr)
				}
				_, err = store.db.ExecContext(ctx, `UPDATE executor_state SET state=? WHERE id=1`, encoded)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "missing database":
				err = os.Remove(filepath.Join(directory, databaseName))
			case "missing marker":
				err = os.Remove(filepath.Join(directory, markerName))
			case "mismatched marker":
				err = os.WriteFile(filepath.Join(directory, markerName), []byte(uuid.NewString()+"\n"), 0600)
			case "corrupt database":
				err = os.WriteFile(filepath.Join(directory, databaseName), bytes.Repeat([]byte{0xff}, 4096), 0600)
			case "unsafe database mode":
				err = os.Chmod(filepath.Join(directory, databaseName), 0644)
			case "unsafe directory mode":
				err = os.Chmod(directory, 0750)
			case "database symlink":
				outside := filepath.Join(protectedDirectory(t), "database")
				if err := os.Rename(filepath.Join(directory, databaseName), outside); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(outside, filepath.Join(directory, databaseName))
			case "database hardlink":
				err = os.Link(filepath.Join(directory, databaseName), filepath.Join(protectedDirectory(t), "alias"))
			}
			if err != nil {
				t.Fatal(err)
			}
			if opened, err := Open(ctx, directory); !errors.Is(err, ErrRecoveryHold) {
				if opened != nil {
					_ = opened.Close()
				}
				t.Fatalf("%s did not fail closed: %v", failure, err)
			}
		})
	}
}

func TestJournalInvalidTransitionDoesNotReplaceAuthority(t *testing.T) {
	ctx := t.Context()
	initial := pendingState(t)
	store, err := Initialize(ctx, protectedDirectory(t), initial)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	for _, mutate := range []func(*agentv1.ExecutorJournalState){
		func(state *agentv1.ExecutorJournalState) { state.InstallationId = uuid.NewString() },
		func(state *agentv1.ExecutorJournalState) { state.PendingGrant = "" },
		func(state *agentv1.ExecutorJournalState) { state.SessionEpoch = 1 },
		func(state *agentv1.ExecutorJournalState) { state.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01}) },
	} {
		state := proto.CloneOf(initial)
		mutate(state)
		if _, err := store.Update(ctx, 1, state); err == nil {
			t.Fatal("invalid replacement accepted")
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.Update(cancelled, 1, initial); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled state update misclassified: %v", err)
	}
	actual, revision, err := store.Load(ctx)
	if err != nil || revision != 1 || !proto.Equal(actual, initial) {
		t.Fatalf("failed replacement damaged prior authority: revision=%d err=%v", revision, err)
	}
}

func TestJournalRejectsReplaceableAncestorBeforeWritingAuthority(t *testing.T) {
	parent := protectedDirectory(t)
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(parent, "executor")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := Initialize(t.Context(), directory, pendingState(t))
	if store != nil {
		_ = store.Close()
	}
	if !errors.Is(err, ErrRecoveryHold) {
		t.Fatalf("private authority accepted beneath attacker-replaceable ancestry: %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("rejected ancestry received protected provisioning state")
	}
}

func TestJournalCancellationIsNotRecoveryHold(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancelled", true: "deadline"}[timeout], func(t *testing.T) {
			ctx := t.Context()
			directory := protectedDirectory(t)
			store, err := Initialize(ctx, directory, pendingState(t))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = store.Close() }()
			var interrupted context.Context
			var cancel context.CancelFunc
			want := context.Canceled
			if timeout {
				interrupted, cancel = context.WithDeadline(ctx, time.Unix(1, 0))
				want = context.DeadlineExceeded
			} else {
				interrupted, cancel = context.WithCancel(ctx)
			}
			cancel()
			if _, _, err := store.Load(interrupted); !errors.Is(err, want) || errors.Is(err, ErrRecoveryHold) {
				t.Errorf("interrupted read misclassified: %v", err)
			}
			if err := store.verifyDatabase(interrupted); !errors.Is(err, want) {
				t.Errorf("interrupted integrity check misclassified: %v", err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			opened, err := Open(interrupted, directory)
			if opened != nil {
				_ = opened.Close()
			}
			if !errors.Is(err, want) || errors.Is(err, ErrRecoveryHold) {
				t.Errorf("interrupted open misclassified: %v", err)
			}
			recovered, err := Open(ctx, directory)
			if err != nil {
				t.Fatalf("cancelled request damaged healthy authority: %v", err)
			}
			defer func() { _ = recovered.Close() }()
		})
	}
}
