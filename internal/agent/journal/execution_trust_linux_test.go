package journal

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"math"
	"net/url"
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

func acknowledgedState(t *testing.T) *agentv1.ExecutorJournalState {
	t.Helper()
	state := pendingState(t)
	state.PendingGrant = ""
	state.ExecutionRootJson = []byte("acknowledged-execution-root-json")
	state.BootstrapEnvelope = []byte("acknowledged-bootstrap-envelope")
	state.CertificatePem = bytes.Repeat([]byte("M"), 96)
	deviceID := uuid.NewString()
	generation := uuid.NewString()
	state.DeviceId = &deviceID
	state.EnrollmentGeneration = &generation
	state.RenewAfter = timestamppb.New(time.Unix(1_700_000_000, 0).UTC())
	return state
}

func TestExecutionTrustPreservesAcknowledgedAuthority(t *testing.T) {
	ctx := t.Context()
	state := acknowledgedState(t)
	const acknowledgedRevision int64 = 1
	directory := protectedDirectory(t)
	store, err := Initialize(ctx, directory, state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	_, original := authorityColumn(t, store.db)
	marker, err := os.ReadFile(filepath.Join(directory, markerName))
	if err != nil {
		t.Fatal(err)
	}

	authority, revision, err := store.Load(ctx)
	if err != nil || revision != acknowledgedRevision || !proto.Equal(authority, state) {
		t.Fatalf("initialized authority changed: revision=%d err=%v", revision, err)
	}
	if blobRevision, blob := authorityColumn(t, store.db); blobRevision != acknowledgedRevision || !bytes.Equal(blob, original) {
		t.Fatal("initialization rewrote acknowledged authority bytes")
	}
	trust, trustRevision, err := store.LoadExecutionTrust(ctx)
	if err != nil || trustRevision != 1 {
		t.Fatalf("initial trust row: revision=%d err=%v", trustRevision, err)
	}
	assertUnconfiguredTrust(t, trust, state.GetInstallationId())
	assertSchemaIdentity(t, store.db, schemaVersion)

	trust.RequestSha256 = bytes.Repeat([]byte{0x01}, 32)
	if again, _, err := store.LoadExecutionTrust(ctx); err != nil || !proto.Equal(again, unconfiguredExecutionTrust(state.GetInstallationId())) {
		t.Fatal("caller alias mutated stored execution trust")
	}
	acceptedAt := time.Unix(1_800_000_000, 0).UTC()
	configured := configuredTrust(state.GetInstallationId(), 3, 5, 2, acceptedAt)
	nextTrustRevision, err := store.UpdateExecutionTrust(ctx, trustRevision, configured)
	if err != nil || nextTrustRevision != 2 {
		t.Fatalf("first execution trust commit: revision=%d err=%v", nextTrustRevision, err)
	}
	if blobRevision, blob := authorityColumn(t, store.db); blobRevision != acknowledgedRevision || !bytes.Equal(blob, original) {
		t.Fatal("trust commit rewrote acknowledged authority")
	}

	rotated := proto.CloneOf(state)
	rotated.RenewAfter = timestamppb.New(acceptedAt)
	nextAuthority, err := store.Update(ctx, acknowledgedRevision, rotated)
	if err != nil || nextAuthority != acknowledgedRevision+1 {
		t.Fatalf("authority update: revision=%d err=%v", nextAuthority, err)
	}
	persistedTrust, persistedTrustRevision, err := store.LoadExecutionTrust(ctx)
	if err != nil || persistedTrustRevision != nextTrustRevision || !proto.Equal(persistedTrust, configured) {
		t.Fatal("authority update changed execution trust")
	}
	loadedAuthority, _, err := store.Load(ctx)
	if err != nil || !bytes.Equal(loadedAuthority.GetIdentityPrivateKey(), state.GetIdentityPrivateKey()) || !bytes.Equal(loadedAuthority.GetBootstrapEnvelope(), state.GetBootstrapEnvelope()) || !bytes.Equal(loadedAuthority.GetCertificatePem(), state.GetCertificatePem()) || loadedAuthority.GetDeviceId() != state.GetDeviceId() {
		t.Fatal("authority update rewrote identity, bootstrap, or enrollment pins")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, directory)
	if err != nil {
		t.Fatalf("journal did not reopen: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	reloaded, reloadedRevision, err := reopened.Load(ctx)
	if err != nil || reloadedRevision != nextAuthority || !proto.Equal(reloaded, rotated) {
		t.Fatalf("reopen lost acknowledged authority: revision=%d err=%v", reloadedRevision, err)
	}
	reloadedTrust, reloadedTrustRevision, err := reopened.LoadExecutionTrust(ctx)
	if err != nil || reloadedTrustRevision != nextTrustRevision || !proto.Equal(reloadedTrust, configured) {
		t.Fatal("reopen reset execution trust")
	}
	assertSchemaIdentity(t, reopened.db, schemaVersion)
	if got, err := os.ReadFile(filepath.Join(directory, markerName)); err != nil || !bytes.Equal(got, marker) {
		t.Fatal("reopen replaced the installation marker")
	}
}

func TestExecutionTrustDamageStaysHold(t *testing.T) {
	for _, failure := range []string{"missing table", "missing row", "corrupt row", "unknown fields", "installation mismatch", "oversized row", "unexpected version"} {
		t.Run(failure, func(t *testing.T) {
			ctx := t.Context()
			initial := acknowledgedState(t)
			directory := protectedDirectory(t)
			store, err := Initialize(ctx, directory, initial)
			if err != nil {
				t.Fatal(err)
			}
			_, authority := authorityColumn(t, store.db)
			var preserved []byte
			switch failure {
			case "missing table":
				_, err = store.db.ExecContext(ctx, `DROP TABLE execution_trust`)
			case "missing row":
				_, err = store.db.ExecContext(ctx, `DELETE FROM execution_trust`)
			case "corrupt row":
				preserved = []byte{0xff, 0x00}
				_, err = store.db.ExecContext(ctx, `UPDATE execution_trust SET state=? WHERE id=1`, preserved)
			case "unknown fields":
				state, _, loadErr := store.LoadExecutionTrust(ctx)
				if loadErr != nil {
					t.Fatal(loadErr)
				}
				state.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
				preserved, err = proto.Marshal(state)
				if err != nil {
					t.Fatal(err)
				}
				_, err = store.db.ExecContext(ctx, `UPDATE execution_trust SET state=? WHERE id=1`, preserved)
			case "installation mismatch":
				state, _, loadErr := store.LoadExecutionTrust(ctx)
				if loadErr != nil {
					t.Fatal(loadErr)
				}
				state.InstallationId = uuid.NewString()
				preserved, err = proto.MarshalOptions{Deterministic: true}.Marshal(state)
				if err != nil {
					t.Fatal(err)
				}
				_, err = store.db.ExecContext(ctx, `UPDATE execution_trust SET state=? WHERE id=1`, preserved)
			case "oversized row":
				preserved = bytes.Repeat([]byte{0xab}, maximumTrustBytes+1)
				_, err = store.db.ExecContext(ctx, `DROP TABLE execution_trust`)
				if err != nil {
					t.Fatal(err)
				}
				_, err = store.db.ExecContext(ctx, `CREATE TABLE execution_trust (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    revision INTEGER NOT NULL CHECK (revision > 0),
    state BLOB NOT NULL
) STRICT`)
				if err != nil {
					t.Fatal(err)
				}
				_, err = store.db.ExecContext(ctx, `INSERT INTO execution_trust (id, revision, state) VALUES (1, 3, ?)`, preserved)
			case "unexpected version":
				configured := configuredTrust(initial.GetInstallationId(), 2, 4, 1, time.Unix(1_800_000_000, 0).UTC())
				if _, err = store.UpdateExecutionTrust(ctx, 1, configured); err != nil {
					t.Fatal(err)
				}
				if err = store.db.QueryRowContext(ctx, `SELECT state FROM execution_trust WHERE id = 1`).Scan(&preserved); err != nil {
					t.Fatal(err)
				}
				preserved = append([]byte(nil), preserved...)
				_, err = store.db.ExecContext(ctx, `PRAGMA user_version = 1`)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if opened, err := Open(ctx, directory); !errors.Is(err, ErrRecoveryHold) {
				if opened != nil {
					_ = opened.Close()
				}
				t.Fatalf("%s did not stay hold: %v", failure, err)
			}
			after := inspectJournal(t, directory)
			if !after.hasAuthority || !bytes.Equal(after.authority, authority) {
				t.Fatalf("%s rewrote authority or reinitialized the journal", failure)
			}
			switch failure {
			case "missing table":
				if after.hasTrustTable || after.version != schemaVersion {
					t.Fatal("missing trust table was recreated")
				}
			case "missing row":
				if !after.hasTrustTable || after.hasTrustRow || after.version != schemaVersion {
					t.Fatal("missing trust row was reinserted")
				}
			case "unexpected version":
				if after.version != 1 || !after.hasTrustRow || after.trustRevision != 2 || !bytes.Equal(after.trust, preserved) {
					t.Fatal("unexpected schema version changed committed trust")
				}
			case "oversized row":
				if !after.hasTrustRow || after.trustRevision != 3 || !bytes.Equal(after.trust, preserved) || after.version != schemaVersion {
					t.Fatal("oversized trust row was replaced")
				}
			default:
				if !after.hasTrustRow || !bytes.Equal(after.trust, preserved) || after.version != schemaVersion {
					t.Fatal("damaged trust row was replaced")
				}
			}
		})
	}
}

func TestExecutionTrustCASAndRollbackFences(t *testing.T) {
	ctx := t.Context()
	initial := pendingState(t)
	directory := protectedDirectory(t)
	store, err := Initialize(ctx, directory, initial)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	_, authority := authorityColumn(t, store.db)
	acceptedAt := time.Unix(1_800_000_000, 0).UTC()
	baseline := configuredTrust(initial.GetInstallationId(), 2, 3, 4, acceptedAt)
	revision, err := store.UpdateExecutionTrust(ctx, 1, baseline)
	if err != nil || revision != 2 {
		t.Fatalf("baseline trust commit: revision=%d err=%v", revision, err)
	}

	rejections := []struct {
		name   string
		mutate func(*agentv1.ExecutionTrustState)
		rev    int64
		want   error
	}{
		{name: "configured to empty", mutate: func(state *agentv1.ExecutionTrustState) {
			*state = *unconfiguredExecutionTrust(initial.GetInstallationId())
		}, rev: revision, want: ErrTrustRejected},
		{name: "root version rollback", mutate: func(state *agentv1.ExecutionTrustState) {
			state.Root.Version = 1
			state.DelegationVersion = 9
		}, rev: revision, want: ErrTrustRejected},
		{name: "same delegation version", mutate: func(state *agentv1.ExecutionTrustState) { state.RequestSha256[0] ^= 0xff }, rev: revision, want: ErrTrustRejected},
		{name: "lower delegation version", mutate: func(state *agentv1.ExecutionTrustState) { state.DelegationVersion = 2 }, rev: revision, want: ErrTrustRejected},
		{name: "recovery epoch rollback", mutate: func(state *agentv1.ExecutionTrustState) {
			state.DelegationVersion = 8
			state.MinimumRecoveryEpoch = 3
		}, rev: revision, want: ErrTrustRejected},
		{name: "accepted_at rollback", mutate: func(state *agentv1.ExecutionTrustState) {
			state.DelegationVersion = 8
			state.AcceptedAt = timestamppb.New(acceptedAt.Add(-time.Second))
		}, rev: revision, want: ErrTrustRejected},
		{name: "wrong installation", mutate: func(state *agentv1.ExecutionTrustState) {
			state.InstallationId = uuid.NewString()
			state.DelegationVersion = 8
		}, rev: revision, want: ErrTrustRejected},
		{name: "unknown field", mutate: func(state *agentv1.ExecutionTrustState) {
			state.DelegationVersion = 8
			state.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
		}, rev: revision, want: ErrTrustRejected},
		{name: "nil state", rev: revision, want: ErrTrustRejected},
		{name: "zero revision", mutate: func(state *agentv1.ExecutionTrustState) { state.DelegationVersion = 8 }, rev: 0, want: ErrConflict},
		{name: "revision overflow", mutate: func(state *agentv1.ExecutionTrustState) { state.DelegationVersion = 8 }, rev: math.MaxInt64, want: ErrConflict},
		{name: "stale revision", mutate: func(state *agentv1.ExecutionTrustState) { state.DelegationVersion = 8 }, rev: 1, want: ErrConflict},
	}
	for _, rejection := range rejections {
		t.Run(rejection.name, func(t *testing.T) {
			var next *agentv1.ExecutionTrustState
			if rejection.name != "nil state" {
				next = proto.CloneOf(baseline)
				rejection.mutate(next)
			}
			if _, err := store.UpdateExecutionTrust(ctx, rejection.rev, next); !errors.Is(err, rejection.want) {
				t.Fatalf("%s: %v", rejection.name, err)
			}
			got, gotRevision, err := store.LoadExecutionTrust(ctx)
			if err != nil || gotRevision != revision || !proto.Equal(got, baseline) {
				t.Fatalf("%s changed stored trust: revision=%d err=%v", rejection.name, gotRevision, err)
			}
			if _, blob := authorityColumn(t, store.db); !bytes.Equal(blob, authority) {
				t.Fatalf("%s changed authority", rejection.name)
			}
		})
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	advanced := proto.CloneOf(baseline)
	advanced.DelegationVersion = 8
	if _, err := store.UpdateExecutionTrust(cancelled, revision, advanced); !errors.Is(err, context.Canceled) || errors.Is(err, ErrRecoveryHold) {
		t.Fatalf("cancelled trust update misclassified: %v", err)
	}

	sameRoot := proto.CloneOf(baseline)
	sameRoot.DelegationVersion = 6
	sameRoot.RequestSha256 = bytes.Repeat([]byte{0x22}, 32)
	sameRoot.MinimumRecoveryEpoch = 4
	sameRoot.AcceptedAt = timestamppb.New(acceptedAt)
	jumped, err := store.UpdateExecutionTrust(ctx, revision, sameRoot)
	if err != nil || jumped != revision+1 {
		t.Fatalf("same root version and equal accepted_at rejected: revision=%d err=%v", jumped, err)
	}
	forward := proto.CloneOf(sameRoot)
	forward.Root.Version = 6
	forward.DelegationVersion = 11
	forward.MinimumRecoveryEpoch = 9
	forward.AcceptedAt = timestamppb.New(acceptedAt.Add(time.Hour))
	forward.DelegationEnvelope = []byte{}
	if _, err := store.UpdateExecutionTrust(ctx, jumped, forward); !errors.Is(err, ErrTrustRejected) {
		t.Fatalf("empty delegation on a configured successor accepted: %v", err)
	}
	forward.DelegationEnvelope = []byte("later-delegation")
	finalRevision, err := store.UpdateExecutionTrust(ctx, jumped, forward)
	if err != nil || finalRevision != jumped+1 {
		t.Fatalf("forward root and recovery epoch rejected: revision=%d err=%v", finalRevision, err)
	}
	loaded, loadedRevision, err := store.LoadExecutionTrust(ctx)
	if err != nil || loadedRevision != finalRevision || !proto.Equal(loaded, forward) {
		t.Fatal("accepted trust fence was not stored")
	}
	if _, blob := authorityColumn(t, store.db); !bytes.Equal(blob, authority) {
		t.Fatal("accepted trust update changed authority")
	}
	loaded.DelegationEnvelope[0] = 'X'
	if again, _, err := store.LoadExecutionTrust(ctx); err != nil || !bytes.Equal(again.GetDelegationEnvelope(), forward.GetDelegationEnvelope()) {
		t.Fatal("caller alias mutated stored delegation")
	}

	first, second := proto.CloneOf(forward), proto.CloneOf(forward)
	first.DelegationVersion = 20
	second.DelegationVersion = 21
	first.RequestSha256 = bytes.Repeat([]byte{0x31}, 32)
	second.RequestSha256 = bytes.Repeat([]byte{0x32}, 32)
	type outcome struct {
		state    *agentv1.ExecutionTrustState
		revision int64
		err      error
	}
	results := make(chan outcome, 2)
	var workers sync.WaitGroup
	for _, state := range []*agentv1.ExecutionTrustState{first, second} {
		workers.Go(func() {
			next, err := store.UpdateExecutionTrust(ctx, finalRevision, state)
			results <- outcome{state, next, err}
		})
	}
	workers.Wait()
	close(results)
	var accepted *agentv1.ExecutionTrustState
	conflicts := 0
	for result := range results {
		if errors.Is(result.err, ErrConflict) {
			conflicts++
			continue
		}
		if result.err != nil || result.revision != finalRevision+1 || accepted != nil {
			t.Fatalf("concurrent trust replacement: %v revision=%d", result.err, result.revision)
		}
		accepted = result.state
	}
	if accepted == nil || conflicts != 1 {
		t.Fatal("trust CAS did not select exactly one commit")
	}
	if _, blob := authorityColumn(t, store.db); !bytes.Equal(blob, authority) {
		t.Fatal("trust CAS changed authority")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.LoadExecutionTrust(ctx); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed trust load usable: %v", err)
	}
	reopened, err := Open(ctx, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	persisted, persistedRevision, err := reopened.LoadExecutionTrust(ctx)
	if err != nil || persistedRevision != finalRevision+1 || !proto.Equal(persisted, accepted) {
		t.Fatalf("winning trust commit lost on reopen: revision=%d err=%v", persistedRevision, err)
	}
}

func configuredTrust(installationID string, rootVersion, delegationVersion, epoch uint64, accepted time.Time) *agentv1.ExecutionTrustState {
	return &agentv1.ExecutionTrustState{
		FormatVersion:        1,
		InstallationId:       installationID,
		Root:                 testRoot(rootVersion),
		DelegationEnvelope:   []byte("delegation-envelope"),
		AcceptedAt:           timestamppb.New(accepted.UTC()),
		RequestSha256:        bytes.Repeat([]byte{0x5a}, 32),
		DelegationVersion:    delegationVersion,
		MinimumRecoveryEpoch: epoch,
	}
}

func testRoot(version uint64) *agentv1.ExecutionRoot {
	return &agentv1.ExecutionRoot{
		DeploymentId: uuid.NewString(),
		Version:      version,
		NotBefore:    timestamppb.New(time.Unix(1_700_000_000, 0).UTC()),
		ExpiresAt:    timestamppb.New(time.Unix(1_900_000_000, 0).UTC()),
		Threshold:    1,
		Keys: []*agentv1.ExecutionKey{{
			KeyId:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			PublicKey: bytes.Repeat([]byte{0x11}, 32),
		}},
	}
}

func assertUnconfiguredTrust(t *testing.T, state *agentv1.ExecutionTrustState, installationID string) {
	t.Helper()
	if state.GetFormatVersion() != 1 || state.GetInstallationId() != installationID || executionTrustConfigured(state) || state.GetRoot() != nil || state.GetAcceptedAt() != nil || len(state.GetDelegationEnvelope()) != 0 || len(state.GetRequestSha256()) != 0 || state.GetDelegationVersion() != 0 || state.GetMinimumRecoveryEpoch() != 0 {
		t.Fatal("execution trust was not the unconfigured installation binding")
	}
}

func assertSchemaIdentity(t *testing.T, db *sql.DB, version int) {
	t.Helper()
	var gotVersion, appID int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&gotVersion); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`PRAGMA application_id`).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	if gotVersion != version || appID != applicationID {
		t.Fatalf("schema identity version=%d app=%d", gotVersion, appID)
	}
}

func authorityColumn(t *testing.T, db *sql.DB) (int64, []byte) {
	t.Helper()
	var revision int64
	var state []byte
	if err := db.QueryRow(`SELECT revision, state FROM executor_state WHERE id = 1`).Scan(&revision, &state); err != nil {
		t.Fatal(err)
	}
	return revision, append([]byte(nil), state...)
}

type journalFacts struct {
	version       int
	appID         int
	authority     []byte
	authorityRev  int64
	hasAuthority  bool
	trust         []byte
	trustRevision int64
	hasTrustRow   bool
	hasTrustTable bool
}

func inspectJournal(t *testing.T, directory string) journalFacts {
	t.Helper()
	db := openFixtureDB(t, directory, "ro")
	defer func() { _ = db.Close() }()
	var facts journalFacts
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&facts.version); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`PRAGMA application_id`).Scan(&facts.appID); err != nil {
		t.Fatal(err)
	}
	err := db.QueryRow(`SELECT revision, state FROM executor_state WHERE id = 1`).Scan(&facts.authorityRev, &facts.authority)
	if err == nil {
		facts.hasAuthority = true
		facts.authority = append([]byte(nil), facts.authority...)
	} else if !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
	var present int
	err = db.QueryRow(`SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'execution_trust'`).Scan(&present)
	if err == nil {
		facts.hasTrustTable = true
	} else if !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
	if facts.hasTrustTable {
		err = db.QueryRow(`SELECT revision, state FROM execution_trust WHERE id = 1`).Scan(&facts.trustRevision, &facts.trust)
		if err == nil {
			facts.hasTrustRow = true
			facts.trust = append([]byte(nil), facts.trust...)
		} else if !errors.Is(err, sql.ErrNoRows) {
			t.Fatal(err)
		}
	}
	return facts
}

func openFixtureDB(t *testing.T, directory, mode string) *sql.DB {
	t.Helper()
	uri := url.URL{Scheme: "file", Path: filepath.Join(directory, databaseName)}
	uri.RawQuery = url.Values{"mode": {mode}}.Encode()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		t.Fatal(err)
	}
	return db
}
