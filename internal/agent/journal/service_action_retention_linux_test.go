package journal

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal/journaldb"
)

func TestServiceReadOnlyRetentionPreservesFloorsAndProtectedHistory(t *testing.T) {
	f := newServiceJournalFixture(t)
	granted := f.record(t, 1, "periodic.service", true)
	if _, err := f.store.AcceptServiceAction(t.Context(), 1, 2, granted); err != nil {
		t.Fatal(err)
	}
	granted = serviceQueued(granted)
	if _, err := f.store.UpdateServiceAction(t.Context(), 1, 1, 2, granted); err != nil {
		t.Fatal(err)
	}
	granted = serviceRunning(granted)
	if _, err := f.store.UpdateServiceAction(t.Context(), 2, 1, 2, granted); err != nil {
		t.Fatal(err)
	}
	granted = serviceCompleted(granted)
	if _, err := f.store.UpdateServiceAction(t.Context(), 3, 1, 2, granted); err != nil {
		t.Fatal(err)
	}
	failed := f.record(t, 2, "periodic.service", true)
	if _, err := f.store.AcceptServiceAction(t.Context(), 1, 2, failed); err != nil {
		t.Fatal(err)
	}
	failed.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_FAILED
	failed.Failure = agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_OBSERVATION
	failed.CompletedAt = timestamppb.New(failed.GetAcceptedAt().AsTime().Add(time.Second))
	if _, err := f.store.UpdateServiceAction(t.Context(), 1, 1, 2, failed); err != nil {
		t.Fatal(err)
	}
	idle := f.record(t, 1, "idle.service", false)
	if _, err := f.store.AcceptServiceAction(t.Context(), 1, 2, idle); err != nil {
		t.Fatal(err)
	}
	var first, latest *agentv1.ServiceExecutionRecord
	for sequence := uint64(3); sequence <= 262; sequence++ {
		latest = f.record(t, sequence, "periodic.service", false)
		if first == nil {
			first = latest
		}
		if _, err := f.store.AcceptServiceAction(t.Context(), 1, 2, latest); err != nil {
			t.Fatalf("periodic admission %d: %v", sequence, err)
		}
	}
	if _, _, err := f.store.LoadServiceAction(t.Context(), first.GetIntent().GetActionId()); !errors.Is(err, ErrServiceActionNotFound) {
		t.Fatalf("old read-only record not pruned: %v", err)
	}
	assertServiceRecord(t, f.store, granted, 4)
	assertServiceRecord(t, f.store, failed, 2)
	assertServiceRecord(t, f.store, idle, 1)
	assertServiceRecord(t, f.store, latest, 1)
	usage, err := f.store.queries.ReadServiceActionUsage(t.Context())
	if err != nil || usage.RecordCount != 260 {
		t.Fatalf("expected256 retained nonfloor successes +2 floors +2 protected records: %v %v", usage, err)
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	f.store, err = Open(t.Context(), f.directory)
	if err != nil {
		t.Fatalf("pruned history failed restart integrity: %v", err)
	}
	assertServiceRecord(t, f.store, idle, 1)
	for _, replay := range []*agentv1.ServiceExecutionRecord{first, f.record(t, 2, "periodic.service", false), proto.CloneOf(latest)} {
		if _, err := f.store.AcceptServiceAction(t.Context(), 1, 2, replay); !errors.Is(err, ErrServiceActionRejected) {
			t.Fatalf("retention revived replay below durable floor: %v", err)
		}
	}
}

func TestServiceReadOnlyRetentionRollback(t *testing.T) {
	f := newServiceJournalFixture(t)
	var oldest *agentv1.ServiceExecutionRecord
	for sequence := uint64(1); sequence <= 257; sequence++ {
		record := f.record(t, sequence, "periodic.service", false)
		if oldest == nil {
			oldest = record
		}
		if _, err := f.store.AcceptServiceAction(t.Context(), 1, 2, record); err != nil {
			t.Fatal(err)
		}
	}
	before := serviceDatabaseSnapshot(t, f.store.db)
	// Abort after INSERT, floor advance and DELETE have executed in the real
	// admission transaction, at the accounting write immediately before commit.
	if _, err := f.store.db.Exec("CREATE TRIGGER retention_fault BEFORE UPDATE ON service_action_usage BEGIN SELECT RAISE(ABORT, 'injected write failure'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AcceptServiceAction(t.Context(), 1, 2, f.record(t, 258, "periodic.service", false)); err == nil {
		t.Fatal("injected durable write failure was ignored")
	}
	if _, err := f.store.db.Exec("DROP TRIGGER retention_fault"); err != nil {
		t.Fatal(err)
	}
	if after := serviceDatabaseSnapshot(t, f.store.db); after != before {
		t.Fatal("failed admission partially pruned evidence, advanced floor or changed accounting")
	}
	assertServiceRecord(t, f.store, oldest, 1)
	if err := f.store.validateServiceActions(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestServiceReadOnlyRetentionCrashBeforeCommit(t *testing.T) {
	const childKey = "LINDM_TEST_RETENTION_CRASH_DIRECTORY"
	if directory := os.Getenv(childKey); directory != "" {
		store, err := Open(t.Context(), directory)
		if err != nil {
			t.Fatal(err)
		}
		// A new read-only action makes the oldest nonfloor eligible. Exercise
		// the production prune helper/accounting inside an uncommitted SQLite
		// transaction, then terminate without Close or rollback defers.
		tx, err := store.db.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		q := store.queries.WithTx(tx)
		row, err := q.NextServiceAction(t.Context(), "")
		if err != nil {
			t.Fatal(err)
		}
		record, err := store.decodeServiceAction(row)
		if err != nil {
			t.Fatal(err)
		}
		fixture := serviceJournalFixture{
			authority: &agentv1.ExecutorJournalState{InstallationId: record.GetInstallationId(), DeviceId: proto.String(record.GetIntent().GetDeviceId()), EnrollmentGeneration: proto.String(record.GetIntent().GetEnrollmentGeneration())},
			trust:     &agentv1.ExecutionTrustState{Root: record.GetAcceptedRoot(), DelegationEnvelope: record.GetAcceptedDelegationEnvelope()},
		}
		next := fixture.record(t, 258, "periodic.service", false)
		encoded, err := store.encodeServiceAction(next)
		if err != nil {
			t.Fatal(err)
		}
		intent := next.GetIntent()
		if err := q.InsertServiceAction(t.Context(), journaldb.InsertServiceActionParams{ActionID: intent.GetActionId(), DeploymentID: intent.GetDeploymentId(), DeviceID: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), Unit: intent.GetDesired().GetUnit(), ResourceSequence: 258, State: int64(next.GetState()), Record: encoded, ReadOnlySuccess: 1}); err != nil {
			t.Fatal(err)
		}
		if err := q.RaiseServiceResourceFloor(t.Context(), journaldb.RaiseServiceResourceFloorParams{DeploymentID: intent.GetDeploymentId(), DeviceID: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), Unit: intent.GetDesired().GetUnit(), ResourceSequence: 258, ActionID: intent.GetActionId()}); err != nil {
			t.Fatal(err)
		}
		count, size, err := store.pruneReadOnlyServiceActions(t.Context(), q)
		if err != nil || count != 1 {
			t.Fatalf("crash did not reach real pruning boundary: count=%d err=%v", count, err)
		}
		usage, err := q.ReadServiceActionUsage(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err := changeServiceActionUsage(t.Context(), q, usage, 1-count, int64(len(encoded))-size); err != nil {
			t.Fatal(err)
		}
		os.Exit(0)
	}
	f := newServiceJournalFixture(t)
	for sequence := uint64(1); sequence <= 257; sequence++ {
		if _, err := f.store.AcceptServiceAction(t.Context(), 1, 2, f.record(t, sequence, "periodic.service", false)); err != nil {
			t.Fatal(err)
		}
	}
	before := serviceDatabaseSnapshot(t, f.store.db)
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestServiceReadOnlyRetentionCrashBeforeCommit$")
	command.Env = append(os.Environ(), childKey+"="+f.directory)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("crash subprocess: %v\n%s", err, output)
	}
	var err error
	f.store, err = Open(t.Context(), f.directory)
	if err != nil {
		t.Fatalf("crash left unrecoverable retention state: %v", err)
	}
	if after := serviceDatabaseSnapshot(t, f.store.db); after != before {
		t.Fatal("crash before commit lost evidence or changed the sequence floor/accounting")
	}
}

func TestServiceReadOnlyMarkerIntegrity(t *testing.T) {
	f := newServiceJournalFixture(t)
	record := f.record(t, 1, "example.service", false)
	if _, err := f.store.AcceptServiceAction(t.Context(), 1, 2, record); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec("UPDATE service_actions SET read_only_success=0"); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	if store, err := Open(t.Context(), f.directory); !errors.Is(err, ErrRecoveryHold) {
		if store != nil {
			_ = store.Close()
		}
		t.Fatalf("changed retention marker escaped integrity checks: %v", err)
	}
}
