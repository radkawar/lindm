package spool

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/agent/spool/spooldb"
)

func spoolDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func testIdentity() Identity {
	return Identity{Deployment: uuid.New(), Device: uuid.New(), Generation: uuid.New()}
}

func openSynced(t *testing.T, directory string, id Identity, hostHigh, packageHigh uint64) *Store {
	t.Helper()
	store, err := Open(t.Context(), directory, id)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := store.Recovery(t.Context())
	if err != nil || !recovery.NeedsSync || recovery.Reason != ReasonUnsynchronized {
		t.Fatalf("fresh spool recovery: %+v %v", recovery, err)
	}
	if err := store.Synchronize(t.Context(), hostHigh, packageHigh); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func observed(value string) *inventoryv1.ObservedString {
	return &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: value}
}

func observation(hostname string, status inventoryv1.CollectionStatus, packages ...*inventoryv1.Package) *inventoryv1.NativeObservation {
	start := time.Unix(1_700_000_000, 0).UTC()
	finish := start.Add(time.Second)
	return &inventoryv1.NativeObservation{
		Host: &inventoryv1.HostObservation{
			StartedAt: timestamppb.New(start), FinishedAt: timestamppb.New(finish),
			BootId: observed("boot"), Hostname: observed(hostname), OsId: observed("debian"),
			OsVersion: observed("12"), Architecture: observed("amd64"), KernelRelease: observed("6.8.0"),
			HardwareVendor: observed("vendor"), HardwareModel: observed("model"), HardwareSerial: observed("serial"),
		},
		Packages: &inventoryv1.PackageObservation{
			StartedAt: timestamppb.New(start), FinishedAt: timestamppb.New(finish),
			Status: status, Backend: "dpkg", Packages: packages,
		},
	}
}

func pkg(name, version string) *inventoryv1.Package {
	return &inventoryv1.Package{Name: name, Version: version, Architecture: "amd64", Manager: "dpkg"}
}

func collectionNames(t *testing.T, directory string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(directory, collectionsName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func TestSpoolReopenPreservesExactPendingBytes(t *testing.T) {
	ctx := t.Context()
	directory := spoolDirectory(t)
	id := testIdentity()
	store := openSynced(t, directory, id, 4, 9)
	if err := store.Queue(ctx, observation("host-a", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, pkg("bash", "5.2.15"), pkg("coreutils", "9.4"))); err != nil {
		t.Fatal(err)
	}
	queuedHost, queuedPkg, err := store.Queued(ctx)
	if err != nil || !queuedHost || !queuedPkg {
		t.Fatalf("queued=%v %v err=%v", queuedHost, queuedPkg, err)
	}
	row, err := store.queries.ReadPackageSlot(ctx, slotQueued)
	if err != nil || row.Sequence != 0 || row.SnapshotID != "" {
		t.Fatalf("queued collection received a sequence: %+v %v", row, err)
	}
	promoted, err := store.PromotePackage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if promoted.Sequence != 10 || !promoted.Success || promoted.BatchCount != 1 || promoted.Manifest.GetSequence() != 10 {
		t.Fatalf("promotion=%+v", promoted)
	}
	if promoted.Manifest.ProtoReflect().Descriptor().Fields().ByName("session_epoch") != nil {
		t.Fatal("manifest carries session epoch")
	}
	parsed, err := uuid.Parse(promoted.Manifest.GetSnapshotId())
	if err != nil || parsed.Version() != 7 {
		t.Fatalf("snapshot id %s: %v", promoted.Manifest.GetSnapshotId(), err)
	}
	ms := int64(parsed[0])<<40 | int64(parsed[1])<<32 | int64(parsed[2])<<24 | int64(parsed[3])<<16 | int64(parsed[4])<<8 | int64(parsed[5])
	if promoted.Manifest.GetCreatedAt().AsTime().Sub(time.UnixMilli(ms).UTC()).Abs() > time.Second {
		t.Fatal("created_at does not match UUIDv7 time")
	}
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(promoted.Manifest)
	if err != nil || !bytes.Equal(canonical, promoted.CanonicalManifest) || sha256.Sum256(canonical) != promoted.ManifestDigest {
		t.Fatal("canonical manifest digest changed")
	}
	original, err := store.Batch(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(original) != [32]byte(promoted.Manifest.GetBatches()[0].GetSha256()) {
		t.Fatal("batch digest does not match manifest")
	}
	host, err := store.PromoteHost(ctx)
	if err != nil || host.Sequence != 5 || host.Observation.GetHostname().GetValue() != "host-a" {
		t.Fatalf("host promotion=%+v %v", host, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, directory, id)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	recovery, err := reopened.Recovery(ctx)
	if err != nil || !recovery.NeedsSync || recovery.Reason != ReasonFence || recovery.PackageAllocated != 10 || recovery.HostAllocated != 5 {
		t.Fatalf("healthy reopen: %+v %v", recovery, err)
	}
	if _, err := reopened.Batch(ctx, 0); !errors.Is(err, ErrNeedsSync) {
		t.Fatalf("upload before fence: %v", err)
	}
	pendingBefore, ok, err := reopened.PendingPackage(ctx)
	if err != nil || !ok || !bytes.Equal(pendingBefore.CanonicalManifest, promoted.CanonicalManifest) {
		t.Fatal("pending manifest unreadable during fence")
	}
	if err := reopened.Synchronize(ctx, 4, 9); err != nil {
		t.Fatal(err)
	}
	again, err := reopened.Batch(ctx, 0)
	if err != nil || !bytes.Equal(original, again) {
		t.Fatal("pending batch bytes changed across restart")
	}
	pending, ok, err := reopened.PendingPackage(ctx)
	if err != nil || !ok || !bytes.Equal(pending.CanonicalManifest, promoted.CanonicalManifest) {
		t.Fatal("pending manifest changed across restart")
	}
}

func TestSpoolDamagedBlobRequiresSyncAndDoesNotRewind(t *testing.T) {
	ctx := t.Context()
	directory := spoolDirectory(t)
	id := testIdentity()
	store := openSynced(t, directory, id, 0, 0)
	if err := store.Queue(ctx, observation("host", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, pkg("bash", "1"))); err != nil {
		t.Fatal(err)
	}
	promoted, err := store.PromotePackage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	names := collectionNames(t, directory)
	if len(names) != 1 {
		t.Fatalf("collections=%v", names)
	}
	path := filepath.Join(directory, collectionsName, names[0], "b000")
	payload, err := os.ReadFile(path)
	if err != nil || len(payload) == 0 {
		t.Fatal(err)
	}
	payload[0] ^= 0xff
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	damaged, err := Open(ctx, directory, id)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = damaged.Close() }()
	recovery, err := damaged.Recovery(ctx)
	if err != nil || !recovery.NeedsSync || recovery.Reason != ReasonDamagedPending || !recovery.LostAdmittedUploadMayRemain {
		t.Fatalf("damaged recovery: %+v %v", recovery, err)
	}
	if _, _, err := damaged.PendingPackage(ctx); !errors.Is(err, ErrNeedsSync) {
		t.Fatalf("damaged pending published: %v", err)
	}
	if _, err := damaged.Batch(ctx, 0); !errors.Is(err, ErrNeedsSync) {
		t.Fatalf("damaged batch published: %v", err)
	}
	if err := damaged.Synchronize(ctx, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := damaged.Queue(ctx, observation("host", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, pkg("coreutils", "2"))); err != nil {
		t.Fatal(err)
	}
	next, err := damaged.PromotePackage(ctx)
	if err != nil || next.Sequence != promoted.Sequence+1 {
		t.Fatalf("rewound or skipped sequence: got=%d want=%d err=%v", next.Sequence, promoted.Sequence+1, err)
	}
}

func TestSpoolMissingDatabaseReconcilesServerHighWater(t *testing.T) {
	ctx := t.Context()
	directory := spoolDirectory(t)
	id := testIdentity()
	store := openSynced(t, directory, id, 3, 4)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{databaseName, databaseName + "-wal", databaseName + "-shm"} {
		if err := os.Remove(filepath.Join(directory, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(directory, collectionsName, uuid.NewString()), 0700); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, directory, id)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	recovery, err := reopened.Recovery(ctx)
	if err != nil || !recovery.NeedsSync || !recovery.LostAdmittedUploadMayRemain {
		t.Fatalf("missing spool: %+v %v", recovery, err)
	}
	if err := reopened.Queue(ctx, observation("held", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, pkg("bash", "1"))); !errors.Is(err, ErrNeedsSync) {
		t.Fatalf("missing spool reinitialized: %v", err)
	}
	if _, err := os.Stat(filepath.Join(directory, databaseName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing spool was recreated before sync")
	}
	if err := reopened.Synchronize(ctx, 7, 8); err != nil {
		t.Fatal(err)
	}
	if names := collectionNames(t, directory); len(names) != 0 {
		t.Fatalf("untracked collection survived recovery: %v", names)
	}
	if err := reopened.Queue(ctx, observation("host", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, pkg("bash", "1"))); err != nil {
		t.Fatal(err)
	}
	host, err := reopened.PromoteHost(ctx)
	pkgUpload, pkgErr := reopened.PromotePackage(ctx)
	if err != nil || pkgErr != nil || host.Sequence != 8 || pkgUpload.Sequence != 9 {
		t.Fatalf("host=%d pkg=%d err=%v %v", host.Sequence, pkgUpload.Sequence, err, pkgErr)
	}
	again, err := reopened.Recovery(ctx)
	if err != nil || !again.LostAdmittedUploadMayRemain {
		t.Fatal("loss recovery claimed the server upload was reset")
	}
}

func TestSpoolScopeChangeDoesNotResumeOldPending(t *testing.T) {
	ctx := t.Context()
	directory := spoolDirectory(t)
	id := testIdentity()
	store := openSynced(t, directory, id, 0, 0)
	if err := store.Queue(ctx, observation("old-host", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, pkg("bash", "1"))); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PromotePackage(ctx); err != nil {
		t.Fatal(err)
	}
	original, err := store.Batch(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	nextID := id
	nextID.Generation = uuid.New()
	reopened, err := Open(ctx, directory, nextID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	recovery, err := reopened.Recovery(ctx)
	if err != nil || !recovery.NeedsSync || recovery.Reason != ReasonScopeChange || recovery.Stored != id {
		t.Fatalf("scope change: %+v %v", recovery, err)
	}
	if _, _, err := reopened.PendingPackage(ctx); !errors.Is(err, ErrNeedsSync) {
		t.Fatalf("old generation pending resumed: %v", err)
	}
	if err := reopened.Synchronize(ctx, 2, 2); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Queue(ctx, observation("new-host", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, pkg("zsh", "5"))); err != nil {
		t.Fatal(err)
	}
	promoted, err := reopened.PromotePackage(ctx)
	if err != nil || promoted.Sequence != 3 || promoted.Manifest.GetEnrollmentGeneration() != nextID.Generation.String() {
		t.Fatalf("rebound promotion=%+v %v", promoted, err)
	}
	fresh, err := reopened.Batch(ctx, 0)
	if err != nil || bytes.Equal(fresh, original) {
		t.Fatal("new generation reused the previous generation payload")
	}
}

func TestSpoolQueueReplacementLeavesPendingImmutable(t *testing.T) {
	ctx := t.Context()
	directory := spoolDirectory(t)
	store := openSynced(t, directory, testIdentity(), 0, 0)
	first := observation("first", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, pkg("bash", "1"))
	second := observation("second", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, pkg("zsh", "2"))
	third := observation("third", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, pkg("dash", "3"))
	if err := store.Queue(ctx, first); err != nil {
		t.Fatal(err)
	}
	firstNames := collectionNames(t, directory)
	if err := store.Queue(ctx, second); err != nil {
		t.Fatal(err)
	}
	if names := collectionNames(t, directory); len(names) != 1 || names[0] == firstNames[0] {
		t.Fatalf("queued collection was not replaced: before=%v after=%v", firstNames, names)
	}
	pending, err := store.PromotePackage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	original, err := store.Batch(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Queue(ctx, third); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PromotePackage(ctx); !errors.Is(err, ErrPending) {
		t.Fatalf("second promotion: %v", err)
	}
	again, err := store.Batch(ctx, 0)
	if err != nil || !bytes.Equal(original, again) {
		t.Fatal("pending bytes changed while the queue was replaced")
	}
	if names := collectionNames(t, directory); len(names) != 2 {
		t.Fatalf("pending plus queued collections=%v", names)
	}
	if pending.Sequence == 0 {
		t.Fatal("pending sequence was not allocated")
	}
}

func TestSpoolSuccessZeroIsDistinctFromFailure(t *testing.T) {
	ctx := t.Context()
	store := openSynced(t, spoolDirectory(t), testIdentity(), 0, 0)
	if err := store.Queue(ctx, observation("host", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS)); err != nil {
		t.Fatal(err)
	}
	zero, err := store.PromotePackage(ctx)
	if err != nil || !zero.Success || zero.BatchCount != 0 || len(zero.Manifest.GetBatches()) != 0 || len(zero.CanonicalManifest) == 0 {
		t.Fatalf("zero snapshot=%+v %v", zero, err)
	}
	if err := store.FinishPackage(ctx, zero.Sequence, zero.Sequence, TerminalAdmitted); err != nil {
		t.Fatal(err)
	}
	if err := store.Queue(ctx, observation("host", inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT)); err != nil {
		t.Fatal(err)
	}
	failed, err := store.PromotePackage(ctx)
	if err != nil || failed.Success || failed.Manifest != nil || failed.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT || failed.Backend != "dpkg" {
		t.Fatalf("failure=%+v %v", failed, err)
	}
	if _, err := store.Batch(ctx, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failure exposed a batch: %v", err)
	}
	if err := store.FinishPackage(ctx, failed.Sequence, 0, TerminalExpired); err != nil {
		t.Fatal(err)
	}
	if err := store.Queue(ctx, observation("host", inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT)); err != nil {
		t.Fatal(err)
	}
	next, err := store.PromotePackage(ctx)
	if err != nil || next.Sequence != failed.Sequence+1 {
		t.Fatalf("expired attempt rewound the counter: got=%d err=%v", next.Sequence, err)
	}
}

func TestSpoolHostCoalesceAndAcknowledge(t *testing.T) {
	ctx := t.Context()
	store := openSynced(t, spoolDirectory(t), testIdentity(), 0, 0)
	if err := store.Queue(ctx, observation("first", inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE)); err != nil {
		t.Fatal(err)
	}
	if err := store.Queue(ctx, observation("second", inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE)); err != nil {
		t.Fatal(err)
	}
	pending, err := store.PromoteHost(ctx)
	if err != nil || pending.Observation.GetHostname().GetValue() != "second" || pending.Sequence != 1 {
		t.Fatalf("coalesce=%+v %v", pending.Observation.GetHostname().GetValue(), err)
	}
	if err := store.Queue(ctx, observation("third", inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE)); err != nil {
		t.Fatal(err)
	}
	still, ok, err := store.PendingHost(ctx)
	if err != nil || !ok || still.Observation.GetHostname().GetValue() != "second" {
		t.Fatal("queued host mutated the pending observation")
	}
	if err := store.AcknowledgeHost(ctx, pending.Sequence, 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("low ack: %v", err)
	}
	if _, ok, err := store.PendingHost(ctx); err != nil || !ok {
		t.Fatal("conflict ack discarded pending")
	}
	if err := store.AcknowledgeHost(ctx, pending.Sequence, pending.Sequence); err != nil {
		t.Fatal(err)
	}
	if err := store.AcknowledgeHost(ctx, pending.Sequence, pending.Sequence); err != nil {
		t.Fatalf("idempotent ack: %v", err)
	}
	third, err := store.PromoteHost(ctx)
	if err != nil || third.Sequence != 2 || third.Observation.GetHostname().GetValue() != "third" {
		t.Fatalf("next host=%+v %v", third, err)
	}
}

func TestSpoolBatchLimitsAndCounterCap(t *testing.T) {
	packages := make([]*inventoryv1.Package, 501)
	for i := range packages {
		packages[i] = pkg("pkg", "1")
	}
	planned, _, err := planBatches(packages)
	if err != nil || len(planned) != 2 || planned[0].records != 500 || planned[1].records != 1 {
		t.Fatalf("500-record split: batches=%d err=%v", len(planned), err)
	}
	wide := make([]*inventoryv1.Package, 400)
	version := strings.Repeat("v", 2000)
	for i := range wide {
		wide[i] = pkg("pkg", version)
	}
	split, total, err := planBatches(wide)
	if err != nil || len(split) < 2 || total > CollectionBudget {
		t.Fatalf("encoded split: batches=%d total=%d err=%v", len(split), total, err)
	}
	for _, plan := range split {
		buf, _, err := assembleBatch(plan)
		if err != nil || len(buf) > MaxBatchEncoded || len(buf) != plan.size {
			t.Fatalf("batch accounting size=%d plan=%d err=%v", len(buf), plan.size, err)
		}
	}
	tooMany := make([]*inventoryv1.Package, MaxPackageRecords+1)
	for i := range tooMany {
		tooMany[i] = pkg("pkg", "1")
	}
	if _, _, err := planBatches(tooMany); !errors.Is(err, ErrCapacity) {
		t.Fatalf("record cap: %v", err)
	}
	ctx := t.Context()
	store := openSynced(t, spoolDirectory(t), testIdentity(), 0, 0)
	if err := store.Queue(ctx, observation("host", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, packages...)); err != nil {
		t.Fatal(err)
	}
	promoted, err := store.PromotePackage(ctx)
	if err != nil || promoted.BatchCount != 2 {
		t.Fatalf("stored split=%d err=%v", promoted.BatchCount, err)
	}
	if _, err := store.Batch(ctx, 2); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing batch: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE scope SET host_allocated = ? WHERE id = 1`, int64(math.MaxInt64)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PromoteHost(ctx); !errors.Is(err, ErrCapacity) {
		t.Fatalf("counter wrap: %v", err)
	}
}

func TestSpoolBudgetCapsAndUnrecognizedEntry(t *testing.T) {
	ctx := t.Context()
	directory := spoolDirectory(t)
	store := openSynced(t, directory, testIdentity(), 0, 0)
	var pages, journalLimit, page int
	if err := store.db.QueryRowContext(ctx, "PRAGMA max_page_count").Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, "PRAGMA journal_size_limit").Scan(&journalLimit); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&page); err != nil {
		t.Fatal(err)
	}
	if pages != maxPageCount || journalLimit != journalSizeLimit || page != pageSize || page*pages+journalLimit > MetadataBudget {
		t.Fatalf("sqlite cap pages=%d page=%d journal=%d", pages, page, journalLimit)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(directory, "notes")
	if err := os.WriteFile(extra, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, directory, testIdentity())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	recovery, err := reopened.Recovery(ctx)
	if err != nil || !recovery.NeedsSync || recovery.Reason != ReasonUnrecognized {
		t.Fatalf("unrecognized: %+v %v", recovery, err)
	}
	if err := reopened.Synchronize(ctx, 1, 1); !errors.Is(err, ErrUnrecognized) {
		t.Fatalf("unrecognized entry deleted or ignored: %v", err)
	}
	if _, err := os.ReadFile(extra); err != nil {
		t.Fatal("unrecognized file was removed")
	}
}

func TestSpoolCancellationIsNotCorruption(t *testing.T) {
	ctx := t.Context()
	directory := spoolDirectory(t)
	id := testIdentity()
	store := openSynced(t, directory, id, 0, 0)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := store.PendingHost(cancelled); !errors.Is(err, context.Canceled) || errors.Is(err, ErrNeedsSync) {
		t.Fatalf("cancelled read: %v", err)
	}
	if err := store.Queue(ctx, observation("host", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, pkg("bash", "1"))); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(cancelled, directory, id); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled open: %v", err)
	}
	reopened, err := Open(ctx, directory, id)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	if _, err := reopened.PromotePackage(ctx); !errors.Is(err, ErrNeedsSync) {
		t.Fatalf("promote before fence: %v", err)
	}
	if err := reopened.Synchronize(ctx, 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.PromotePackage(ctx); err != nil {
		t.Fatalf("cancelled request damaged the spool: %v", err)
	}
}

func TestSpoolRejectsSecondOwnerAndUnsafeBoundary(t *testing.T) {
	ctx := t.Context()
	directory := spoolDirectory(t)
	store := openSynced(t, directory, testIdentity(), 0, 0)
	if _, err := Open(ctx, directory, testIdentity()); !errors.Is(err, ErrAlreadyOpen) {
		t.Fatalf("second owner: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, directory, testIdentity()); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("unsafe mode: %v", err)
	}
	parent := spoolDirectory(t)
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(parent, "spool")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, child, testIdentity()); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("replaceable ancestry: %v", err)
	}
	entries, err := os.ReadDir(child)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("rejected ancestry received spool files")
	}
}

func TestSpoolErrorsDoNotContainObservationText(t *testing.T) {
	store := openSynced(t, spoolDirectory(t), testIdentity(), 0, 0)
	obs := observation("secret-hostname", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, pkg("secret-package", "1"))
	obs.Host.Hostname.Value = ""
	err := store.Queue(t.Context(), obs)
	if err == nil || strings.Contains(err.Error(), "secret-hostname") || strings.Contains(err.Error(), "secret-package") {
		t.Fatalf("observation leaked: %v", err)
	}
}

func TestSpoolOrphanCollectionIsRemovedOnReopen(t *testing.T) {
	ctx := t.Context()
	directory := spoolDirectory(t)
	id := testIdentity()
	store := openSynced(t, directory, id, 0, 0)
	orphan := uuid.NewString()
	if err := os.Mkdir(filepath.Join(directory, collectionsName, orphan), 0700); err != nil {
		t.Fatal(err)
	}
	if err := store.queries.InsertOwned(ctx, spooldb.InsertOwnedParams{CollectionID: orphan, Referenced: 0, ByteSize: 0}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, directory, id)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	if _, err := os.Stat(filepath.Join(directory, collectionsName, orphan)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan collection remained: %v", err)
	}
}

func TestSpoolQueueBeforeSynchronizeDoesNotAllocate(t *testing.T) {
	ctx := t.Context()
	directory := spoolDirectory(t)
	id := testIdentity()
	store, err := Open(ctx, directory, id)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if err := store.Queue(ctx, observation("offline", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, pkg("bash", "1"), pkg("zsh", "2"))); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PromotePackage(ctx); !errors.Is(err, ErrNeedsSync) {
		t.Fatalf("promote before sync: %v", err)
	}
	row, err := store.queries.ReadPackageSlot(ctx, slotQueued)
	if err != nil || row.Sequence != 0 {
		t.Fatalf("queued sequence=%d err=%v", row.Sequence, err)
	}
	scope, err := store.queries.ReadScope(ctx)
	if err != nil || scope.Synced != 0 || scope.PackageAllocated != 0 {
		t.Fatalf("pre-sync scope=%+v %v", scope, err)
	}
	if err := store.Synchronize(ctx, 5, 6); err != nil {
		t.Fatal(err)
	}
	promoted, err := store.PromotePackage(ctx)
	if err != nil || promoted.Sequence != 7 || promoted.BatchCount != 1 {
		t.Fatalf("post-sync promotion=%+v %v", promoted, err)
	}
	if err := store.MarkBatchAccepted(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkBatchAccepted(ctx, 0); err != nil {
		t.Fatalf("idempotent Put hint without local Begin hint: %v", err)
	}
	if err := store.MarkBatchAccepted(ctx, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("nonexistent batch accepted without local Begin hint: %v", err)
	}
	pending, ok, err := store.PendingPackage(ctx)
	if err != nil || !ok || len(pending.AcceptedBatches) != 1 || pending.AcceptedBatches[0] != 0 || pending.BeginAccepted {
		t.Fatalf("progress=%+v %v", pending.AcceptedBatches, err)
	}
	if err := store.FinishPackage(ctx, promoted.Sequence, promoted.Sequence, TerminalAdmitted); err != nil {
		t.Fatalf("committed receipt required local acks: %v", err)
	}
}

func TestSpoolAllowsTransportStatusAndRemovesItsTemp(t *testing.T) {
	ctx := t.Context()
	directory := spoolDirectory(t)
	id := testIdentity()
	store := openSynced(t, directory, id, 0, 0)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	status := []byte("public-status")
	if err := os.WriteFile(filepath.Join(directory, transportStatusName), status, 0600); err != nil {
		t.Fatal(err)
	}
	temp := filepath.Join(directory, transportStatusTempPrefix+"abc")
	if err := os.WriteFile(temp, status, 0600); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, directory, id)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	recovery, err := reopened.Recovery(ctx)
	if err != nil || recovery.Reason == ReasonUnrecognized {
		t.Fatalf("status file rejected: %+v %v", recovery, err)
	}
	got, err := os.ReadFile(filepath.Join(directory, transportStatusName))
	if err != nil || !bytes.Equal(got, status) {
		t.Fatal("transport status was removed or changed")
	}
	if _, err := os.Stat(temp); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("status temp remained: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "notes"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	blocked, err := Open(ctx, directory, id)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocked.Close() }()
	recovery, err = blocked.Recovery(ctx)
	if err != nil || recovery.Reason != ReasonUnrecognized {
		t.Fatalf("arbitrary file accepted: %+v %v", recovery, err)
	}
}
