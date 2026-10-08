package spool

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func TestSpoolPendingManifestCancellationPreservesQueue(t *testing.T) {
	ctx := t.Context()
	directory := spoolDirectory(t)
	store := openSynced(t, directory, testIdentity(), 0, 0)
	if err := store.Queue(ctx, observation("pending", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, pkg("bash", "1"))); err != nil {
		t.Fatal(err)
	}
	pending, err := store.PromotePackage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := store.Batch(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Queue(ctx, observation("queued", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, pkg("coreutils", "2"))); err != nil {
		t.Fatal(err)
	}
	queued, err := store.queries.ReadPackageSlot(ctx, slotQueued)
	if err != nil {
		t.Fatal(err)
	}
	queuedBatch, err := os.ReadFile(filepath.Join(directory, collectionsName, queued.CollectionID, "b000"))
	if err != nil {
		t.Fatal(err)
	}
	interrupted, cancel := context.WithCancel(ctx)
	defer cancel()
	store.afterPendingPackageRead = func() {
		store.afterPendingPackageRead = nil
		cancel()
	}
	if _, _, err := store.PendingPackage(interrupted); !errors.Is(err, context.Canceled) || errors.Is(err, ErrNeedsSync) {
		t.Errorf("cancellation after reading healthy manifest: %v", err)
	}
	recovery, err := store.Recovery(ctx)
	if err != nil || recovery.NeedsSync || recovery.LostAdmittedUploadMayRemain {
		t.Errorf("cancellation marked healthy pending damaged: %+v %v", recovery, err)
	}
	if err := store.Synchronize(ctx, 0, 0); err != nil {
		t.Fatal(err)
	}
	resumed, found, err := store.PendingPackage(ctx)
	if err != nil || !found || resumed.Sequence != pending.Sequence || !bytes.Equal(resumed.CanonicalManifest, pending.CanonicalManifest) || !proto.Equal(resumed.Manifest, pending.Manifest) {
		t.Fatalf("synchronization changed immutable pending upload: %+v found=%v err=%v", resumed, found, err)
	}
	gotBatch, err := store.Batch(ctx, 0)
	if err != nil || !bytes.Equal(gotBatch, batch) {
		t.Fatalf("synchronization deleted pending batch: %v", err)
	}
	hostQueued, packageQueued, err := store.Queued(ctx)
	if err != nil || !hostQueued || !packageQueued {
		t.Fatalf("synchronization deleted queued observation: host=%v package=%v err=%v", hostQueued, packageQueued, err)
	}
	if err := store.FinishPackage(ctx, pending.Sequence, pending.Sequence, TerminalAdmitted); err != nil {
		t.Fatal(err)
	}
	next, err := store.PromotePackage(ctx)
	if err != nil || next.Sequence != pending.Sequence+1 {
		t.Fatalf("queued upload could not resume: %+v %v", next, err)
	}
	gotBatch, err = store.Batch(ctx, 0)
	if err != nil || !bytes.Equal(gotBatch, queuedBatch) {
		t.Fatalf("queued batch changed after cancellation: %v", err)
	}
}

func TestSpoolUnusableOwnershipRecoversAfterServerFence(t *testing.T) {
	for _, corruption := range []string{"missing_table", "invalid_collection_id"} {
		for _, unexpected := range []bool{false, true} {
			name := corruption + "/validated_blobs"
			if unexpected {
				name = corruption + "/unexpected_entry"
			}
			t.Run(name, func(t *testing.T) {
				ctx := t.Context()
				directory := spoolDirectory(t)
				id := testIdentity()
				store := openSynced(t, directory, id, 3, 5)
				if err := store.Queue(ctx, observation("pending", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, pkg("bash", "1"))); err != nil {
					t.Fatal(err)
				}
				if _, err := store.PromotePackage(ctx); err != nil {
					t.Fatal(err)
				}
				row, err := store.queries.ReadPackageSlot(ctx, slotPending)
				if err != nil {
					t.Fatal(err)
				}
				blobPath := filepath.Join(directory, collectionsName, row.CollectionID, "b000")
				blob, err := os.ReadFile(blobPath)
				if err != nil || len(blob) == 0 {
					t.Fatalf("fixture lacks an existing blob: %v", err)
				}
				markerPath := filepath.Join(directory, collectionsName, row.CollectionID, "keep-me")
				if unexpected {
					if err := os.WriteFile(markerPath, []byte("not spool-owned"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if corruption == "missing_table" {
					if _, err := store.db.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
						t.Fatal(err)
					}
					if _, err := store.db.ExecContext(ctx, "DROP TABLE owned_dir"); err != nil {
						t.Fatal(err)
					}
				} else {
					if _, err := store.db.ExecContext(ctx, "INSERT INTO owned_dir (collection_id, referenced, byte_size) VALUES (?, 0, 0)", strings.Repeat("x", 36)); err != nil {
						t.Fatal(err)
					}
				}
				var integrity string
				if err := store.db.QueryRowContext(ctx, "PRAGMA quick_check(1)").Scan(&integrity); err != nil || integrity != "ok" {
					t.Fatalf("fixture is not structurally readable SQLite: %q %v", integrity, err)
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
				if err != nil || recovery.Reason != ReasonCorrupt || !recovery.NeedsSync || !recovery.LostAdmittedUploadMayRemain {
					t.Errorf("unusable ownership did not require corruption recovery: %+v %v", recovery, err)
				}
				if err := reopened.Queue(ctx, observation("blocked", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS)); !errors.Is(err, ErrNeedsSync) {
					t.Errorf("queue accepted before current-session fence: %v", err)
				}
				if _, err := reopened.PromotePackage(ctx); !errors.Is(err, ErrNeedsSync) {
					t.Errorf("promotion accepted before current-session fence: %v", err)
				}
				beforeFence, err := os.ReadFile(blobPath)
				if err != nil || !bytes.Equal(beforeFence, blob) {
					t.Fatalf("blob deleted before current-session fence: %v", err)
				}
				err = reopened.Synchronize(ctx, 41, 51)
				if unexpected {
					if !errors.Is(err, ErrUnrecognized) {
						t.Fatalf("unvalidated collection cleanup was not refused: %v", err)
					}
					got, err := os.ReadFile(markerPath)
					if err != nil || string(got) != "not spool-owned" {
						t.Fatalf("cleanup touched unknown entry: %q %v", got, err)
					}
					got, err = os.ReadFile(blobPath)
					if err != nil || !bytes.Equal(got, blob) {
						t.Fatalf("cleanup partially deleted unvalidated collection: %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("recover readable SQLite with unusable ownership after fence: %v", err)
				}
				if _, err := os.Stat(filepath.Dir(blobPath)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("validated stale collection was not removed: %v", err)
				}
				if err := reopened.Queue(ctx, observation("recovered", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, pkg("coreutils", "2"))); err != nil {
					t.Fatal(err)
				}
				host, hostErr := reopened.PromoteHost(ctx)
				packages, packageErr := reopened.PromotePackage(ctx)
				if hostErr != nil || packageErr != nil || host.Sequence != 42 || packages.Sequence != 52 {
					t.Fatalf("rebuild ignored current server high-water: host=%d package=%d errors=%v %v", host.Sequence, packages.Sequence, hostErr, packageErr)
				}
				if got, err := reopened.Batch(ctx, 0); err != nil || len(got) == 0 {
					t.Fatalf("rebuilt spool cannot read new payload: %v", err)
				}
			})
		}
	}
}

func TestSpoolConnectSupportsOfflineQueue(t *testing.T) {
	ctx := t.Context()
	store, err := Open(ctx, spoolDirectory(t), testIdentity())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if err := store.Queue(ctx, observation("offline", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, pkg("bash", "1"))); err != nil {
		t.Fatalf("initialize SQLite and persist an offline collection: %v", err)
	}
	if _, err := store.PromotePackage(ctx); !errors.Is(err, ErrNeedsSync) {
		t.Fatalf("offline queue allocated before current-session sync: %v", err)
	}
	if err := store.Synchronize(ctx, 10, 20); err != nil {
		t.Fatal(err)
	}
	upload, err := store.PromotePackage(ctx)
	if err != nil || upload.Sequence != 21 {
		t.Fatalf("promote after server fence: sequence=%d err=%v", upload.Sequence, err)
	}
	batch, err := store.Batch(ctx, 0)
	if err != nil || len(batch) == 0 {
		t.Fatalf("read persisted offline payload: %v", err)
	}
}

func TestSpoolQueuedZeroSuccessSurvivesReopen(t *testing.T) {
	ctx := t.Context()
	directory := spoolDirectory(t)
	id := testIdentity()
	store, err := Open(ctx, directory, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Queue(ctx, observation("offline-empty", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS)); err != nil {
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
	host, packages, err := reopened.Queued(ctx)
	if err != nil || !host || !packages {
		t.Fatalf("reopen discarded successful zero-package observation: host=%v package=%v err=%v", host, packages, err)
	}
	recovery, err := reopened.Recovery(ctx)
	if err != nil || !recovery.NeedsSync || recovery.PackageAllocated != 0 || recovery.HostAllocated != 0 {
		t.Fatalf("offline observation allocated a sequence: %+v %v", recovery, err)
	}
	if _, err := reopened.PromotePackage(ctx); !errors.Is(err, ErrNeedsSync) {
		t.Fatalf("promotion before current-session fence: %v", err)
	}
	if err := reopened.Synchronize(ctx, 7, 8); err != nil {
		t.Fatal(err)
	}
	upload, err := reopened.PromotePackage(ctx)
	if err != nil || !upload.Success || upload.Sequence != 9 || upload.BatchCount != 0 || upload.Manifest == nil || len(upload.CanonicalManifest) == 0 {
		t.Fatalf("zero-package success was changed to failure: %+v %v", upload, err)
	}
}

// Cancel only after SQLite has really committed. This is the crash window in
// which filesystem cleanup/checkpointing has not yet completed; no SQL or file
// operation is replaced with a fake implementation.
func cancelAfterCommit(t *testing.T, store *Store) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	store.afterCommit = func() {
		store.afterCommit = nil
		cancel()
	}
	t.Cleanup(func() {
		store.afterCommit = nil
		cancel()
	})
	return ctx
}

func TestSpoolReopenCleansOrphanDescriptors(t *testing.T) {
	ctx := t.Context()
	directory := spoolDirectory(t)
	id := testIdentity()
	store := openSynced(t, directory, id, 0, 0)
	if err := store.Queue(ctx, observation("pending", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, pkg("bash", "1"))); err != nil {
		t.Fatal(err)
	}
	pending, err := store.PromotePackage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Queue(ctx, observation("queued", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, pkg("zsh", "2"))); err != nil {
		t.Fatal(err)
	}
	if err := store.noteDamage(ctx); !errors.Is(err, ErrNeedsSync) {
		t.Fatal(err)
	}
	interrupted := cancelAfterCommit(t, store)
	if err := store.discardPayloads(interrupted); !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupt committed discard before filesystem cleanup: %v", err)
	}
	owned, err := store.queries.ListOwned(ctx)
	if err != nil || len(owned) != 2 {
		t.Fatalf("discard crash fixture has no orphan ownership rows: %v %v", owned, err)
	}
	for _, row := range owned {
		batches, err := store.queries.ListBatches(ctx, row.CollectionID)
		if err != nil || row.Referenced != 0 || len(batches) == 0 {
			t.Fatalf("discard crash fixture lost descriptor children: %+v %v", row, err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, directory, id)
	if err != nil {
		t.Fatalf("reopen orphan descriptors violated foreign keys: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	for _, row := range owned {
		batches, err := reopened.queries.ListBatches(ctx, row.CollectionID)
		if err != nil || len(batches) != 0 {
			t.Fatalf("orphan descriptors remain: %v %v", batches, err)
		}
	}
	remaining, err := reopened.queries.ListOwned(ctx)
	if err != nil || len(remaining) != 0 || len(collectionNames(t, directory)) != 0 {
		t.Fatalf("orphan ownership or payload remains: %v %v", remaining, err)
	}
	if err := reopened.Synchronize(ctx, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Queue(ctx, observation("replacement", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, pkg("dash", "3"))); err != nil {
		t.Fatal(err)
	}
	next, err := reopened.PromotePackage(ctx)
	if err != nil || next.Sequence != pending.Sequence+1 {
		t.Fatalf("orphan recovery rewound allocation: sequence=%d err=%v", next.Sequence, err)
	}
}

func nearLimitObservation(t *testing.T) *inventoryv1.NativeObservation {
	t.Helper()
	item := pkg("package", strings.Repeat("v", 2048))
	recordSize := proto.Size(&inventoryv1.PackageBatch{Packages: []*inventoryv1.Package{item}})
	packages := make([]*inventoryv1.Package, CollectionBudget/recordSize)
	for i := range packages {
		packages[i] = item
	}
	return observation("near-limit", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, packages...)
}

func physicalTreeBytes(t *testing.T, directory string) int64 {
	t.Helper()
	var total int64
	err := filepath.WalkDir(directory, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		var stat unix.Stat_t
		if err := unix.Lstat(path, &stat); err != nil {
			return err
		}
		total += stat.Blocks * 512
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return total
}

func TestSpoolPhysicalBlockOverheadSurvivesReopen(t *testing.T) {
	ctx := t.Context()
	directory := spoolDirectory(t)
	id := testIdentity()
	store := openSynced(t, directory, id, 0, 0)
	obs := nearLimitObservation(t)
	if err := store.Queue(ctx, obs); err != nil {
		t.Fatalf("admit first near-limit collection: %v", err)
	}
	pending, err := store.PromotePackage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	original, err := store.Batch(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Queue(ctx, obs); err != nil {
		t.Fatalf("admit second near-limit collection: %v", err)
	}
	var blobs int64
	for _, name := range collectionNames(t, directory) {
		n, err := store.collectionPhysical(name)
		if err != nil || n > collectionPhysicalBudget {
			t.Fatalf("admitted collection exceeds physical allowance: bytes=%d err=%v", n, err)
		}
		blobs += n
	}
	if blobs <= 2*CollectionBudget {
		t.Fatalf("fixture did not exercise filesystem block overhead: physical=%d encoded ceiling=%d", blobs, 2*CollectionBudget)
	}
	if physical := physicalTreeBytes(t, directory); physical > SpoolBudget {
		t.Fatalf("admitted spool exceeds 160 MiB: %d", physical)
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
	if err != nil || recovery.Reason != ReasonFence || recovery.LostAdmittedUploadMayRemain {
		t.Fatalf("healthy block overhead treated as corruption: %+v %v", recovery, err)
	}
	if err := reopened.Synchronize(ctx, 0, 0); err != nil {
		t.Fatal(err)
	}
	again, ok, err := reopened.PendingPackage(ctx)
	if err != nil || !ok || !bytes.Equal(again.CanonicalManifest, pending.CanonicalManifest) {
		t.Fatalf("reopen discarded immutable pending manifest: ok=%v err=%v", ok, err)
	}
	batch, err := reopened.Batch(ctx, 0)
	if err != nil || !bytes.Equal(batch, original) {
		t.Fatalf("reopen changed pending payload: %v", err)
	}
	_, queued, err := reopened.Queued(ctx)
	if err != nil || !queued {
		t.Fatalf("reopen discarded admitted queued collection: %v", err)
	}
}

func TestSpoolCanceledQueuedDeleteReclaimsPhysicalBytes(t *testing.T) {
	ctx := t.Context()
	directory := spoolDirectory(t)
	store := openSynced(t, directory, testIdentity(), 0, 0)
	obs := nearLimitObservation(t)
	if err := store.Queue(ctx, obs); err != nil {
		t.Fatal(err)
	}
	pending, err := store.PromotePackage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	original, err := store.Batch(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Queue(ctx, obs); err != nil {
		t.Fatal(err)
	}
	old, err := store.queries.ReadPackageSlot(ctx, slotQueued)
	if err != nil {
		t.Fatal(err)
	}
	interrupted := cancelAfterCommit(t, store)
	if err := store.dropQueuedPackage(interrupted); !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupt queued deletion after metadata commit: %v", err)
	}
	if physical, err := store.collectionPhysical(old.CollectionID); err != nil || physical < CollectionBudget-4096 {
		t.Fatalf("crash fixture did not leave near-64-MiB orphan: bytes=%d err=%v", physical, err)
	}
	if err := store.Queue(ctx, obs); err != nil {
		t.Fatalf("reclaim orphan before admitting replacement: %v", err)
	}
	if physical := physicalTreeBytes(t, directory); physical > SpoolBudget {
		t.Fatalf("orphan omitted from 160-MiB physical budget: %d", physical)
	}
	if _, err := os.Stat(filepath.Join(directory, collectionsName, old.CollectionID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("previous queued orphan survived new collection: %v", err)
	}
	owned, err := store.queries.ListOwned(ctx)
	if err != nil || len(owned) != 2 || len(collectionNames(t, directory)) != 2 {
		t.Fatalf("expected only pending and queued ownership: %+v %v", owned, err)
	}
	again, ok, err := store.PendingPackage(ctx)
	if err != nil || !ok || !bytes.Equal(again.CanonicalManifest, pending.CanonicalManifest) {
		t.Fatalf("orphan cleanup changed immutable pending manifest: ok=%v err=%v", ok, err)
	}
	batch, err := store.Batch(ctx, 0)
	if err != nil || !bytes.Equal(batch, original) {
		t.Fatalf("orphan cleanup changed immutable pending batch: %v", err)
	}
}

func TestSpoolCorruptConnectRecoversAfterServerFence(t *testing.T) {
	ctx := t.Context()
	directory := spoolDirectory(t)
	corrupt := bytes.Repeat([]byte("not a SQLite database\n"), 200)
	path := filepath.Join(directory, databaseName)
	if err := os.WriteFile(path, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(ctx, directory, testIdentity())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	defer func() {
		if value := recover(); value != nil {
			t.Fatalf("partially connected database panicked during recovery: %v", value)
		}
	}()
	recovery, err := store.Recovery(ctx)
	if err != nil || recovery.Reason != ReasonCorrupt || !recovery.NeedsSync || !recovery.LostAdmittedUploadMayRemain {
		t.Fatalf("corrupt database did not expose safe recovery: %+v %v", recovery, err)
	}
	if err := store.Queue(ctx, observation("blocked", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS)); !errors.Is(err, ErrNeedsSync) {
		t.Fatalf("corrupt database rebuilt before server fence: %v", err)
	}
	beforeSync, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(beforeSync, corrupt) {
		t.Fatalf("corrupt evidence changed before synchronization: %v", err)
	}
	if err := store.Synchronize(ctx, 41, 51); err != nil {
		t.Fatalf("server-fenced corruption recovery: %v", err)
	}
	if err := store.Queue(ctx, observation("recovered", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, pkg("bash", "1"))); err != nil {
		t.Fatal(err)
	}
	host, hostErr := store.PromoteHost(ctx)
	packages, packageErr := store.PromotePackage(ctx)
	if hostErr != nil || packageErr != nil || host.Sequence != 42 || packages.Sequence != 52 {
		t.Fatalf("recovery ignored server high-water: host=%d packages=%d err=%v %v", host.Sequence, packages.Sequence, hostErr, packageErr)
	}
}

func TestSpoolPostCommitCancellationKeepsReferencedPayload(t *testing.T) {
	ctx := t.Context()
	directory := spoolDirectory(t)
	id := testIdentity()
	store := openSynced(t, directory, id, 0, 0)
	obs := observation("committed", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, pkg("bash", "1"))
	expected, err := proto.MarshalOptions{Deterministic: true}.Marshal(&inventoryv1.PackageBatch{Packages: obs.GetPackages().GetPackages()})
	if err != nil {
		t.Fatal(err)
	}
	interrupted := cancelAfterCommit(t, store)
	if err := store.Queue(interrupted, obs); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel post-commit checkpoint: %v", err)
	}
	queued, err := store.queries.ReadPackageSlot(ctx, slotQueued)
	if err != nil || queued.CollectionID == "" {
		t.Fatalf("failure was not injected after queued metadata committed: %+v %v", queued, err)
	}
	payload, err := os.ReadFile(filepath.Join(directory, collectionsName, queued.CollectionID, "b000"))
	if err != nil || !bytes.Equal(payload, expected) {
		t.Fatalf("post-commit cancellation deleted referenced payload: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, directory, id)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	if err := reopened.Synchronize(ctx, 0, 0); err != nil {
		t.Fatal(err)
	}
	upload, err := reopened.PromotePackage(ctx)
	if err != nil || upload.Sequence != 1 || upload.BatchCount != 1 {
		t.Fatalf("committed queued payload was lost on reopen: %+v %v", upload, err)
	}
	batch, err := reopened.Batch(ctx, 0)
	if err != nil || !bytes.Equal(batch, expected) || sha256.Sum256(batch) != [32]byte(upload.Manifest.GetBatches()[0].GetSha256()) {
		t.Fatalf("recovered committed payload differs from its manifest: %v", err)
	}
}

func TestSpoolPostCommitFsyncFailureKeepsReferencedPayload(t *testing.T) {
	ctx := t.Context()
	directory := spoolDirectory(t)
	store := openSynced(t, directory, testIdentity(), 0, 0)
	obs := observation("committed", inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, pkg("bash", "1"))
	expected, err := proto.MarshalOptions{Deterministic: true}.Marshal(&inventoryv1.PackageBatch{Packages: obs.GetPackages().GetPackages()})
	if err != nil {
		t.Fatal(err)
	}
	// O_PATH is a real directory handle that supports openat/unlinkat but
	// rejects fsync. Swap it only after the payload and SQLite commit succeed.
	// The original handle stays open, retaining the spool's flock throughout.
	fd, err := unix.Open(directory, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	pathDir := os.NewFile(uintptr(fd), "spool-fsync-failure")
	defer func() { _ = pathDir.Close() }()
	originalDir := store.dir
	t.Cleanup(func() {
		store.dir = originalDir
		store.afterCommit = nil
	})
	store.afterCommit = func() {
		store.afterCommit = nil
		store.dir = pathDir
	}
	err = store.Queue(ctx, obs)
	store.dir = originalDir
	store.afterCommit = nil
	if !errors.Is(err, unix.EBADF) {
		t.Fatalf("expected real post-commit directory fsync failure: %v", err)
	}
	queued, err := store.queries.ReadPackageSlot(ctx, slotQueued)
	if err != nil || queued.CollectionID == "" {
		t.Fatalf("fsync failure preceded queued metadata commit: %+v %v", queued, err)
	}
	payload, err := os.ReadFile(filepath.Join(directory, collectionsName, queued.CollectionID, "b000"))
	if err != nil || !bytes.Equal(payload, expected) {
		t.Fatalf("post-commit fsync failure deleted referenced payload: %v", err)
	}
	upload, err := store.PromotePackage(ctx)
	if err != nil || upload.Sequence != 1 {
		t.Fatalf("committed payload could not be promoted: %+v %v", upload, err)
	}
	batch, err := store.Batch(ctx, 0)
	if err != nil || !bytes.Equal(batch, expected) {
		t.Fatalf("post-fsync-failure promotion published a missing payload: %v", err)
	}
}
