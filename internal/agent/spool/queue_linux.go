package spool

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"io"
	"math"
	"os"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	devicev1 "lindm/gen/lindm/device/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/agent/spool/spooldb"
	"lindm/internal/protodata"
)

type batchDesc struct {
	index   uint32
	records uint32
	size    uint32
	sum     [32]byte
}

// Queue coalesces the latest host and package collection into the replaceable
// slots. It does not allocate a sequence and does not mutate pending bytes.
// A pristine or healthy spool accepts Queue before Synchronize. A missing,
// corrupt, damaged, or unrecognized spool returns ErrNeedsSync and is not
// reinitialized. The previous unsubmitted collection and all tracked orphans
// are durably removed before replacement bytes are written. An error after the
// queued metadata commits preserves its referenced payload for retry/reopen.
func (s *Store) Queue(ctx context.Context, observation *inventoryv1.NativeObservation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.queueable(ctx); err != nil {
		return err
	}
	if err := s.ensureQueueDB(ctx); err != nil {
		return err
	}
	if err := s.validateObservation(observation); err != nil {
		return err
	}
	hostBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(observation.GetHost())
	if err != nil || len(hostBytes) == 0 || len(hostBytes) > maxHostBytes {
		return ErrInvalid
	}
	pkg := observation.GetPackages()
	success := pkg.GetStatus() == inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	var plans []batchPlan
	var total int64
	if success && len(pkg.GetPackages()) > 0 {
		plans, total, err = planBatches(pkg.GetPackages())
		if err != nil {
			return err
		}
	}
	if err := s.dropQueuedPackage(ctx); err != nil {
		return dbErr(ctx, err)
	}
	var collectionID string
	var descs []batchDesc
	if len(plans) > 0 {
		collectionID, descs, err = s.writeCollection(ctx, plans, total)
		if err != nil {
			return dbErr(ctx, err)
		}
	}
	if committed, err := s.commitQueued(ctx, hostBytes, pkg, success, collectionID, total, descs); err != nil {
		if collectionID != "" && !committed {
			s.abandonCollection(ctx, collectionID)
		}
		return dbErr(ctx, err)
	}
	return nil
}

// Queued reports whether a replaceable host or package collection is waiting
// for promotion. Neither has a sequence yet.
func (s *Store) Queued(ctx context.Context) (bool, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.queueable(ctx); err != nil {
		return false, false, err
	}
	if s.db == nil {
		return false, false, nil
	}
	_, hostErr := s.queries.ReadHostSlot(ctx, slotQueued)
	_, pkgErr := s.queries.ReadPackageSlot(ctx, slotQueued)
	if hostErr != nil && !errors.Is(hostErr, sql.ErrNoRows) {
		return false, false, dbErr(ctx, hostErr)
	}
	if pkgErr != nil && !errors.Is(pkgErr, sql.ErrNoRows) {
		return false, false, dbErr(ctx, pkgErr)
	}
	return hostErr == nil, pkgErr == nil, nil
}

// PendingHost returns the immutable in-flight host upload, if any.
func (s *Store) PendingHost(ctx context.Context) (HostUpload, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.inspectable(ctx); err != nil {
		return HostUpload{}, false, err
	}
	row, err := s.queries.ReadHostSlot(ctx, slotPending)
	if errors.Is(err, sql.ErrNoRows) {
		return HostUpload{}, false, nil
	}
	if err != nil {
		return HostUpload{}, false, dbErr(ctx, err)
	}
	obs, err := decodeHost(row.Observation)
	if err != nil {
		_ = s.noteDamage(ctx)
		return HostUpload{}, false, ErrNeedsSync
	}
	cloned, ok := proto.Clone(obs).(*inventoryv1.HostObservation)
	if !ok {
		return HostUpload{}, false, ErrInvalid
	}
	return HostUpload{Sequence: uint64(row.Sequence), Observation: cloned}, true, nil
}

// PromoteHost allocates the next host sequence and makes the queued observation
// immutable. The allocation and payload commit together, before any outbound RPC.
func (s *Store) PromoteHost(ctx context.Context) (HostUpload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx); err != nil {
		return HostUpload{}, err
	}
	var upload HostUpload
	err := s.tx(ctx, func(q *spooldb.Queries) error {
		if _, err := q.ReadHostSlot(ctx, slotPending); err == nil {
			return ErrPending
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		queued, err := q.ReadHostSlot(ctx, slotQueued)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrEmpty
		}
		if err != nil {
			return err
		}
		scope, err := q.ReadScope(ctx)
		if err != nil {
			return err
		}
		seq, err := nextSequence(scope.HostAllocated)
		if err != nil {
			return err
		}
		if seq <= scope.HostHighwater {
			return ErrConflict
		}
		if err := q.DeleteHostSlot(ctx, slotQueued); err != nil {
			return err
		}
		if err := q.InsertHostSlot(ctx, spooldb.InsertHostSlotParams{Kind: slotPending, Sequence: seq, Observation: queued.Observation}); err != nil {
			return err
		}
		changed, err := q.UpdateScopeCounters(ctx, spooldb.UpdateScopeCountersParams{
			HostAllocated: seq, PackageAllocated: scope.PackageAllocated,
			HostHighwater: scope.HostHighwater, PackageHighwater: scope.PackageHighwater,
		})
		if err != nil {
			return err
		}
		if changed != 1 {
			return ErrConflict
		}
		obs, err := decodeHost(queued.Observation)
		if err != nil {
			return err
		}
		cloned, ok := proto.Clone(obs).(*inventoryv1.HostObservation)
		if !ok {
			return ErrInvalid
		}
		upload = HostUpload{Sequence: uint64(seq), Observation: cloned}
		return nil
	})
	if err != nil {
		return HostUpload{}, dbErr(ctx, err)
	}
	if err := s.checkpoint(ctx); err != nil && ctx.Err() != nil {
		return HostUpload{}, ctx.Err()
	}
	return upload, nil
}

// AcknowledgeHost drops the pending host after the server accepts it. A lower
// server high-water is a conflict and does not discard the payload. Allocated
// counters are not rewound.
func (s *Store) AcknowledgeHost(ctx context.Context, seq, serverHigh uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx); err != nil {
		return err
	}
	if seq == 0 || seq > math.MaxInt64 || serverHigh > math.MaxInt64 || serverHigh < seq {
		return ErrConflict
	}
	row, err := s.queries.ReadHostSlot(ctx, slotPending)
	if errors.Is(err, sql.ErrNoRows) {
		return s.alreadyTerminal(ctx, true, seq, serverHigh)
	}
	if err != nil {
		return dbErr(ctx, err)
	}
	if row.Sequence != int64(seq) {
		return ErrConflict
	}
	err = s.tx(ctx, func(q *spooldb.Queries) error {
		if err := q.DeleteHostSlot(ctx, slotPending); err != nil {
			return err
		}
		return s.raiseTx(ctx, q, int64(serverHigh), -1)
	})
	if err != nil {
		return dbErr(ctx, err)
	}
	return s.checkpoint(ctx)
}

// PendingPackage returns the immutable in-flight package attempt, if any.
func (s *Store) PendingPackage(ctx context.Context) (PackageUpload, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.inspectable(ctx); err != nil {
		return PackageUpload{}, false, err
	}
	row, err := s.queries.ReadPackageSlot(ctx, slotPending)
	if errors.Is(err, sql.ErrNoRows) {
		return PackageUpload{}, false, nil
	}
	if err != nil {
		return PackageUpload{}, false, dbErr(ctx, err)
	}
	if s.afterPendingPackageRead != nil {
		s.afterPendingPackageRead()
	}
	upload, err := s.packageUpload(ctx, row)
	if err != nil {
		if ctx.Err() != nil {
			return PackageUpload{}, false, ctx.Err()
		}
		_ = s.noteDamage(ctx)
		return PackageUpload{}, false, ErrNeedsSync
	}
	return upload, true, nil
}

// PromotePackage allocates the next package sequence. A success collection,
// including zero packages, receives a UUIDv7 manifest whose created_at is the
// UUID time. A failure carries status, times and backend and no batches.
func (s *Store) PromotePackage(ctx context.Context) (PackageUpload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx); err != nil {
		return PackageUpload{}, err
	}
	var upload PackageUpload
	err := s.tx(ctx, func(q *spooldb.Queries) error {
		if _, err := q.ReadPackageSlot(ctx, slotPending); err == nil {
			return ErrPending
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		queued, err := q.ReadPackageSlot(ctx, slotQueued)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrEmpty
		}
		if err != nil {
			return err
		}
		scope, err := q.ReadScope(ctx)
		if err != nil {
			return err
		}
		seq, err := nextSequence(scope.PackageAllocated)
		if err != nil {
			return err
		}
		if seq <= scope.PackageHighwater {
			return ErrConflict
		}
		pending := queued
		pending.Sequence = seq
		if queued.Success == 1 {
			manifest, canonical, err := s.buildManifest(ctx, q, queued, uint64(seq))
			if err != nil {
				return err
			}
			pending.SnapshotID = manifest.GetSnapshotId()
			pending.CreatedUnix = manifest.GetCreatedAt().AsTime().UnixNano()
			pending.Manifest = canonical
		}
		if err := q.DeletePackageSlot(ctx, slotQueued); err != nil {
			return err
		}
		if err := q.InsertPackageSlot(ctx, packageParams(slotPending, pending)); err != nil {
			return err
		}
		changed, err := q.UpdateScopeCounters(ctx, spooldb.UpdateScopeCountersParams{
			HostAllocated: scope.HostAllocated, PackageAllocated: seq,
			HostHighwater: scope.HostHighwater, PackageHighwater: scope.PackageHighwater,
		})
		if err != nil {
			return err
		}
		if changed != 1 {
			return ErrConflict
		}
		built, err := s.packageUpload(ctx, pending)
		if err != nil {
			return err
		}
		upload = built
		return nil
	})
	if err != nil {
		return PackageUpload{}, dbErr(ctx, err)
	}
	if err := s.checkpoint(ctx); err != nil && ctx.Err() != nil {
		return PackageUpload{}, ctx.Err()
	}
	return upload, nil
}

// Batch reads one verified package-batch file. It does not re-encode the batch
// or load any other batch. A digest or size mismatch is damage, not a payload
// the caller may upload.
func (s *Store) Batch(ctx context.Context, index uint32) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	if index >= MaxBatches {
		return nil, ErrNotFound
	}
	row, err := s.queries.ReadPackageSlot(ctx, slotPending)
	if errors.Is(err, sql.ErrNoRows) || err == nil && row.Success != 1 {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, dbErr(ctx, err)
	}
	batches, err := s.queries.ListBatches(ctx, row.CollectionID)
	if err != nil {
		return nil, dbErr(ctx, err)
	}
	var match *spooldb.ListBatchesRow
	for i := range batches {
		if batches[i].BatchIndex == int64(index) {
			match = &batches[i]
			break
		}
	}
	if match == nil {
		return nil, ErrNotFound
	}
	fd, err := s.openCollection(row.CollectionID)
	if err != nil {
		_ = s.noteDamage(ctx)
		return nil, ErrNeedsSync
	}
	defer func() { _ = unix.Close(fd) }()
	name, ok := batchFileName(int(index))
	if !ok {
		return nil, ErrNotFound
	}
	sum, n, err := hashFile(fd, name)
	if err != nil || n != match.EncodedSize || !digestEqual(match.Sha256, sum) {
		_ = s.noteDamage(ctx)
		return nil, ErrNeedsSync
	}
	fileFD, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = s.noteDamage(ctx)
		return nil, ErrNeedsSync
	}
	file := os.NewFile(uintptr(fileFD), "spool-batch")
	defer func() { _ = file.Close() }()
	buf := make([]byte, n)
	if _, err := io.ReadFull(file, buf); err != nil {
		return nil, dbErr(ctx, err)
	}
	if sha256.Sum256(buf) != sum {
		_ = s.noteDamage(ctx)
		return nil, ErrNeedsSync
	}
	return buf, nil
}

// MarkBegin records that the server accepted Begin for the pending success
// snapshot. It is idempotent.
func (s *Store) MarkBegin(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx); err != nil {
		return err
	}
	row, err := s.queries.ReadPackageSlot(ctx, slotPending)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrEmpty
		}
		return dbErr(ctx, err)
	}
	if row.Success != 1 {
		return ErrConflict
	}
	changed, err := s.queries.UpdatePackageBegin(ctx, row.Sequence)
	if err != nil {
		return dbErr(ctx, err)
	}
	if changed != 1 {
		return ErrConflict
	}
	return s.checkpoint(ctx)
}

// MarkBatchAccepted records one successfully uploaded batch index. Indexes may
// be marked more than once. The server's successful Put is sufficient even if
// the local Begin hint was lost; neither hint is publication authority.
func (s *Store) MarkBatchAccepted(ctx context.Context, index uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx); err != nil {
		return err
	}
	row, err := s.queries.ReadPackageSlot(ctx, slotPending)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrEmpty
		}
		return dbErr(ctx, err)
	}
	if row.Success != 1 || index >= MaxBatches {
		return ErrConflict
	}
	batches, err := s.queries.ListBatches(ctx, row.CollectionID)
	if err != nil {
		return dbErr(ctx, err)
	}
	found := false
	for _, batch := range batches {
		if batch.BatchIndex == int64(index) {
			found = true
			break
		}
	}
	if !found {
		return ErrNotFound
	}
	mask := append([]byte(nil), row.AcceptedMask...)
	if len(mask) != 64 {
		return ErrConflict
	}
	mask[index/8] |= 1 << (index % 8)
	changed, err := s.queries.UpdatePackageMask(ctx, spooldb.UpdatePackageMaskParams{AcceptedMask: mask, Sequence: row.Sequence})
	if err != nil {
		return dbErr(ctx, err)
	}
	if changed != 1 {
		return ErrConflict
	}
	return s.checkpoint(ctx)
}

// FinishPackage discards a terminal package attempt. TerminalAdmitted requires
// only that seq match the pending attempt and serverHigh >= seq. The caller
// supplies that after a server COMMITTED receipt. Missing local begin/batch
// marks do not block it and do not rewind allocated counters.
func (s *Store) FinishPackage(ctx context.Context, seq, serverHigh uint64, terminal Terminal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx); err != nil {
		return err
	}
	if seq == 0 || seq > math.MaxInt64 || serverHigh > math.MaxInt64 {
		return ErrInvalid
	}
	switch terminal {
	case TerminalAdmitted:
		if serverHigh < seq {
			return ErrConflict
		}
	case TerminalSuperseded, TerminalExpired:
	default:
		return ErrInvalid
	}
	row, err := s.queries.ReadPackageSlot(ctx, slotPending)
	if errors.Is(err, sql.ErrNoRows) {
		return s.alreadyTerminal(ctx, false, seq, serverHigh)
	}
	if err != nil {
		return dbErr(ctx, err)
	}
	if row.Sequence != int64(seq) {
		return ErrConflict
	}
	if err := s.dropPendingPackage(ctx, row, serverHigh); err != nil {
		return dbErr(ctx, err)
	}
	return nil
}

func (s *Store) dropQueuedPackage(ctx context.Context) error {
	row, err := s.queries.ReadPackageSlot(ctx, slotQueued)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	id := row.CollectionID
	err = s.tx(ctx, func(q *spooldb.Queries) error {
		if err := q.DeletePackageSlot(ctx, slotQueued); err != nil {
			return err
		}
		if id == "" {
			return nil
		}
		if err := q.DeleteBatches(ctx, id); err != nil {
			return err
		}
		changed, err := q.MarkOwned(ctx, spooldb.MarkOwnedParams{Referenced: 0, ByteSize: 0, CollectionID: id})
		if err != nil {
			return err
		}
		if changed != 1 {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err := s.checkpoint(ctx); err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if id == "" {
		return nil
	}
	if err := s.deleteCollection(id); err != nil {
		return err
	}
	return s.queries.DeleteOwned(ctx, id)
}

func (s *Store) dropPendingPackage(ctx context.Context, row spooldb.ReadPackageSlotRow, serverHigh uint64) error {
	id := row.CollectionID
	err := s.tx(ctx, func(q *spooldb.Queries) error {
		if err := q.DeletePackageSlot(ctx, slotPending); err != nil {
			return err
		}
		if id != "" {
			if err := q.DeleteBatches(ctx, id); err != nil {
				return err
			}
			if _, err := q.MarkOwned(ctx, spooldb.MarkOwnedParams{Referenced: 0, ByteSize: 0, CollectionID: id}); err != nil {
				return err
			}
		}
		return s.raiseTx(ctx, q, -1, int64(serverHigh))
	})
	if err != nil {
		return err
	}
	if err := s.checkpoint(ctx); err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if id == "" {
		return nil
	}
	if err := s.deleteCollection(id); err != nil {
		return err
	}
	return s.queries.DeleteOwned(ctx, id)
}

func (s *Store) alreadyTerminal(ctx context.Context, host bool, seq, serverHigh uint64) error {
	scope, err := s.queries.ReadScope(ctx)
	if err != nil {
		return dbErr(ctx, err)
	}
	allocated := scope.PackageAllocated
	high := scope.PackageHighwater
	if host {
		allocated = scope.HostAllocated
		high = scope.HostHighwater
	}
	if int64(seq) > allocated {
		return ErrConflict
	}
	if int64(serverHigh) <= high {
		return nil
	}
	if host {
		return s.raise(ctx, int64(serverHigh), scope.PackageHighwater)
	}
	return s.raise(ctx, scope.HostHighwater, int64(serverHigh))
}

func (s *Store) raiseTx(ctx context.Context, q *spooldb.Queries, hostHigh, packageHigh int64) error {
	scope, err := q.ReadScope(ctx)
	if err != nil {
		return err
	}
	nextHostHigh := scope.HostHighwater
	nextPkgHigh := scope.PackageHighwater
	nextHostAlloc := scope.HostAllocated
	nextPkgAlloc := scope.PackageAllocated
	if hostHigh >= 0 {
		nextHostHigh = max64(nextHostHigh, hostHigh)
		nextHostAlloc = max64(nextHostAlloc, hostHigh)
	}
	if packageHigh >= 0 {
		nextPkgHigh = max64(nextPkgHigh, packageHigh)
		nextPkgAlloc = max64(nextPkgAlloc, packageHigh)
	}
	changed, err := q.UpdateScopeCounters(ctx, spooldb.UpdateScopeCountersParams{
		HostAllocated: nextHostAlloc, PackageAllocated: nextPkgAlloc,
		HostHighwater: nextHostHigh, PackageHighwater: nextPkgHigh,
	})
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrConflict
	}
	return nil
}

func (s *Store) writeCollection(ctx context.Context, plans []batchPlan, total int64) (string, []batchDesc, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	existingBytes, err := s.reclaimCollectionSpace(ctx)
	if err != nil {
		return "", nil, err
	}
	meta, err := s.metadataPhysical()
	if err != nil {
		return "", nil, err
	}
	sqliteBytes, err := s.sqlitePhysical()
	if err != nil {
		return "", nil, err
	}
	// Reserve block slack for both batch files and their directory before
	// creating any payload; the same allowance is enforced after writing.
	estimate := total + (collectionPhysicalBudget - CollectionBudget)
	if total > CollectionBudget || estimate > collectionPhysicalBudget || sqliteBytes > sqlitePhysicalBudget || meta > MetadataBudget || meta+existingBytes+estimate > SpoolBudget {
		return "", nil, ErrCapacity
	}
	id := uuid.New()
	if id == uuid.Nil {
		return "", nil, ErrInvalid
	}
	name := id.String()
	if err := s.queries.InsertOwned(ctx, spooldb.InsertOwnedParams{CollectionID: name, Referenced: 0, ByteSize: 0}); err != nil {
		return "", nil, err
	}
	parent, err := s.collectionsFD()
	if err != nil {
		s.abandonCollection(ctx, name)
		return "", nil, err
	}
	defer func() { _ = unix.Close(parent) }()
	if err := unix.Mkdirat(parent, name, 0700); err != nil {
		s.abandonCollection(ctx, name)
		return "", nil, err
	}
	dirfd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		s.abandonCollection(ctx, name)
		return "", nil, err
	}
	defer func() { _ = unix.Close(dirfd) }()
	descs := make([]batchDesc, 0, len(plans))
	for i, plan := range plans {
		if err := ctx.Err(); err != nil {
			s.abandonCollection(ctx, name)
			return "", nil, err
		}
		buf, sum, err := assembleBatch(plan)
		if err != nil {
			s.abandonCollection(ctx, name)
			return "", nil, err
		}
		decoded := &inventoryv1.PackageBatch{}
		if proto.Unmarshal(buf, decoded) != nil || s.validator.Validate(decoded) != nil || protodata.ValidateClosed(decoded.ProtoReflect()) != nil {
			s.abandonCollection(ctx, name)
			return "", nil, ErrInvalid
		}
		fileName, ok := batchFileName(i)
		if !ok {
			s.abandonCollection(ctx, name)
			return "", nil, ErrInvalid
		}
		if err := writeExclusive(dirfd, fileName, buf); err != nil {
			s.abandonCollection(ctx, name)
			return "", nil, err
		}
		descs = append(descs, batchDesc{index: uint32(i), records: plan.records, size: uint32(len(buf)), sum: sum})
	}
	if err := unix.Fsync(dirfd); err != nil || unix.Fsync(parent) != nil || s.dir.Sync() != nil {
		s.abandonCollection(ctx, name)
		return "", nil, errors.New("sync observation collection failed")
	}
	physical, err := s.collectionPhysical(name)
	if err != nil {
		s.abandonCollection(ctx, name)
		return "", nil, err
	}
	if physical > collectionPhysicalBudget || meta+existingBytes+physical > SpoolBudget {
		s.abandonCollection(ctx, name)
		return "", nil, ErrCapacity
	}
	return name, descs, nil
}

func (s *Store) commitQueued(ctx context.Context, host []byte, pkg *inventoryv1.PackageObservation, success bool, collectionID string, total int64, descs []batchDesc) (bool, error) {
	started, ok := unixNano(pkg.GetStartedAt())
	finished, ok2 := unixNano(pkg.GetFinishedAt())
	if !ok || !ok2 || finished < started {
		return false, ErrInvalid
	}
	successBit := int64(0)
	if success {
		successBit = 1
	}
	err := s.tx(ctx, func(q *spooldb.Queries) error {
		changed, err := q.UpdateHostSlot(ctx, spooldb.UpdateHostSlotParams{Sequence: 0, Observation: host, Kind: slotQueued})
		if err != nil {
			return err
		}
		if changed == 0 {
			if err := q.InsertHostSlot(ctx, spooldb.InsertHostSlotParams{Kind: slotQueued, Sequence: 0, Observation: host}); err != nil {
				return err
			}
		}
		if err := q.InsertPackageSlot(ctx, spooldb.InsertPackageSlotParams{
			Kind: slotQueued, Sequence: 0, Success: successBit, Status: int64(pkg.GetStatus()),
			Backend: pkg.GetBackend(), StartedUnix: started, FinishedUnix: finished,
			SnapshotID: "", CreatedUnix: 0, CollectionID: collectionID, BeginAccepted: 0,
			AcceptedMask: newMask(), Manifest: []byte{},
		}); err != nil {
			return err
		}
		for _, desc := range descs {
			sum := make([]byte, 32)
			copy(sum, desc.sum[:])
			if err := q.InsertBatch(ctx, spooldb.InsertBatchParams{
				CollectionID: collectionID, BatchIndex: int64(desc.index), Sha256: sum,
				RecordCount: int64(desc.records), EncodedSize: int64(desc.size),
			}); err != nil {
				return err
			}
		}
		if collectionID == "" {
			return nil
		}
		changed, err = q.MarkOwned(ctx, spooldb.MarkOwnedParams{Referenced: 1, ByteSize: total, CollectionID: collectionID})
		if err != nil {
			return err
		}
		if changed != 1 {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	// Once referenced, the payload belongs to the committed queued slot even
	// when subsequent checkpointing or directory fsync fails.
	if err := s.checkpoint(ctx); err != nil {
		return true, err
	}
	return true, s.dir.Sync()
}

func (s *Store) buildManifest(ctx context.Context, q *spooldb.Queries, row spooldb.ReadPackageSlotRow, seq uint64) (*devicev1.PackageSnapshotManifest, []byte, error) {
	var batches []spooldb.ListBatchesRow
	var err error
	if row.CollectionID != "" {
		batches, err = q.ListBatches(ctx, row.CollectionID)
		if err != nil {
			return nil, nil, err
		}
	}
	id, err := uuid.NewV7()
	if err != nil || id.Version() != 7 {
		return nil, nil, ErrInvalid
	}
	created, err := uuidV7Time(id)
	if err != nil {
		return nil, nil, err
	}
	sec, nsec := id.Time().UnixTime()
	if created.Sub(time.Unix(sec, nsec).UTC()).Abs() > time.Second {
		return nil, nil, ErrInvalid
	}
	descs := make([]*devicev1.PackageBatchDescriptor, len(batches))
	for i, batch := range batches {
		if batch.BatchIndex != int64(i) {
			return nil, nil, ErrInvalid
		}
		sum := append([]byte(nil), batch.Sha256...)
		descs[i] = &devicev1.PackageBatchDescriptor{Index: uint32(i), Sha256: sum, Count: uint32(batch.RecordCount), EncodedSize: uint32(batch.EncodedSize)}
	}
	manifest := &devicev1.PackageSnapshotManifest{
		SnapshotId: id.String(), CreatedAt: stamp(created), EnrollmentGeneration: s.identity.Generation.String(),
		Sequence: seq, StartedAt: stamp(unixTime(row.StartedUnix)), FinishedAt: stamp(unixTime(row.FinishedUnix)),
		Backend: row.Backend, Batches: descs,
	}
	if err := protodata.ValidateClosed(manifest.ProtoReflect()); err != nil || s.validator.Validate(manifest) != nil {
		return nil, nil, ErrInvalid
	}
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(manifest)
	if err != nil || len(canonical) == 0 || len(canonical) > 65536 {
		return nil, nil, ErrInvalid
	}
	round := &devicev1.PackageSnapshotManifest{}
	if proto.Unmarshal(canonical, round) != nil || !proto.Equal(round, manifest) {
		return nil, nil, ErrInvalid
	}
	return manifest, canonical, nil
}

func (s *Store) packageUpload(ctx context.Context, row spooldb.ReadPackageSlotRow) (PackageUpload, error) {
	upload := PackageUpload{
		Sequence: uint64(row.Sequence), Success: row.Success == 1,
		Status: inventoryv1.CollectionStatus(row.Status), Backend: row.Backend,
		StartedAt: unixTime(row.StartedUnix), FinishedAt: unixTime(row.FinishedUnix),
		BeginAccepted: row.BeginAccepted == 1, AcceptedBatches: acceptedBatches(row.AcceptedMask),
	}
	if _, ok := inventoryv1.CollectionStatus_name[int32(row.Status)]; !ok || row.Status == 0 {
		return PackageUpload{}, ErrInvalid
	}
	if !upload.Success {
		return upload, nil
	}
	if len(row.Manifest) == 0 {
		return PackageUpload{}, ErrInvalid
	}
	manifest := &devicev1.PackageSnapshotManifest{}
	if err := proto.Unmarshal(row.Manifest, manifest); err != nil {
		return PackageUpload{}, ErrInvalid
	}
	cloned, ok := proto.Clone(manifest).(*devicev1.PackageSnapshotManifest)
	if !ok {
		return PackageUpload{}, ErrInvalid
	}
	upload.Manifest = cloned
	upload.CanonicalManifest = append([]byte(nil), row.Manifest...)
	upload.ManifestDigest = sha256.Sum256(row.Manifest)
	upload.BatchCount = len(manifest.GetBatches())
	if ctx.Err() != nil {
		return PackageUpload{}, ctx.Err()
	}
	return upload, nil
}

func (s *Store) reclaimCollectionSpace(ctx context.Context) (int64, error) {
	rows, err := s.queries.ListOwned(ctx)
	if err != nil {
		return 0, err
	}
	// Interrupted deletion may leave a full queued collection behind after its
	// slot disappears. Reclaim every orphan before admitting any new bytes.
	if err := s.cleanOrphans(ctx, rows); err != nil {
		return 0, err
	}
	var total int64
	for _, row := range rows {
		n, err := s.collectionPhysical(row.CollectionID)
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
}

func (s *Store) noteDamage(ctx context.Context) error {
	s.markNeeds(ReasonDamagedPending)
	if s.db == nil {
		return ErrNeedsSync
	}
	_ = s.queries.DeleteRecovery(ctx)
	_ = s.queries.InsertRecovery(ctx, string(ReasonDamagedPending))
	return ErrNeedsSync
}

func (s *Store) abandonCollection(ctx context.Context, id string) {
	_ = s.deleteCollection(id)
	_ = s.queries.DeleteOwned(ctx, id)
}

func newMask() []byte {
	return make([]byte, MaxBatches/8)
}

func packageParams(kind int64, row spooldb.ReadPackageSlotRow) spooldb.InsertPackageSlotParams {
	mask := row.AcceptedMask
	if len(mask) != 64 {
		mask = newMask()
	}
	manifest := row.Manifest
	if manifest == nil {
		manifest = []byte{}
	}
	return spooldb.InsertPackageSlotParams{
		Kind: kind, Sequence: row.Sequence, Success: row.Success, Status: row.Status,
		Backend: row.Backend, StartedUnix: row.StartedUnix, FinishedUnix: row.FinishedUnix,
		SnapshotID: row.SnapshotID, CreatedUnix: row.CreatedUnix, CollectionID: row.CollectionID,
		BeginAccepted: row.BeginAccepted, AcceptedMask: mask, Manifest: manifest,
	}
}

func unixNano(ts interface {
	AsTime() time.Time
	IsValid() bool
}) (int64, bool) {
	if ts == nil || !ts.IsValid() {
		return 0, false
	}
	return ts.AsTime().UnixNano(), true
}

func acceptedBatches(mask []byte) []uint32 {
	out := []uint32{}
	if len(mask) != 64 {
		return out
	}
	for i := range MaxBatches {
		if mask[i/8]&(1<<uint(i%8)) != 0 {
			out = append(out, uint32(i))
		}
	}
	return out
}
