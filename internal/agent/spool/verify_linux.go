package spool

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	devicev1 "lindm/gen/lindm/device/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/agent/spool/spooldb"
	"lindm/internal/protodata"
)

func (s *Store) verifyContents(ctx context.Context) error {
	row, err := s.queries.ReadScope(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.closeDB()
		s.markNeeds(ReasonCorrupt)
		return nil
	}
	stored, ok := parseIdentity(row.Deployment, row.Device, row.Generation)
	if !ok || row.HostAllocated < 0 || row.PackageAllocated < 0 || row.HostHighwater < 0 || row.PackageHighwater < 0 || row.HostAllocated < row.HostHighwater || row.PackageAllocated < row.PackageHighwater || (row.Synced != 0 && row.Synced != 1) {
		s.closeDB()
		s.markNeeds(ReasonCorrupt)
		return nil
	}
	s.stored = stored
	if row.LossRecovered != 0 {
		s.lossMayRemain = true
	}
	if stored != s.identity {
		s.markNeeds(ReasonScopeChange)
	}
	reason, err := s.queries.ReadRecovery(ctx)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.markNeeds(ReasonCorrupt)
		return nil
	}
	if err == nil {
		s.markNeeds(knownReason(reason))
	}
	owned, err := s.queries.ListOwned(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.closeDB()
		s.markNeeds(ReasonCorrupt)
		return nil
	}
	names, err := s.collectionNames()
	if err != nil {
		return err
	}
	ownedSet := map[string]spooldb.OwnedDir{}
	for _, item := range owned {
		if !canonicalUUID(item.CollectionID) || item.ByteSize < 0 || item.ByteSize > CollectionBudget {
			s.closeDB()
			s.markNeeds(ReasonCorrupt)
			return nil
		}
		ownedSet[item.CollectionID] = item
	}
	for _, name := range names {
		if _, ok := ownedSet[name]; !ok {
			s.markNeeds(ReasonUnrecognized)
		}
	}
	if s.reason == ReasonUnrecognized || s.reason == ReasonScopeChange || s.reason == ReasonCorrupt {
		return nil
	}
	if err := s.cleanOrphans(ctx, owned); err != nil {
		if errors.Is(err, ErrUnrecognized) {
			s.markNeeds(ReasonUnrecognized)
			return nil
		}
		return err
	}
	if err := s.verifyHost(ctx, row.HostAllocated); err != nil {
		return s.damage(ctx, err)
	}
	if err := s.verifyPackage(ctx, row.PackageAllocated, ownedSet); err != nil {
		return s.damage(ctx, err)
	}
	if err := s.enforceBudget(owned); err != nil {
		s.markNeeds(ReasonCorrupt)
	}
	if s.reason == "" {
		s.needsSync = true
		if row.Synced == 0 {
			s.reason = ReasonUnsynchronized
		} else {
			s.reason = ReasonFence
		}
	}
	return nil
}

func knownReason(reason string) Reason {
	switch Reason(reason) {
	case ReasonMissing, ReasonCorrupt, ReasonScopeChange, ReasonDamagedPending, ReasonUnrecognized, ReasonUnsynchronized:
		return Reason(reason)
	default:
		return ReasonCorrupt
	}
}

func (s *Store) damage(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, ErrUnrecognized) {
		s.markNeeds(ReasonUnrecognized)
		return nil
	}
	s.markNeeds(ReasonDamagedPending)
	return nil
}

func (s *Store) cleanOrphans(ctx context.Context, owned []spooldb.OwnedDir) error {
	for _, row := range owned {
		if row.Referenced != 0 {
			continue
		}
		if err := s.deleteCollection(row.CollectionID); err != nil {
			return err
		}
		if err := s.tx(ctx, func(q *spooldb.Queries) error {
			if err := q.DeleteBatches(ctx, row.CollectionID); err != nil {
				return err
			}
			return q.DeleteOwned(ctx, row.CollectionID)
		}); err != nil {
			return dbErr(ctx, err)
		}
	}
	return nil
}

func (s *Store) verifyHost(ctx context.Context, allocated int64) error {
	pending, err := s.queries.ReadHostSlot(ctx, slotPending)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil {
		if pending.Sequence < 1 || pending.Sequence > allocated {
			return ErrNeedsSync
		}
		if _, err := decodeHost(pending.Observation); err != nil {
			return ErrNeedsSync
		}
	}
	queued, err := s.queries.ReadHostSlot(ctx, slotQueued)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if queued.Sequence != 0 {
		return ErrNeedsSync
	}
	if _, err := decodeHost(queued.Observation); err != nil {
		return s.queries.DeleteHostSlot(ctx, slotQueued)
	}
	return nil
}

func (s *Store) verifyPackage(ctx context.Context, allocated int64, owned map[string]spooldb.OwnedDir) error {
	pending, err := s.queries.ReadPackageSlot(ctx, slotPending)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	pendingID := ""
	if err == nil {
		pendingID = pending.CollectionID
		if pending.Sequence < 1 || pending.Sequence > allocated {
			return ErrNeedsSync
		}
		if err := s.verifyPackageRow(ctx, pending, true); err != nil {
			return err
		}
	}
	queued, err := s.queries.ReadPackageSlot(ctx, slotQueued)
	if errors.Is(err, sql.ErrNoRows) {
		return s.unreferenced(ctx, owned, pendingID, "")
	}
	if err != nil {
		return err
	}
	if queued.Sequence != 0 {
		return ErrNeedsSync
	}
	if err := s.verifyPackageRow(ctx, queued, false); err != nil {
		if dropErr := s.dropQueuedPackage(ctx); dropErr != nil {
			return dropErr
		}
		return nil
	}
	return s.unreferenced(ctx, owned, pendingID, queued.CollectionID)
}

func (s *Store) unreferenced(ctx context.Context, owned map[string]spooldb.OwnedDir, pendingID, queuedID string) error {
	for id, row := range owned {
		if row.Referenced == 0 || id == pendingID || id == queuedID {
			continue
		}
		if err := s.deleteCollection(id); err != nil {
			return err
		}
		if err := s.queries.DeleteBatches(ctx, id); err != nil {
			return err
		}
		if err := s.queries.DeleteOwned(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) verifyPackageRow(ctx context.Context, row spooldb.ReadPackageSlotRow, pending bool) error {
	if row.FinishedUnix < row.StartedUnix || row.Status < 1 || row.Status > 7 || len(row.AcceptedMask) != 64 {
		return ErrNeedsSync
	}
	success := row.Success == 1
	if success != (row.Status == int64(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS)) {
		return ErrNeedsSync
	}
	if !success {
		if row.SnapshotID != "" || row.CollectionID != "" || len(row.Manifest) != 0 || row.BeginAccepted != 0 {
			return ErrNeedsSync
		}
		return nil
	}
	if !pending {
		if row.SnapshotID != "" || len(row.Manifest) != 0 || row.BeginAccepted != 0 {
			return ErrNeedsSync
		}
	}
	if row.CollectionID == "" {
		if !pending {
			return nil
		}
		return s.verifyManifest(row, nil)
	}
	if !canonicalUUID(row.CollectionID) {
		return ErrNeedsSync
	}
	batches, err := s.queries.ListBatches(ctx, row.CollectionID)
	if err != nil {
		return err
	}
	if len(batches) == 0 || len(batches) > MaxBatches {
		return ErrNeedsSync
	}
	var total int64
	for i, batch := range batches {
		if batch.BatchIndex != int64(i) || batch.RecordCount < 1 || batch.RecordCount > MaxBatchRecords || batch.EncodedSize < 1 || batch.EncodedSize > MaxBatchEncoded || len(batch.Sha256) != 32 {
			return ErrNeedsSync
		}
		total += batch.EncodedSize
	}
	if total <= 0 || total > CollectionBudget {
		return ErrNeedsSync
	}
	if err := s.hashCollection(row.CollectionID, batches); err != nil {
		return err
	}
	if pending {
		return s.verifyManifest(row, batches)
	}
	return nil
}

func (s *Store) hashCollection(id string, batches []spooldb.ListBatchesRow) error {
	fd, err := s.openCollection(id)
	if err != nil {
		return ErrNeedsSync
	}
	defer func() { _ = unix.Close(fd) }()
	names, err := listDir(fd)
	if err != nil {
		return err
	}
	if len(names) != len(batches) {
		return ErrNeedsSync
	}
	for _, batch := range batches {
		name, ok := batchFileName(int(batch.BatchIndex))
		if !ok {
			return ErrNeedsSync
		}
		sum, n, err := hashFile(fd, name)
		if err != nil || n != batch.EncodedSize || !digestEqual(batch.Sha256, sum) {
			return ErrNeedsSync
		}
	}
	return nil
}

func (s *Store) verifyManifest(row spooldb.ReadPackageSlotRow, batches []spooldb.ListBatchesRow) error {
	if len(row.Manifest) == 0 || len(row.Manifest) > 65536 || !canonicalUUID(row.SnapshotID) {
		return ErrNeedsSync
	}
	manifest := &devicev1.PackageSnapshotManifest{}
	if err := proto.Unmarshal(row.Manifest, manifest); err != nil {
		return ErrNeedsSync
	}
	if err := protodata.ValidateClosed(manifest.ProtoReflect()); err != nil || s.validator.Validate(manifest) != nil {
		return ErrNeedsSync
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(manifest)
	if err != nil || !bytes.Equal(encoded, row.Manifest) {
		return ErrNeedsSync
	}
	id, err := uuid.Parse(manifest.GetSnapshotId())
	if err != nil || id.String() != row.SnapshotID || id.Version() != 7 || manifest.GetSequence() != uint64(row.Sequence) || manifest.GetEnrollmentGeneration() != s.identity.Generation.String() {
		return ErrNeedsSync
	}
	created, err := uuidV7Time(id)
	if err != nil || manifest.GetCreatedAt() == nil || manifest.GetCreatedAt().AsTime().Sub(created).Abs() > time.Second {
		return ErrNeedsSync
	}
	if len(manifest.GetBatches()) != len(batches) {
		return ErrNeedsSync
	}
	for i, desc := range manifest.GetBatches() {
		if desc.GetIndex() != uint32(i) || int64(desc.GetCount()) != batches[i].RecordCount || int64(desc.GetEncodedSize()) != batches[i].EncodedSize || !bytes.Equal(desc.GetSha256(), batches[i].Sha256) {
			return ErrNeedsSync
		}
	}
	return nil
}

func (s *Store) enforceBudget(owned []spooldb.OwnedDir) error {
	meta, err := s.metadataPhysical()
	if err != nil {
		return err
	}
	sqliteBytes, err := s.sqlitePhysical()
	if err != nil {
		return err
	}
	if sqliteBytes > sqlitePhysicalBudget || meta > MetadataBudget {
		return ErrCapacity
	}
	var blobs int64
	for _, row := range owned {
		n, err := s.collectionPhysical(row.CollectionID)
		if err != nil {
			return err
		}
		if n > collectionPhysicalBudget {
			return ErrCapacity
		}
		blobs += n
	}
	if blobs > collectionPhysicalBudget*2 || meta+blobs > SpoolBudget {
		return ErrCapacity
	}
	return nil
}

func (s *Store) deleteTracked(ctx context.Context) error {
	rows, err := s.queries.ListOwned(ctx)
	if err != nil {
		return dbErr(ctx, err)
	}
	for _, row := range rows {
		if err := s.deleteCollection(row.CollectionID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) discardPayloads(ctx context.Context) error {
	rows, err := s.queries.ListOwned(ctx)
	if err != nil {
		return dbErr(ctx, err)
	}
	err = s.tx(ctx, func(q *spooldb.Queries) error {
		for _, kind := range []int64{slotPending, slotQueued} {
			if err := q.DeleteHostSlot(ctx, kind); err != nil {
				return err
			}
			if err := q.DeletePackageSlot(ctx, kind); err != nil {
				return err
			}
		}
		for _, row := range rows {
			changed, err := q.MarkOwned(ctx, spooldb.MarkOwnedParams{Referenced: 0, ByteSize: row.ByteSize, CollectionID: row.CollectionID})
			if err != nil {
				return err
			}
			if changed != 1 {
				return ErrConflict
			}
		}
		return nil
	})
	if err != nil {
		return dbErr(ctx, err)
	}
	if err := s.checkpoint(ctx); err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	for _, row := range rows {
		if err := s.deleteCollection(row.CollectionID); err != nil {
			return err
		}
		if err := s.queries.DeleteBatches(ctx, row.CollectionID); err != nil {
			return err
		}
		if err := s.queries.DeleteOwned(ctx, row.CollectionID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) clearRecovery(ctx context.Context) error {
	if err := s.queries.DeleteRecovery(ctx); err != nil {
		return dbErr(ctx, err)
	}
	return nil
}

func decodeHost(raw []byte) (*inventoryv1.HostObservation, error) {
	if len(raw) == 0 || len(raw) > maxHostBytes {
		return nil, ErrInvalid
	}
	obs := &inventoryv1.HostObservation{}
	if err := proto.Unmarshal(raw, obs); err != nil {
		return nil, ErrInvalid
	}
	if err := protodata.ValidateClosed(obs.ProtoReflect()); err != nil {
		return nil, ErrInvalid
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(obs)
	if err != nil || !bytes.Equal(encoded, raw) {
		return nil, ErrInvalid
	}
	return obs, nil
}

func uuidV7Time(id uuid.UUID) (time.Time, error) {
	if id.Version() != 7 {
		return time.Time{}, ErrInvalid
	}
	ms := int64(id[0])<<40 | int64(id[1])<<32 | int64(id[2])<<24 | int64(id[3])<<16 | int64(id[4])<<8 | int64(id[5])
	if ms < 0 {
		return time.Time{}, ErrInvalid
	}
	return time.UnixMilli(ms).UTC(), nil
}

func unixTime(nanos int64) time.Time {
	return time.Unix(0, nanos).UTC()
}

func stamp(t time.Time) *timestamppb.Timestamp {
	return timestamppb.New(t)
}
