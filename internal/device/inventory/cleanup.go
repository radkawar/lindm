package inventory

import (
	"context"
	"log/slog"
	"time"

	"lindm/internal/device/core"

	"github.com/google/uuid"

	"lindm/internal/device/devicedb"
)

// RunSnapshotCleanup is an exclusive job and returns only on cancellation. Each
// device is cleaned under its own row lock, so a briefly overlapping former
// leader cannot release the same reservation twice.
func (s *Service) RunSnapshotCleanup(ctx context.Context) error {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		if err := s.CleanupSnapshots(ctx); err != nil && ctx.Err() == nil {
			slog.Error("snapshot cleanup failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (s *Service) CleanupSnapshots(ctx context.Context) error {
	now := s.Now()
	if err := s.Within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
		return q.DeleteExpiredPackageCursors(ctx, core.Timestamptz(now))
	}); err != nil {
		return err
	}
	ids, err := devicedb.New(s.Pool).ListInventoryCleanupDevices(ctx)
	if err != nil {
		return err
	}
	var first error
	for _, id := range ids {
		err := s.Within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
			device, err := q.GetDeviceForUpdate(ctx, id)
			if err != nil {
				return err
			}
			return s.cleanupDevice(ctx, q, device, s.Now())
		})
		if err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (s *Service) cleanupDevice(ctx context.Context, q *devicedb.Queries, device devicedb.GetDeviceForUpdateRow, now time.Time) error {
	if err := q.DeleteExpiredPackageCursors(ctx, core.Timestamptz(now)); err != nil {
		return err
	}
	open, err := q.ListExpiredOpenSnapshots(ctx, devicedb.ListExpiredOpenSnapshotsParams{DeviceID: device.ID, Now: core.Timestamptz(now)})
	if err != nil {
		return err
	}
	for _, row := range open {
		if err := s.expireStaging(ctx, q, device.ID, row.ID, row.ReservedBytes, row.MetadataBytes); err != nil {
			return err
		}
	}
	bulk, err := q.ListReleasableSnapshotBulk(ctx, devicedb.ListReleasableSnapshotBulkParams{
		DeviceID: device.ID, Cutoff: core.Timestamptz(now.Add(-supersededBulkRetention)), Now: core.Timestamptz(now),
	})
	if err != nil {
		return err
	}
	for _, row := range bulk {
		if err := q.DeleteSnapshotPackages(ctx, row.ID); err != nil {
			return err
		}
		if err := q.ReleaseSnapshotBulk(ctx, devicedb.ReleaseSnapshotBulkParams{ReservedBytes: row.MetadataBytes, ID: row.ID}); err != nil {
			return err
		}
		release := row.ReservedBytes - row.MetadataBytes
		if release < 0 {
			return core.ErrInternalState
		}
		if err := s.releaseInventory(ctx, q, device.ID, release); err != nil {
			return err
		}
	}
	receipts, err := q.ListExpiredSnapshotReceipts(ctx, devicedb.ListExpiredSnapshotReceiptsParams{DeviceID: device.ID, Now: core.Timestamptz(now)})
	if err != nil {
		return err
	}
	for _, row := range receipts {
		if err := s.deleteReceipt(ctx, q, device.ID, row.ID, row.ReservedBytes, now); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) expireStaging(ctx context.Context, q *devicedb.Queries, deviceID, snapshotID uuid.UUID, reserved, metadata int64) error {
	if err := q.DeleteSnapshotPackages(ctx, snapshotID); err != nil {
		return err
	}
	if err := q.ExpireStagingSnapshot(ctx, devicedb.ExpireStagingSnapshotParams{ReservedBytes: metadata, ID: snapshotID}); err != nil {
		return err
	}
	release := reserved - metadata
	if release < 0 {
		return core.ErrInternalState
	}
	if err := s.releaseInventory(ctx, q, deviceID, release); err != nil {
		return err
	}
	return q.ClearOpenSnapshot(ctx, devicedb.ClearOpenSnapshotParams{ID: deviceID, OpenSnapshotID: &snapshotID})
}

func (s *Service) deleteReceipt(ctx context.Context, q *devicedb.Queries, deviceID, snapshotID uuid.UUID, reserved int64, now time.Time) error {
	if err := q.DeleteSnapshotCursors(ctx, devicedb.DeleteSnapshotCursorsParams{SnapshotID: snapshotID, Now: core.Timestamptz(now)}); err != nil {
		return err
	}
	if err := q.DeleteSnapshotBatches(ctx, snapshotID); err != nil {
		return err
	}
	if err := q.DeleteSnapshotPackages(ctx, snapshotID); err != nil {
		return err
	}
	if err := q.DeletePackageSnapshot(ctx, snapshotID); err != nil {
		return err
	}
	return s.releaseInventory(ctx, q, deviceID, reserved)
}
