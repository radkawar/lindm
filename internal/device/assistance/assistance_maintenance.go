// SPDX-License-Identifier: Apache-2.0

package assistance

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"lindm/internal/auditkind"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
)

const assistanceMaintenanceInterval = time.Minute

// RunAssistanceMaintenance is the exclusive background job that enforces
// recording retention, settles recordings whose session ended without a final
// segment, expires reconnect workflows and removes expired retrievals.
func (s *Service) RunAssistanceMaintenance(ctx context.Context) error {
	ticker := time.NewTicker(assistanceMaintenanceInterval)
	defer ticker.Stop()
	for {
		if err := s.MaintainAssistance(ctx); err != nil && ctx.Err() == nil {
			slog.Error("assistance maintenance failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// MaintainAssistance runs one bounded maintenance pass. Each object is handled
// in its own transaction so one failure never blocks the others.
func (s *Service) MaintainAssistance(ctx context.Context) error {
	now := s.Now()
	var first error
	keep := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	q := devicedb.New(s.Pool)
	due, err := q.ListAssistanceRecordingsDue(ctx, devicedb.ListAssistanceRecordingsDueParams{Now: core.Timestamptz(now), SettleBefore: core.Timestamptz(now.Add(-assistanceRecordingGrace))})
	if err != nil {
		return err
	}
	for _, id := range due {
		keep(s.Within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
			row, err := q.LockAssistanceRecording(ctx, id)
			if err != nil {
				return err
			}
			now := s.Now()
			if (row.State == recordingComplete || row.State == recordingIncomplete) && !now.Before(row.RetainUntil.Time) {
				expired := row
				if err := deleteAssistanceRecordingContent(ctx, q, &row, now, "retention_expired"); err != nil {
					return err
				}
				return recordAssistanceRecordingAudit(ctx, q, nil, auditkind.AssistanceRecordingRetention, expired, "deleted", "retention_expired", "retain_until", expired.RetainUntil.Time.Format(time.RFC3339))
			}
			return settleAssistanceRecording(ctx, q, &row, now)
		}))
	}
	expired, err := q.ListExpiredAssistanceReconnects(ctx, core.Timestamptz(now))
	if err != nil {
		return errors.Join(first, err)
	}
	for _, id := range expired {
		keep(s.Within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
			workflow, err := q.LockAssistanceReconnectWorkflow(ctx, id)
			if err != nil {
				return err
			}
			_, err = expireAssistanceReconnect(ctx, q, &workflow, s.Now())
			return err
		}))
	}
	keep(q.DeleteExpiredAssistanceRecordingRetrievals(ctx, core.Timestamptz(now)))
	return first
}
