// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"lindm/internal/integrations/integrationdb"
)

// RunDeliveries is a replicated job: every instance owns four bounded workers.
// Leases are fenced by random token, monotonically increasing generation and
// database time. A webhook receiver must deduplicate the signed body's event_id
// per destination, not the informational unsigned delivery/replay headers. A
// crash after send/before commit, or a process pause beyond a lease, may cause a
// duplicate network effect. Store failure returns to the job supervisor, which
// restarts the workers after backoff.
func (s *Service) RunDeliveries(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers sync.WaitGroup
	failures := make(chan error, 4)
	for range 4 {
		workers.Go(func() {
			sender := &deliverySender{service: s}
			defer sender.close()
			for ctx.Err() == nil {
				workCtx, stop := context.WithTimeout(ctx, 25*time.Second)
				worked, err := s.workOne(workCtx, sender)
				stop()
				if err != nil {
					if ctx.Err() == nil {
						failures <- errors.New("integrations: delivery store unavailable")
						cancel()
					}
					return
				}
				if !worked {
					timer := time.NewTimer(250 * time.Millisecond)
					select {
					case <-ctx.Done():
						timer.Stop()
					case <-timer.C:
					}
				}
			}
		})
	}
	workers.Wait()
	close(failures)
	return <-failures
}

// RunComplianceDeadlines is an exclusive job that turns expired verification
// deadlines into compliance events. Each pass row-locks assignments with SKIP
// LOCKED and records only state transitions, so a briefly overlapping former
// leader cannot emit duplicate events.
func (s *Service) RunComplianceDeadlines(ctx context.Context) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		scanCtx, stop := context.WithTimeout(ctx, 15*time.Second)
		err := integrationdb.New(s.pool).RefreshComplianceEvents(scanCtx)
		stop()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("integrations: compliance event store unavailable")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (s *Service) workOne(ctx context.Context, sender *deliverySender) (bool, error) {
	q := integrationdb.New(s.pool)
	if err := q.ExpireExhaustedDeliveries(ctx); err != nil {
		return false, err
	}
	token := uuid.New()
	delivery, err := q.ClaimDelivery(ctx, &token)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	target, err := q.LoadDeliveryTarget(ctx, delivery.DestinationID)
	reason := ""
	if errors.Is(err, pgx.ErrNoRows) {
		reason = "destination_disabled"
	} else if err != nil {
		return true, err
	}
	if reason == "" {
		event, loadErr := q.LoadEvent(ctx, delivery.EventID)
		if loadErr != nil {
			return true, loadErr
		}
		sendCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		reason = sender.send(sendCtx, target, event, delivery)
		cancel()
	}
	if reason == "" {
		_, err = q.CompleteDelivery(ctx, integrationdb.CompleteDeliveryParams{ID: delivery.ID, LeaseToken: delivery.LeaseToken, LeaseGeneration: delivery.LeaseGeneration})
	} else {
		_, err = q.FailDelivery(ctx, integrationdb.FailDeliveryParams{ID: delivery.ID, LeaseToken: delivery.LeaseToken, LeaseGeneration: delivery.LeaseGeneration, LastError: reason, DelaySeconds: retryDelay(delivery.Attempts).Seconds()})
	}
	return true, err
}

// Equal jitter keeps every retry delayed and caps the total delay at fifteen
// minutes. Attempts are durable and exhausted leases also become dead letters.
func retryDelay(attempt int32) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 10 {
		attempt = 10
	}
	ceiling := 5 * time.Second * time.Duration(1<<uint(attempt-1))
	if ceiling > 15*time.Minute {
		ceiling = 15 * time.Minute
	}
	return ceiling/2 + time.Duration(rand.Int64N(int64(ceiling/2)+1))
}
