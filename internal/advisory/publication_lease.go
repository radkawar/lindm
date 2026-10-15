// SPDX-License-Identifier: Apache-2.0

package advisory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"lindm/internal/advisory/advisorydb"
)

// startAdvisoryLeaseHeartbeat keeps ownership while a parser completes documents
// before emitting its first batch. It never marks parser progress: only actual
// parsed documents and committed batches may extend the watchdog. The caller
// owns the bounded parent context and must stop/join before removing the lease.
func (s *Service) startAdvisoryLeaseHeartbeat(parent context.Context, generation uuid.UUID, interval time.Duration, lease *sync.Mutex) (context.Context, func()) {
	ctx, fail := context.WithCancelCause(parent)
	heartbeatCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				lease.Lock()
				if heartbeatCtx.Err() != nil {
					lease.Unlock()
					return
				}
				bounded, stop := context.WithTimeout(heartbeatCtx, 5*time.Second)
				renewed, err := advisorydb.New(s.pool).RenewAdvisoryGeneration(bounded, generation)
				stop()
				lease.Unlock()
				if heartbeatCtx.Err() != nil {
					return
				}
				if err != nil {
					fail(fmt.Errorf("renew advisory publication lease: %w", err))
					return
				}
				if renewed != 1 {
					fail(ErrConflict)
					return
				}
			}
		}
	}()
	var stopped sync.Once
	return ctx, func() {
		stopped.Do(func() {
			cancel()
			<-done
		})
	}
}
