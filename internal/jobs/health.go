// SPDX-License-Identifier: Apache-2.0

package jobs

import (
	"context"
	"sync"
	"time"
)

// Health is local loop-lifetime evidence, not proof of completed work or of
// leadership elsewhere. Waiting exclusive jobs are distinct from failed loops.
type Health struct {
	Running   int
	Waiting   int
	Failed    int
	ChangedAt time.Time
}

type jobHealth struct {
	mu        sync.Mutex
	states    []uint8
	changedAt time.Time
}

func (h *jobHealth) observe(index int, state uint8) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.states[index] = state
	h.changedAt = time.Now()
}

func (h *jobHealth) supervise(index int, run func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		h.observe(index, 1)
		err := run(ctx)
		if ctx.Err() != nil {
			h.observe(index, 0)
		} else {
			h.observe(index, 2)
		}
		return err
	}
}

// Health snapshots all configured job loops without disclosing error messages.
func (s *Supervisor) Health() Health {
	h := s.health
	h.mu.Lock()
	defer h.mu.Unlock()
	result := Health{ChangedAt: h.changedAt}
	for _, state := range h.states {
		switch state {
		case 1:
			result.Running++
		case 2:
			result.Failed++
		default:
			result.Waiting++
		}
	}
	return result
}
