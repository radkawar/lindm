// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"context"
	"errors"
	"sync"
	"time"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

var (
	ErrRefreshStalled = errors.New("feed: refresh made no document or committed-batch progress")
	ErrRefreshCeiling = errors.New("feed: refresh exceeded its overall time ceiling")
)

// RefreshProgress bounds a source by completed work, not by archive size or bytes
// trickling over the network. Mark is called only after a full document was parsed
// or a publication batch committed. Its clock retains monotonic time semantics.
// Close must be called; it joins the watchdog and releases both context timers.
type RefreshProgress struct {
	ctx           context.Context
	cancel        context.CancelCauseFunc
	cancelOverall context.CancelFunc
	mu            sync.Mutex
	last          time.Time
	idle          time.Duration
	done          chan struct{}
}

func NewRefreshProgress(parent context.Context, source *advisoryv1.FeedSource) (context.Context, *RefreshProgress) {
	idle, overall := 5*time.Minute, 2*time.Hour
	if value := source.GetProgressTimeoutSeconds(); value != 0 {
		idle = time.Duration(value) * time.Second
	}
	if value := source.GetRefreshTimeoutSeconds(); value != 0 {
		overall = time.Duration(value) * time.Second
	}
	return newRefreshProgress(parent, idle, overall)
}

func newRefreshProgress(parent context.Context, idle, overall time.Duration) (context.Context, *RefreshProgress) {
	bounded, cancelOverall := context.WithTimeoutCause(parent, overall, ErrRefreshCeiling)
	ctx, cancel := context.WithCancelCause(bounded)
	progress := &RefreshProgress{ctx: ctx, cancel: cancel, cancelOverall: cancelOverall, last: time.Now(), idle: idle, done: make(chan struct{})}
	go progress.watch()
	return ctx, progress
}

func (p *RefreshProgress) Mark() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := context.Cause(p.ctx); err != nil {
		return err
	}
	p.last = time.Now()
	return nil
}

func (p *RefreshProgress) Close() {
	p.cancel(context.Canceled)
	p.cancelOverall()
	<-p.done
}

func (p *RefreshProgress) watch() {
	defer close(p.done)
	timer := time.NewTimer(p.idle)
	defer timer.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-timer.C:
			p.mu.Lock()
			remaining := time.Until(p.last.Add(p.idle))
			if remaining <= 0 {
				p.cancel(ErrRefreshStalled)
			}
			p.mu.Unlock()
			if remaining <= 0 {
				return
			}
			timer.Reset(remaining)
		}
	}
}
