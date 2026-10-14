// SPDX-License-Identifier: Apache-2.0

//go:build linux

package recovery

import (
	"context"
	"errors"
	"time"

	"golang.org/x/sys/unix"
)

var ErrAuthorityExpired = errors.New("recovery_start_authority_expired")

func bootTime() (time.Duration, error) {
	var value unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &value); err != nil {
		return 0, err
	}
	return time.Duration(value.Nano()), nil
}

// effectGate is process-local and never reconstructed from a prior start grant.
// The immutable journal marker survives any loss of the server acknowledgment.
// The native provider invokes this exactly at its final before-effect boundary.
type effectGate struct {
	journal    StateStore
	started    time.Duration
	expires    time.Time
	clock      func() (time.Time, time.Time, error)
	boottime   func() (time.Duration, error)
	verify     func(context.Context) error
	checkpoint func(context.Context) error
	attempted  bool
}

func (g *effectGate) fresh(ctx context.Context) error {
	if err := g.deadline(ctx); err != nil {
		return err
	}
	// Signature verification can span a suspend or consume the remaining grant
	// lifetime. Sample both deadlines after it, at the native effect boundary.
	if err := g.verify(ctx); err != nil {
		return err
	}
	return g.deadline(ctx)
}

func (g *effectGate) deadline(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	elapsed, err := g.boottime()
	if err != nil {
		return err
	}
	_, latest, err := g.clock()
	if err != nil {
		return err
	}
	if elapsed < g.started || elapsed-g.started >= 30*time.Second || !latest.Before(g.expires) {
		return ErrAuthorityExpired
	}
	return nil
}

func (g *effectGate) consume(ctx context.Context) error {
	if g.attempted {
		return ErrConsumed
	}
	g.attempted = true
	if err := g.fresh(ctx); err != nil {
		return err
	}
	if err := g.journal.Consume(); err != nil {
		return err
	}
	// checkpoint persists the exact protobuf state off-target, commits it on
	// the server and authenticates the response. Any error retains consumption.
	if err := g.checkpoint(ctx); err != nil {
		return err
	}
	// A durable server round trip may itself use the remaining grant lifetime.
	// Recheck authenticated and suspend-aware monotonic deadlines after its response.
	return g.fresh(ctx)
}
