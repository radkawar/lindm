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
	clock      func() time.Time
	boottime   func() (time.Duration, error)
	verify     func(context.Context) error
	checkpoint func(context.Context) error
	attempted  bool
}

func (g *effectGate) fresh(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	elapsed, err := g.boottime()
	if err != nil {
		return err
	}
	if elapsed < g.started || elapsed-g.started >= 30*time.Second || !g.clock().Before(g.expires) {
		return ErrAuthorityExpired
	}
	return g.verify(ctx)
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
	// Recheck wall and suspend-aware monotonic deadlines after its response.
	return g.fresh(ctx)
}
