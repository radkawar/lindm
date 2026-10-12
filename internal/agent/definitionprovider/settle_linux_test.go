//go:build linux

package definitionprovider

import (
	"context"
	"errors"
	"testing"
	"time"
)

// pendingManager reports a queued job for the first pending observations.
type pendingManager struct {
	fakeManager
	pending int
	calls   int
}

func (m *pendingManager) Unit(context.Context, string, string) (*unitView, error) {
	m.calls++
	return &unitView{id: "example.service", pending: m.calls <= m.pending}, nil
}

// A timer that elapses during an apply queues a start for the target (Fedora
// 44 x86_64 timer-calendar-fires-target); the observation waits for that job
// instead of turning an in-flight apply into an outcome-unknown conflict.
func TestSettledTargetWaitsForTransientJob(t *testing.T) {
	m := &pendingManager{pending: 3}
	target, err := settledTarget(context.Background(), m, "example.service", 5*time.Second)
	if err != nil || target == nil || target.pending || m.calls != 4 {
		t.Fatalf("target %+v, err %v after %d observations", target, err, m.calls)
	}
}

func TestSettledTargetRefusesAPersistentJob(t *testing.T) {
	m := &pendingManager{pending: 1 << 30}
	if _, err := settledTarget(context.Background(), m, "example.service", 300*time.Millisecond); !errors.Is(err, ErrConflict) {
		t.Fatalf("persistent job: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := settledTarget(ctx, &pendingManager{pending: 1 << 30}, "example.service", time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled wait: %v", err)
	}
}
