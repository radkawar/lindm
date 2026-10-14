// SPDX-License-Identifier: Apache-2.0

package jobs

import (
	"context"
	"errors"
	"testing"
)

func TestJobHealthSeparatesFailureFromWaitingAndCancellation(t *testing.T) {
	observer := &jobHealth{states: make([]uint8, 2)}
	s := &Supervisor{health: observer}
	initial := s.Health()
	if initial.Waiting != 2 || initial.Running != 0 || initial.Failed != 0 || !initial.ChangedAt.IsZero() {
		t.Fatal("unstarted loops fabricated activity")
	}
	run := observer.supervise(0, func(context.Context) error {
		current := s.Health()
		if current.Running != 1 || current.Waiting != 1 {
			t.Fatal("running loop not observed separately from waiting leadership")
		}
		return errors.New("do-not-disclose-private-worker-error")
	})
	if err := run(t.Context()); err == nil {
		t.Fatal("supervision changed job error")
	}
	failed := s.Health()
	if failed.Failed != 1 || failed.Waiting != 1 || failed.Running != 0 {
		t.Fatalf("failed loop observation: %+v", failed)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := observer.supervise(0, func(ctx context.Context) error { return ctx.Err() })(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("supervision changed cancellation")
	}
	stopped := s.Health()
	if stopped.Failed != 0 || stopped.Waiting != 2 {
		t.Fatal("normal cancellation falsely classified as a worker failure")
	}
}
