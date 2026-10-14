// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

// Native consent could be dismissed without ActionInvoked by a 60 ms pulse at
// the correct action coordinates. The virtual clock checks the actual event
// sequence, including the released dwell before the caller parks the pointer.
func TestLocalPointerClickSeparatesPressReleaseAndPark(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		var events []struct {
			down bool
			at   time.Duration
		}
		err := localPointerClick(t.Context(), func(down bool) error {
			events = append(events, struct {
				down bool
				at   time.Duration
			}{down, time.Since(start)})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 2 || !events[0].down || events[1].down {
			t.Fatalf("not one explicit press/release: %+v", events)
		}
		if events[0].at != 0 || events[1].at != 250*time.Millisecond {
			t.Fatalf("press/release timing = %+v", events)
		}
		if elapsed := time.Since(start); elapsed != 500*time.Millisecond {
			t.Fatalf("pointer may park after %v, want 500ms", elapsed)
		}
	})
}

func TestLocalPointerClickPreservesCancellationAndCommandFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		calls := 0
		err := localPointerClick(ctx, func(bool) error {
			calls++
			return nil
		})
		if !errors.Is(err, context.DeadlineExceeded) || calls != 1 {
			t.Fatalf("cancelled click: calls=%d, error=%v", calls, err)
		}
	})
	synctest.Test(t, func(t *testing.T) {
		denied := errors.New("QMP denied input")
		start := time.Now()
		calls := 0
		err := localPointerClick(t.Context(), func(bool) error {
			calls++
			return denied
		})
		if !errors.Is(err, denied) || calls != 1 || time.Since(start) != 0 {
			t.Fatalf("denied click: calls=%d, error=%v", calls, err)
		}
	})
}
