// SPDX-License-Identifier: Apache-2.0

//go:build linux

package transport

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"connectrpc.com/connect"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// A challenge is prepared only after any previous ordinary inventory operation
// has joined. The sole owner cannot admit either a staging manifest or a full
// ordinary publication in the challenge-to-consume interval.
func TestDeviceActionStartHoldsInventoryOwner(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDeviceActionRelayFixture(t)
		r := &runner{refreshes: make(chan inventoryRefreshJob)}
		f.loop.withInventoryOwner = r.withInventoryOwner
		entered, release := make(chan struct{}), make(chan struct{})
		executor, ok := f.loop.executor.(*deviceActionRelayExecutor)
		if !ok {
			t.Fatal("relay fixture executor has unexpected type")
		}
		f.loop.executor = &inventoryOwnerStartBarrier{deviceActionRelayExecutor: executor, entered: entered, release: release}
		done := make(chan error, 1)
		go func() { done <- f.loop.dispatchDeviceActions(t.Context()) }()
		var job inventoryRefreshJob
		select {
		case job = <-r.refreshes:
		case <-entered:
			close(release)
			<-done
			t.Fatal("start reached executor before inventory owner handoff")
		}
		if f.prepares != 0 || f.authorizations != 0 || f.starts != 0 {
			t.Fatal("challenge or grant escaped inventory owner handoff")
		}
		ordinaryAdmitted := false
		ownerDone := make(chan struct{})
		go func() {
			r.handleInventoryRefresh(job)
			// This models the next ordinary cycle on the same owner. Both host
			// admission and package begin/commit must occur after consumption.
			ordinaryAdmitted = true
			close(ownerDone)
		}()
		<-entered
		synctest.Wait()
		if f.prepares != 1 || f.authorizations != 1 || ordinaryAdmitted {
			t.Fatal("ordinary inventory entered the challenge-to-consume window")
		}
		close(release)
		<-ownerDone
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if !ordinaryAdmitted || f.starts != 1 || f.reports != 1 || !f.closed {
			t.Fatal("serialized start did not complete exactly once")
		}
	})
}

type inventoryOwnerStartBarrier struct {
	*deviceActionRelayExecutor
	entered chan struct{}
	release chan struct{}
}

func (e *inventoryOwnerStartBarrier) StartDeviceAction(ctx context.Context, req *connect.Request[agentv1.StartDeviceActionRequest]) (*connect.Response[agentv1.StartDeviceActionResponse], error) {
	close(e.entered)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-e.release:
	}
	return e.deviceActionRelayExecutor.StartDeviceAction(ctx, req)
}

func TestInventoryOwnerFencesUncertainChallenge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := &runner{}
		lost := errors.New("lost prepare or start reply")
		job := inventoryRefreshJob{ctx: t.Context(), operation: func() error { return lost }, done: make(chan error, 1)}
		r.handleInventoryRefresh(job)
		if err := <-job.done; !errors.Is(err, lost) {
			t.Fatal(err)
		}
		if got := time.Until(r.inventoryNotBefore); got != deviceActionCredentialWait {
			t.Fatalf("uncertain challenge fence = %v", got)
		}
		// No executor or store is installed: reaching ordinary work would panic.
		if err := r.cycle(t.Context()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(deviceActionCredentialWait - time.Nanosecond)
		if err := r.cycle(t.Context()); err != nil {
			t.Fatal(err)
		}
		// An owner job is still admitted while ordinary work is fenced, and an
		// exact retained-grant success can resume ordinary collection immediately.
		job.operation = func() error { return nil }
		r.handleInventoryRefresh(job)
		if err := <-job.done; err != nil {
			t.Fatal(err)
		}
		if !r.inventoryNotBefore.IsZero() {
			t.Fatal("successful recovery retained inventory fence")
		}
	})
}
