//go:build linux

package osupdateprovider

import (
	"context"
	"errors"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/osupdate"
)

// refusingStore fails the test on any ownership access: a busy refusal must
// precede every ledger read and mutation.
type refusingStore struct {
	t    *testing.T
	load error
}

func (s refusingStore) LoadResourceOwnership(context.Context, string, string, string, *resourcev1.ResourceRef) (*agentv1.ResourceOwnershipLedger, error) {
	if s.load == nil {
		s.t.Fatal("ledger read while the run lock was not held")
	}
	return nil, s.load
}

func (s refusingStore) ClaimResourceOwnership(context.Context, string, int64, *agentv1.ResourceOwnershipSnapshot) (*agentv1.ResourceOwnershipLedger, error) {
	s.t.Fatal("ownership claimed")
	return nil, nil
}

func (s refusingStore) BeginResourceOwnershipEffect(context.Context, string, int64, *agentv1.ResourceOwnershipSnapshot, []agentv1.ResourceOwnedDimension) (*agentv1.ResourceOwnershipLedger, error) {
	s.t.Fatal("ownership effect begun")
	return nil, nil
}

func (s refusingStore) CompleteResourceOwnershipEffect(context.Context, string, int64, *agentv1.ResourceOwnershipSnapshot) (*agentv1.ResourceOwnershipLedger, error) {
	s.t.Fatal("ownership effect completed")
	return nil, nil
}

// The x86_64 Fedora 44 lane's periodic reconcile ran its helper while the
// window run's dnf5 transaction was upgrading systemd and dnf5: the
// post-effect observation no longer matched, and the ledger stayed UNKNOWN.
// An effect now refuses as busy, before the ownership effect begins, while a
// run holds the runner's lock, and holds that lock itself until it returns.
func TestApplyRefusesWhileAnUpdateRunHoldsTheLock(t *testing.T) {
	p := fixtureProvider(t)
	desired := fixtureDesired()
	plan, _, err := p.plan(t.Context(), fixtureState(desired), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, fixtureSnapshot(t, p, nil, false, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	p.store = refusingStore{t: t}
	p.config.ExecuteNative = func(context.Context, *agentv1.NativeResourceTransactionRequest, func(context.Context) error) (*agentv1.ResourceOwnershipSnapshot, error) {
		t.Fatal("native helper launched during an update run")
		return nil, nil
	}
	p.runLock = func() (func() error, error) { return nil, osupdate.ErrRunInProgress }
	gate := func(context.Context) error { t.Fatal("start gate consumed"); return nil }
	if _, err := p.Apply(t.Context(), plan, gate); !errors.Is(err, ErrBusy) {
		t.Fatalf("apply during an update run = %v, want ErrBusy", err)
	}

	// Without contention the lock is held through the ledger work and
	// released on every return.
	held, released := false, false
	p.runLock = func() (func() error, error) {
		held = true
		return func() error { released = true; return nil }, nil
	}
	stop := errors.New("ledger unavailable")
	p.store = refusingStore{t: t, load: stop}
	if _, err := p.Apply(t.Context(), plan, gate); !errors.Is(err, stop) || !held || !released {
		t.Fatalf("apply = %v, lock held %v released %v", err, held, released)
	}
}
