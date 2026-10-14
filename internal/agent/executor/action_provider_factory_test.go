// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"testing"
	"time"

	"lindm/internal/agent/journal"
)

func TestActionProviderFactorySharesProvisionedJournal(t *testing.T) {
	now := time.Date(2031, 7, 1, 0, 0, 0, 0, time.UTC)
	fixture := newFixture(t, now)
	directory := protectedDir(t)
	var supplied *journal.Store
	calls := 0
	native := new(actionBoundary)
	factory := WithActionProviderFactory(func(store *journal.Store) (DeviceActionProvider, error) {
		calls++
		supplied = store
		if _, _, err := store.Load(t.Context()); err != nil {
			t.Fatalf("factory received unopened journal: %v", err)
		}
		return native, nil
	})
	svc, err := New(t.Context(), directory, WithClock(func() time.Time { return now }), factory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = svc.Close() }()
	if calls != 0 || svc.actionProvider != nil {
		t.Fatal("provider composed before bootstrap created protected storage")
	}
	prepare(t, svc, fixture, "lg1_test-grant-secret-with-32-characters-minimum", false)
	if calls != 1 || supplied != svc.store || svc.actionProvider != native {
		t.Fatal("provider does not own the executor's existing journal")
	}
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	svc, err = New(t.Context(), directory, WithClock(func() time.Time { return now }), factory)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || supplied != svc.store || svc.actionProvider != native {
		t.Fatal("reopened executor did not compose provider exactly once")
	}
}
