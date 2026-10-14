// SPDX-License-Identifier: Apache-2.0

//go:build linux

package definitionprovider

import (
	"context"
	"errors"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

func timerState(enabled, active bool) *resourcev1.SystemdDefinitionObservation {
	return &resourcev1.SystemdDefinitionObservation{TimerEnabled: proto.Bool(enabled), TimerActive: proto.Bool(active)}
}
func TestTimerEnablementAndStartAreSeparateIdempotentEffects(t *testing.T) {
	manager := &fakeManager{}
	if err := timerAfter(context.Background(), manager, "example.timer", timerState(false, false), timerState(true, true)); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(manager.calls, []string{"enable", "reload", "start"}) {
		t.Fatalf("timer enable/start semantics = %v", manager.calls)
	}
	manager.calls = nil
	if err := timerAfter(context.Background(), manager, "example.timer", timerState(true, true), timerState(true, true)); err != nil {
		t.Fatal(err)
	}
	if len(manager.calls) != 0 {
		t.Fatalf("converged timer restarted: %v", manager.calls)
	}
	if err := timerBefore(context.Background(), manager, "example.timer", timerState(true, true), timerState(false, false)); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(manager.calls, []string{"stop", "disable"}) {
		t.Fatalf("timer release semantics = %v", manager.calls)
	}
}
func TestFailedReloadDoesNotStartOrReplayTimer(t *testing.T) {
	manager := &fakeManager{fail: "reload"}
	err := timerAfter(context.Background(), manager, "example.timer", timerState(false, false), timerState(true, true))
	if !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("failed reload not uncertain: %v", err)
	}
	if !slices.Equal(manager.calls, []string{"enable", "reload"}) {
		t.Fatalf("failed reload started or retried effect: %v", manager.calls)
	}
}
func TestInterruptedEffectsDoNotContinue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := &fakeManager{cancel: cancel}
	err := timerBefore(ctx, manager, "example.timer", timerState(true, true), timerState(false, false))
	if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted stop = %v", err)
	}
	if !slices.Equal(manager.calls, []string{"stop"}) {
		t.Fatalf("continued after interruption: %v", manager.calls)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	cancel()
	manager = &fakeManager{}
	if err := timerAfter(ctx, manager, "example.timer", timerState(false, false), timerState(true, true)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled preflight = %v", err)
	}
	if len(manager.calls) != 0 {
		t.Fatalf("canceled preflight mutated: %v", manager.calls)
	}
}
func TestFailedStopDoesNotDisableTimer(t *testing.T) {
	manager := &fakeManager{fail: "stop"}
	if err := timerBefore(context.Background(), manager, "example.timer", timerState(true, true), timerState(false, false)); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("failed stop = %v", err)
	}
	if !slices.Equal(manager.calls, []string{"stop"}) {
		t.Fatalf("disable after failed stop = %v", manager.calls)
	}
}
