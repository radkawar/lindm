//go:build linux

package actionprovider

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"buf.build/go/protovalidate"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestSessionSnapshotIgnoresAcknowledgementButFencesSessionChanges(t *testing.T) {
	sessions := []graphicalSession{{ID: "2"}, {ID: "1"}}
	p := &Provider{sessionNative: func(context.Context, string) ([]graphicalSession, error) { return sessions, nil }}
	locked, before, err := p.sessions(context.Background(), false)
	if err != nil || locked {
		t.Fatalf("before: locked=%v error=%v", locked, err)
	}
	sessions = []graphicalSession{{ID: "1", Locked: true}, {ID: "2", Locked: true}}
	locked, after, err := p.sessions(context.Background(), false)
	if err != nil || !locked || !bytes.Equal(before, after) {
		t.Fatalf("acknowledgement changed identity digest: %v", err)
	}
	sessions = sessions[:1]
	_, changed, err := p.sessions(context.Background(), false)
	if err != nil || bytes.Equal(before, changed) {
		t.Fatalf("session replacement was not fenced: %v", err)
	}
}

func TestSessionTerminationAndFreshGate(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		t.Run(map[bool]string{false: "terminate", true: "gate_denied"}[refuse], func(t *testing.T) {
			validator, err := protovalidate.New()
			if err != nil {
				t.Fatal(err)
			}
			var effects []string
			terminated := false
			p := &Provider{config: &agentv1.DeviceActionProviderConfig{AllowSessionLock: true}, validate: validator, gate: make(chan struct{}, 1), clock: time.Now}
			p.sessionNative = func(_ context.Context, operation string) ([]graphicalSession, error) {
				if operation == "observe" {
					if terminated {
						return nil, nil
					}
					return []graphicalSession{{ID: "1", Locked: true}}, nil
				}
				effects = append(effects, operation)
				if operation == "terminate" {
					terminated = true
				}
				return nil, nil
			}
			spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{TerminateSessions: true}}}
			ctx := context.Background()
			before, err := p.Observe(ctx, spec)
			if err != nil {
				t.Fatal(err)
			}
			if before.GetSessionsLocked() {
				t.Fatal("locked hints alone cannot prove termination")
			}
			plan, err := p.Plan(ctx, spec, before)
			if err != nil {
				t.Fatal(err)
			}
			plan.ActionId = fixtureAction
			denied := errors.New("gate denied")
			result, err := p.Apply(ctx, plan, nil, func(context.Context) error {
				if refuse {
					return denied
				}
				return nil
			})
			if refuse {
				if !errors.Is(err, denied) || len(effects) != 0 {
					t.Fatalf("denied gate had effects=%v error=%v", effects, err)
				}
			} else if err != nil || !result.GetVerified() || !slices.Equal(effects, []string{"lock", "terminate"}) {
				t.Fatalf("termination result verified=%v effects=%v error=%v", result.GetVerified(), effects, err)
			}
		})
	}
}

func TestSessionEffectFailureIsOutcomeUnknownAndNeverRetried(t *testing.T) {
	validator, err := protovalidate.New()
	if err != nil {
		t.Fatal(err)
	}
	effects := 0
	p := &Provider{config: &agentv1.DeviceActionProviderConfig{AllowSessionLock: true}, validate: validator, gate: make(chan struct{}, 1), clock: time.Now}
	p.sessionNative = func(_ context.Context, operation string) ([]graphicalSession, error) {
		if operation == "observe" {
			return []graphicalSession{{ID: "1"}}, nil
		}
		effects++
		return nil, context.DeadlineExceeded
	}
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{}}}
	before, err := p.Observe(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := p.Plan(context.Background(), spec, before)
	if err != nil {
		t.Fatal(err)
	}
	plan.ActionId = fixtureAction
	_, err = p.Apply(context.Background(), plan, nil, func(context.Context) error { return nil })
	if !errors.Is(err, ErrOutcomeUnknown) || effects != 1 {
		t.Fatalf("ambiguous effect repeated or lost: effects=%d error=%v", effects, err)
	}
}
