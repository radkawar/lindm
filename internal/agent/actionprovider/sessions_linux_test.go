//go:build linux

package actionprovider

import (
	"bytes"
	"context"
	"errors"
	"net"
	"path/filepath"
	"slices"
	"strings"
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

// unreportedLockFixture plans a session lock against a desktop whose locker
// never reports LockedHint, as cinnamon-screensaver, cosmic-greeter and a
// Hyprland session without a logind Lock listener do.
func unreportedLockFixture(t *testing.T) (*Provider, *agentv1.DeviceActionPlan, *int) {
	t.Helper()
	validator, err := protovalidate.New()
	if err != nil {
		t.Fatal(err)
	}
	effects := 0
	p := &Provider{config: &agentv1.DeviceActionProviderConfig{AllowSessionLock: true}, validate: validator, gate: make(chan struct{}, 1), clock: time.Now, lockWait: 300 * time.Millisecond}
	p.sessionNative = func(_ context.Context, operation string) ([]graphicalSession, error) {
		switch operation {
		case "observe":
			return []graphicalSession{{ID: "3"}}, nil
		case "lock":
			effects++
			return nil, nil
		default:
			return nil, errors.New("unexpected session operation")
		}
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
	return p, plan, &effects
}

func TestUnreportedSessionLockIsVisibleAndNeverClaimed(t *testing.T) {
	p, plan, effects := unreportedLockFixture(t)
	result, err := p.Apply(context.Background(), plan, nil, func(context.Context) error { return nil })
	if err != nil {
		t.Fatalf("an elapsed acknowledgement window is a definite observation, not an interruption: %v", err)
	}
	if result.GetVerified() || result.GetAfter().GetSessionsLocked() || *effects != 1 {
		t.Fatalf("unreported lock claimed or repeated: verified=%v locked=%v effects=%d", result.GetVerified(), result.GetAfter().GetSessionsLocked(), *effects)
	}
	if !strings.HasPrefix(result.GetEvidence(), "session_lock_state_unreported: ") || !strings.Contains(result.GetEvidence(), "300ms") {
		t.Fatalf("evidence does not name the unreported lock state: %q", result.GetEvidence())
	}
	if err := p.validate.Validate(result); err != nil {
		t.Fatalf("unreported verification is not a valid executor result: %v", err)
	}
	again, err := p.Verify(context.Background(), plan, result)
	if err != nil || again.GetVerified() || *effects != 1 {
		t.Fatalf("re-verification claimed the lock or repeated it: verified=%v effects=%d error=%v", again.GetVerified(), *effects, err)
	}
}

func TestSessionLockCancellationRemainsOutcomeUnknown(t *testing.T) {
	p, plan, effects := unreportedLockFixture(t)
	p.lockWait = time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := p.Apply(ctx, plan, nil, func(context.Context) error { return nil })
	if !errors.Is(err, ErrOutcomeUnknown) || errors.Is(err, errSessionLockUnreported) || *effects != 1 {
		t.Fatalf("cancelled acknowledgement wait was misreported: effects=%d error=%v", *effects, err)
	}
}

// A native logind call can see the acknowledgement window's deadline pass
// before the window's timer fires: dialing the bus past it fails with an i/o
// timeout that is context.DeadlineExceeded. That is the window ending, not an
// interruption (pop2404-lock-quarantine-07 ended OUTCOME_UNKNOWN/INTERRUPTED).
func TestSessionLockWindowDeadlineRaceIsUnreportedNotInterrupted(t *testing.T) {
	p, plan, effects := unreportedLockFixture(t)
	_, dialErr := (&net.Dialer{Deadline: time.Now().Add(-time.Second)}).Dial("unix", filepath.Join(t.TempDir(), "system_bus_socket"))
	if !errors.Is(dialErr, context.DeadlineExceeded) {
		t.Fatalf("a dial past its deadline must report context.DeadlineExceeded: %v", dialErr)
	}
	late := false
	p.clock = func() time.Time {
		if late {
			return time.Now().Add(time.Hour)
		}
		return time.Now()
	}
	native := p.sessionNative
	afterLock := 0
	p.sessionNative = func(ctx context.Context, operation string) ([]graphicalSession, error) {
		if operation == "observe" && *effects != 0 {
			// Verification's own observation and the window's first tick
			// succeed; the next tick runs past the window's deadline.
			if afterLock++; afterLock > 2 {
				late = true
				return nil, dialErr
			}
		}
		return native(ctx, operation)
	}
	result, err := p.Apply(context.Background(), plan, nil, func(context.Context) error { return nil })
	if err != nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the window's own deadline was reported as an interruption: %v", err)
	}
	if result.GetVerified() || result.GetAfter().GetSessionsLocked() || *effects != 1 || !strings.HasPrefix(result.GetEvidence(), "session_lock_state_unreported: ") {
		t.Fatalf("unreported lock misreported: verified=%v locked=%v effects=%d evidence=%q", result.GetVerified(), result.GetAfter().GetSessionsLocked(), *effects, result.GetEvidence())
	}
}
