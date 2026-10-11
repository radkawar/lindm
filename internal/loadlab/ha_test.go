package loadlab

import (
	"errors"
	"testing"

	"connectrpc.com/connect"
)

// The HA oracle must count a second execution of any action as a duplicate
// effect and never let one request map to two server actions.
func TestHALedgerDetectsDuplicateEffects(t *testing.T) {
	l := newHALedger()
	if err := l.accept("request", "device", "action"); err != nil {
		t.Fatal(err)
	}
	if l.idle("device") {
		t.Fatal("device with an unfinished accepted restart is idle")
	}
	if err := l.accept("request", "device", "other-action"); err == nil {
		t.Fatal("one request accepted as two actions")
	}
	if err := l.executeRestart("device", "action"); err != nil {
		t.Fatal(err)
	}
	if !l.restartSeen("action") {
		t.Fatal("executed restart can be prepared again")
	}
	if err := l.executeRestart("device", "action"); !errors.Is(err, errProtocolViolation) || l.duplicates != 1 {
		t.Fatalf("second restart execution not a violation: %v", err)
	}
	l.finishRestart("action", true, "boot")
	if !l.idle("device") {
		t.Fatal("finished restart keeps device busy")
	}
	if err := l.serviceEffect("device", "service", 1); err != nil {
		t.Fatal(err)
	}
	if err := l.serviceEffect("device", "service", 1); !errors.Is(err, errProtocolViolation) || l.serviceDuplicates != 1 {
		t.Fatalf("second service execution not a violation: %v", err)
	}
}

func TestHAAmbiguousOutcomesAreRetriedWithTheSameRequest(t *testing.T) {
	for code, want := range map[connect.Code]bool{
		connect.CodeUnavailable: true, connect.CodeDeadlineExceeded: true, connect.CodeInternal: true, connect.CodeUnknown: true, connect.CodeAborted: true,
		connect.CodeFailedPrecondition: false, connect.CodePermissionDenied: false, connect.CodeAlreadyExists: false, connect.CodeInvalidArgument: false,
	} {
		if got := ambiguous(connect.NewError(code, errors.New("fixture"))); got != want {
			t.Errorf("%s ambiguous = %t", code, got)
		}
	}
}
