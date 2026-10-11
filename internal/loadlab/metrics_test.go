package loadlab

import (
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"

	"lindm/internal/rpcreason"
)

func TestMeasurementsPreserveErrorsAndBoundLatency(t *testing.T) {
	m := &measurements{}
	for i := 1; i <= 100; i++ {
		m.observe("/device/GetSyncState", time.Duration(i)*time.Millisecond, nil)
	}
	result := m.snapshot(true)["GetSyncState"]
	if result.P50Milliseconds != 50 || result.P95Milliseconds != 95 || result.P99Milliseconds != 99 || result.Calls != 100 {
		t.Fatalf("wrong percentiles: %+v", result)
	}
	if len(m.snapshot(false)) != 0 {
		t.Fatal("stage reset retained earlier measurements")
	}
	m.observe("/device/GetResourceWork", time.Hour, connect.NewError(connect.CodeUnavailable, errors.New("unavailable")))
	m.observe("/device/GetResourceWork", time.Millisecond, connect.NewError(connect.CodePermissionDenied, errors.New("denied")))
	result = m.snapshot(false)["GetResourceWork"]
	if result.Errors != 2 || result.NonRetryableErrors != 1 || result.P99Milliseconds != 30001 || result.MaxMilliseconds != 3600000 {
		t.Fatalf("unbounded or lost error measurement: %+v", result)
	}
	if !breached(m.snapshot(false)) {
		t.Fatal("SLO breach was hidden")
	}
}
func TestSLOBreachBoundary(t *testing.T) {
	for _, test := range []struct {
		latency              int
		errors, nonRetryable uint64
		want                 bool
	}{{999, 0, 0, false}, {1000, 0, 0, true}, {20, 1, 0, false}, {20, 0, 1, true}} {
		got := breached(map[string]RPCResult{"GetSyncState": {P99Milliseconds: test.latency, Errors: test.errors, NonRetryableErrors: test.nonRetryable}})
		if got != test.want {
			t.Errorf("breached(%+v)=%t", test, got)
		}
	}
}

func TestSnapshotCompletionBoundary(t *testing.T) {
	for _, test := range []struct {
		completed, attempted, devices uint64
		want                          bool
	}{
		{9900, 10000, 10000, true}, {9899, 10000, 10000, false},
		{19800, 20000, 10000, true}, {19799, 20000, 10000, false},
		{9900, 9900, 10000, true}, {9800, 9800, 10000, false},
	} {
		if got := snapshotsComplete(test.completed, test.attempted, test.devices); got != test.want {
			t.Errorf("snapshotsComplete(%+v)=%t", test, got)
		}
	}
}

func TestFailureReasonsSurviveStageSnapshot(t *testing.T) {
	m := &measurements{}
	failure := connect.NewError(connect.CodeFailedPrecondition, errors.New("not persisted"))
	rpcreason.Set(failure, "execution_signing_rejected")
	m.observe("/device/GetResourceWork", time.Millisecond, failure)
	first := m.snapshot(false)
	m.observe("/device/GetResourceWork", time.Millisecond, failure)
	if first["GetResourceWork"].Reasons["execution_signing_rejected"] != 1 {
		t.Fatal("later traffic mutated retained evidence")
	}
	if m.snapshot(true)["GetResourceWork"].Reasons["execution_signing_rejected"] != 2 {
		t.Fatal("diagnostic reason was lost")
	}
}
