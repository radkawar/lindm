//go:build linux

package transport

import (
	"testing"

	"connectrpc.com/connect"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/rpcreason"
)

// Server admission backpressure is a deferral the agent retries on its normal
// cadence, not a local failure.
func TestServerAdmissionRejectionIsDeferred(t *testing.T) {
	for _, reason := range []string{"admission_rejected", "rate_limited"} {
		if got := outcome(rpcreason.Error(connect.CodeResourceExhausted, reason)); got != agentv1.TransportOutcome_TRANSPORT_OUTCOME_SERVER_ADMISSION_DEFERRED {
			t.Errorf("%s: outcome %v", reason, got)
		}
	}
	if continueAfter(rpcreason.Error(connect.CodeResourceExhausted, "admission_rejected")) {
		t.Error("flush kept offering uploads to a saturated server")
	}
	if !continueAfter(rpcreason.Error(connect.CodeResourceExhausted, "rate_limited")) {
		t.Error("per-device deferral stopped unrelated evidence")
	}
}
