package device

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/device/devicedb"
)

// A device-attested native-busy refusal (another package frontend, such as a
// release upgrade, held dpkg) is a hold: retried one reconcile interval after
// the server recorded it, never immediately and never for other blocks.
func TestNativeBusyHoldRetriesAfterInterval(t *testing.T) {
	ref := &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE, CanonicalKey: "deb/example/amd64"}
	document, err := proto.Marshal(&policyv1.ProfileResource{ResourceId: "5b0c6f3e-2d8a-4f0b-9b1e-7a3c1d2e4f01", Desired: &resourcev1.ResourceDesiredState{Ref: ref}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	interval := 5 * time.Minute
	row := func(reason string, observed time.Time) []devicedb.ResourceAssignmentResource {
		return []devicedb.ResourceAssignmentResource{{ResourceKind: int16(ref.GetKind()), CanonicalKey: ref.GetCanonicalKey(), Document: document, Disposition: 5, Reason: reason, ObservedAt: pgtype.Timestamptz{Time: observed, Valid: true}}}
	}
	for _, tc := range []struct {
		name     string
		rows     []devicedb.ResourceAssignmentResource
		eligible bool
	}{
		{"held within interval", row(resourceReasonNativeBusy, now.Add(-interval+time.Second)), false},
		{"held for interval", row(resourceReasonNativeBusy, now.Add(-interval)), true},
		{"other block", row("admission_precondition", now.Add(-time.Hour)), false},
		{"hold without observation", []devicedb.ResourceAssignmentResource{{ResourceKind: int16(ref.GetKind()), CanonicalKey: ref.GetCanonicalKey(), Document: document, Disposition: 5, Reason: resourceReasonNativeBusy}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate, err := eligibleResource(tc.rows, now, interval)
			if err != nil {
				t.Fatal(err)
			}
			if (candidate != nil) != tc.eligible {
				t.Fatalf("eligible = %t, want %t", candidate != nil, tc.eligible)
			}
		})
	}
}

// A native-busy release refusal names its reason instead of a generic failure.
func TestNativeBusyReleaseReason(t *testing.T) {
	state, reason := releaseResultState(&agentv1.ResourceExecutionStatus{State: agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED, Failure: agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NATIVE_BUSY})
	if state != "release_conflict" || reason != resourceReasonNativeBusy {
		t.Fatalf("release busy = %s/%s", state, reason)
	}
}
