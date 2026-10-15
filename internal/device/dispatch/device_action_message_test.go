// SPDX-License-Identifier: Apache-2.0

package dispatch

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/device/devicedb"
)

func TestActionMessageDistinguishesInFlightFromAmbiguous(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	deadline := now.Add(time.Minute)
	intent, err := proto.Marshal(&agentv1.DeviceActionIntent{Spec: &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_RefreshInventory{RefreshInventory: &agentv1.RefreshInventoryAction{}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		state    agentv1.DeviceActionState
		reported bool
		at       time.Time
		closed   bool
		want     agentv1.DeviceActionState
	}{
		{"start grant", 0, false, now, false, agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING},
		{"queued progress", agentv1.DeviceActionState_DEVICE_ACTION_STATE_QUEUED, true, now, false, agentv1.DeviceActionState_DEVICE_ACTION_STATE_QUEUED},
		{"running progress", agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING, true, now, false, agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING},
		{"just before deadline", 0, false, deadline.Add(-time.Nanosecond), false, agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING},
		{"at deadline", 0, false, deadline, false, agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN},
		{"overdue running", agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING, true, deadline.Add(time.Second), false, agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN},
		{"reported ambiguity", agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN, true, now, false, agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN},
		{"closed possible effect", 0, false, now, true, agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN},
		{"signed success after deadline", agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, true, deadline, true, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED},
		{"signed failure after deadline", agentv1.DeviceActionState_DEVICE_ACTION_STATE_FAILED, true, deadline, true, agentv1.DeviceActionState_DEVICE_ACTION_STATE_FAILED},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := devicedb.DeviceAction{ID: uuid.New(), IntentDocument: intent, IntentEnvelope: []byte("immutable intent envelope"), IssuedAt: pgtype.Timestamptz{Time: now.Add(-time.Second), Valid: true}, ExpiresAt: pgtype.Timestamptz{Time: deadline, Valid: true}, StartAuthorizedAt: pgtype.Timestamptz{Time: now, Valid: true}, OutcomeUnknown: true}
			var reported *agentv1.DeviceActionStatus
			if tc.reported {
				reported = &agentv1.DeviceActionStatus{State: tc.state, Before: &agentv1.DeviceActionObservation{Supported: true, ObservedAt: timestamppb.New(now)}, Verification: &agentv1.DeviceActionVerification{Evidence: "preserve reported progress"}}
				row.StatusDocument, err = proto.Marshal(reported)
				if err != nil {
					t.Fatal(err)
				}
			}
			if tc.closed {
				row.ClosedAt = pgtype.Timestamptz{Time: now, Valid: true}
				row.ClosedReason = "outcome_unknown"
			}
			got, err := actionMessage(row, tc.at)
			if err != nil {
				t.Fatal(err)
			}
			if got.GetStatus().GetState() != tc.want {
				t.Fatalf("state = %v, want %v", got.GetStatus().GetState(), tc.want)
			}
			if got.GetStatus().GetCompletedAt() != nil || got.GetStatus().GetFailure() == agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_INTERRUPTED {
				t.Fatal("projection invented completion or interrupted failure")
			}
			if reported != nil {
				reported.State = tc.want
				if !proto.Equal(got.GetStatus(), reported) {
					t.Fatal("projection discarded reported evidence")
				}
			}
		})
	}
}
