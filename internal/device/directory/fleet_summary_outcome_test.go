// SPDX-License-Identifier: Apache-2.0

package directory

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/device/devicedb"
)

func TestRecentActionOutcome(t *testing.T) {
	at := pgtype.Timestamptz{Time: time.Unix(1_700_000_000, 0), Valid: true}
	future := pgtype.Timestamptz{Time: at.Time.Add(time.Minute), Valid: true}
	device := func(state agentv1.DeviceActionState) []byte {
		document, err := proto.Marshal(&agentv1.DeviceActionStatus{State: state})
		if err != nil {
			t.Fatal(err)
		}
		return document
	}
	resource := func(state agentv1.ResourceExecutionState) []byte {
		document, err := proto.Marshal(&agentv1.ResourceExecutionStatus{State: state})
		if err != nil {
			t.Fatal(err)
		}
		return document
	}
	tests := []struct {
		name string
		row  devicedb.FleetSummaryRecentActionsRow
		want adminv1.FleetActionOutcome
	}{
		{"device succeeded", devicedb.FleetSummaryRecentActionsRow{Kind: "device", StartAuthorizedAt: at, ClosedAt: at, ClosedReason: "result", StatusDocument: device(agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED)}, adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_SUCCEEDED},
		{"device failed", devicedb.FleetSummaryRecentActionsRow{Kind: "device", StartAuthorizedAt: at, ClosedAt: at, ClosedReason: "result", StatusDocument: device(agentv1.DeviceActionState_DEVICE_ACTION_STATE_FAILED)}, adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_FAILED},
		{"device reported unknown", devicedb.FleetSummaryRecentActionsRow{Kind: "device", StartAuthorizedAt: at, StatusDocument: device(agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN)}, adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_UNKNOWN},
		{"device reported expired", devicedb.FleetSummaryRecentActionsRow{Kind: "device", ClosedAt: at, ClosedReason: "result", StatusDocument: device(agentv1.DeviceActionState_DEVICE_ACTION_STATE_EXPIRED)}, adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_EXPIRED},
		{"device expired unstarted", devicedb.FleetSummaryRecentActionsRow{Kind: "device", ClosedAt: at, ClosedReason: "expired_unstarted"}, adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_EXPIRED},
		{"device closed unknown flag", devicedb.FleetSummaryRecentActionsRow{Kind: "device", ClosedAt: at, ClosedReason: "outcome_unknown", OutcomeUnknown: true}, adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_UNKNOWN},
		{"closed after start without report is never success", devicedb.FleetSummaryRecentActionsRow{Kind: "device", StartAuthorizedAt: at, ClosedAt: at, ClosedReason: "result"}, adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_UNKNOWN},
		{"device cancelled before start", devicedb.FleetSummaryRecentActionsRow{Kind: "device", ClosedAt: at, ClosedReason: "cancelled"}, adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_CANCELLED},
		{"device open unknown flag", devicedb.FleetSummaryRecentActionsRow{Kind: "device", StartAuthorizedAt: at, OutcomeUnknown: true}, adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_UNKNOWN},
		{"device start grant inside deadline", devicedb.FleetSummaryRecentActionsRow{Kind: "device", StartAuthorizedAt: at, ExpiresAt: future, OutcomeUnknown: true}, adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_RUNNING},
		{"device queued inside deadline", devicedb.FleetSummaryRecentActionsRow{Kind: "device", StartAuthorizedAt: at, ExpiresAt: future, OutcomeUnknown: true, StatusDocument: device(agentv1.DeviceActionState_DEVICE_ACTION_STATE_QUEUED)}, adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_RUNNING},
		{"device running inside deadline", devicedb.FleetSummaryRecentActionsRow{Kind: "device", StartAuthorizedAt: at, ExpiresAt: future, OutcomeUnknown: true, StatusDocument: device(agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING)}, adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_RUNNING},
		{"device deadline without result", devicedb.FleetSummaryRecentActionsRow{Kind: "device", StartAuthorizedAt: at, ExpiresAt: at, OutcomeUnknown: true}, adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_UNKNOWN},
		{"device deadline with running progress", devicedb.FleetSummaryRecentActionsRow{Kind: "device", StartAuthorizedAt: at, ExpiresAt: at, OutcomeUnknown: true, StatusDocument: device(agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING)}, adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_UNKNOWN},
		{"device reported unknown inside deadline", devicedb.FleetSummaryRecentActionsRow{Kind: "device", StartAuthorizedAt: at, ExpiresAt: future, OutcomeUnknown: true, StatusDocument: device(agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN)}, adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_UNKNOWN},
		{"device running", devicedb.FleetSummaryRecentActionsRow{Kind: "device", StartAuthorizedAt: at, StatusDocument: device(agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING)}, adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_RUNNING},
		{"device waiting", devicedb.FleetSummaryRecentActionsRow{Kind: "device"}, adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_WAITING},
		{"resource succeeded", devicedb.FleetSummaryRecentActionsRow{Kind: "resource", StartAuthorizedAt: at, ClosedAt: at, ClosedReason: "result", StatusDocument: resource(agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED)}, adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_SUCCEEDED},
		{"resource failed", devicedb.FleetSummaryRecentActionsRow{Kind: "resource", StartAuthorizedAt: at, ClosedAt: at, ClosedReason: "result", StatusDocument: resource(agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED)}, adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_FAILED},
		{"resource superseded", devicedb.FleetSummaryRecentActionsRow{Kind: "resource", ClosedAt: at, ClosedReason: "result", StatusDocument: resource(agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUPERSEDED)}, adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_CANCELLED},
		{"resource running despite open-start flag", devicedb.FleetSummaryRecentActionsRow{Kind: "resource", StartAuthorizedAt: at, OutcomeUnknown: true, StatusDocument: resource(agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING)}, adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_RUNNING},
		{"resource cancelled before start", devicedb.FleetSummaryRecentActionsRow{Kind: "resource", ClosedAt: at, ClosedReason: "assignment_removed_never_prepared"}, adminv1.FleetActionOutcome_FLEET_ACTION_OUTCOME_CANCELLED},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := recentActionOutcome(test.row, at.Time)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("recentActionOutcome() = %v, want %v", got, test.want)
			}
		})
	}
	if _, err := recentActionOutcome(devicedb.FleetSummaryRecentActionsRow{Kind: "device", StatusDocument: []byte{0xff}}, at.Time); err == nil {
		t.Fatal("corrupt status document was accepted")
	}
}

func TestFleetPopulationCacheRejectsInvalidRPMRoot(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	population := &adminv1.GetFleetSummaryResponse{ObservedAt: timestamppb.New(now)}
	if !fleetPopulationCurrent(population, now, true) {
		t.Fatal("valid current cache unexpectedly rejected")
	}
	if fleetPopulationCurrent(population, now, false) {
		t.Fatal("cached trusted fleet survived RPM root invalidation")
	}
	if fleetPopulationCurrent(population, now.Add(FleetSummaryMaxAge+time.Second), true) {
		t.Fatal("expired cache unexpectedly trusted")
	}
}
