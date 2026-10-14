// SPDX-License-Identifier: Apache-2.0

package device

import (
	"testing"
	"time"

	"lindm/internal/device/inventory"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/device/devicedb"
)

func TestPatchStatusParamsMapsAvailableStatus(t *testing.T) {
	generation := uuid.New()
	observed := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	received := observed.Add(time.Minute)
	status := &agentv1.PatchStatusObservation{
		ObservedAt: timestamppb.New(observed), Available: true,
		Backend:                resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF4_AUTOMATIC,
		PendingSecurityUpdates: 1, PendingUpdates: 4, DeferredUpdates: 2, RebootRequired: true,
		MetadataRefreshedAt: timestamppb.New(observed.Add(-time.Hour)), PolicyInstalled: true,
		LastRun: &agentv1.PatchRunSummary{FinishedAt: timestamppb.New(observed.Add(-time.Minute)), Result: agentv1.PatchRunResult_PATCH_RUN_RESULT_DEFERRED},
	}
	got := inventory.PatchStatusParams(generation, status, received)
	if got.GenerationID != generation || !got.Available || got.Reason != "" || got.Backend != 3 ||
		got.PendingSecurityUpdates != 1 || got.PendingUpdates != 4 || got.DeferredUpdates != 2 || !got.RebootRequired ||
		!got.ObservedAt.Time.Equal(observed) || !got.ReceivedAt.Time.Equal(received) ||
		!got.MetadataRefreshedAt.Valid || !got.MetadataRefreshedAt.Time.Equal(observed.Add(-time.Hour)) ||
		got.LastSuccessfulUpdate.Valid || got.RebootScheduledFor.Valid || !got.PolicyInstalled ||
		got.LastRunResult != 4 || !got.LastRunFinishedAt.Time.Equal(observed.Add(-time.Minute)) {
		t.Fatalf("mapped status = %+v", got)
	}
}

func TestPatchStatusParamsDropsUnavailableCounts(t *testing.T) {
	status := &agentv1.PatchStatusObservation{ObservedAt: timestamppb.Now(), Reason: "patch_status_invalid", PendingUpdates: 3, PendingSecurityUpdates: 1, DeferredUpdates: 1, RebootRequired: true}
	got := inventory.PatchStatusParams(uuid.New(), status, time.Now())
	if got.Available || got.Reason != "patch_status_invalid" || got.PendingUpdates != 0 || got.PendingSecurityUpdates != 0 ||
		got.DeferredUpdates != 0 || got.RebootRequired || got.LastRunResult != 0 || got.LastRunFinishedAt.Valid {
		t.Fatalf("unavailable status kept meaningless counts: %+v", got)
	}
}

func TestFleetPatchSummaryReportsThreshold(t *testing.T) {
	got := inventory.FleetPatchSummary(devicedb.FleetSummaryPatchRow{PatchedDevices: 1, SecurityPendingDevices: 2, RebootRequiredDevices: 3, StaleDevices: 4, UnknownDevices: 5, PendingSecurityUpdates: 6, FailedRunDevices: 7})
	want := &adminv1.FleetPatchSummary{PatchedDevices: 1, SecurityPendingDevices: 2, RebootRequiredDevices: 3, StaleDevices: 4, UnknownDevices: 5, PendingSecurityUpdates: 6, FailedRunDevices: 7, StaleAfterSeconds: 21600}
	if !proto.Equal(got, want) {
		t.Fatalf("summary = %v, want %v", got, want)
	}
}
