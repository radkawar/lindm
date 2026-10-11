package inventory

import (
	"context"
	"time"

	"lindm/internal/device/core"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/device/devicedb"
)

// patchStaleAfterSeconds bounds how old a published patch status may be and
// still count toward fleet patch compliance. Executors recompute hourly, so
// six hours tolerates missed inventories without hiding a silent device.
const PatchStaleAfterSeconds = 21600

// recordPatchStatus projects the already validated host observation's patch
// status into host_patch_status. The row is untrusted telemetry for fleet
// compliance and never native success authority. Without a status the
// generation keeps no projection.
func recordPatchStatus(ctx context.Context, q *devicedb.Queries, generation uuid.UUID, status *agentv1.PatchStatusObservation, received time.Time) error {
	if status == nil {
		return q.DeleteHostPatchStatus(ctx, generation)
	}
	return q.UpsertHostPatchStatus(ctx, PatchStatusParams(generation, status, received))
}

// patchStatusParams maps a validated observation. Counts of an unavailable
// status carry no meaning and are stored as zero, as the table requires.
func PatchStatusParams(generation uuid.UUID, status *agentv1.PatchStatusObservation, received time.Time) devicedb.UpsertHostPatchStatusParams {
	params := devicedb.UpsertHostPatchStatusParams{
		GenerationID: generation, ObservedAt: core.Timestamptz(status.GetObservedAt().AsTime()), ReceivedAt: core.Timestamptz(received),
		Available: status.GetAvailable(), Reason: status.GetReason(), Backend: int16(status.GetBackend()),
		MetadataRefreshedAt:  optionalTimestamptz(status.GetMetadataRefreshedAt()),
		LastSuccessfulUpdate: optionalTimestamptz(status.GetLastSuccessfulUpdate()),
		RebootScheduledFor:   optionalTimestamptz(status.GetRebootScheduledFor()),
		PolicyInstalled:      status.GetPolicyInstalled(),
	}
	if status.GetAvailable() {
		params.PendingSecurityUpdates = int32(status.GetPendingSecurityUpdates())
		params.PendingUpdates = int32(status.GetPendingUpdates())
		params.DeferredUpdates = int32(status.GetDeferredUpdates())
		params.RebootRequired = status.GetRebootRequired()
	}
	if run := status.GetLastRun(); run != nil {
		params.LastRunFinishedAt = core.Timestamptz(run.GetFinishedAt().AsTime())
		params.LastRunResult = int16(run.GetResult())
	}
	return params
}

func optionalTimestamptz(ts *timestamppb.Timestamp) pgtype.Timestamptz {
	if ts == nil {
		return pgtype.Timestamptz{}
	}
	return core.Timestamptz(ts.AsTime())
}

func FleetPatchSummary(row devicedb.FleetSummaryPatchRow) *adminv1.FleetPatchSummary {
	return &adminv1.FleetPatchSummary{
		PatchedDevices: uint64(row.PatchedDevices), SecurityPendingDevices: uint64(row.SecurityPendingDevices),
		RebootRequiredDevices: uint64(row.RebootRequiredDevices), StaleDevices: uint64(row.StaleDevices),
		UnknownDevices: uint64(row.UnknownDevices), PendingSecurityUpdates: uint64(row.PendingSecurityUpdates),
		FailedRunDevices: uint64(row.FailedRunDevices), StaleAfterSeconds: PatchStaleAfterSeconds,
	}
}
