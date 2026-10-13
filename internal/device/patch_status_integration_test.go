//go:build integration

package device

import (
	"testing"
	"time"

	"lindm/internal/device/inventory"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/device/devicedb"
)

func patchStatusReport(t *testing.T, f *enrolledFixture, sequence uint64, status *agentv1.PatchStatusObservation) {
	t.Helper()
	report := hostObservation(f.generation, sequence, "patch-status")
	report.Observation.Details = nativeDetailsFixture()
	report.Observation.Details.PatchStatus = status
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(report)); err != nil {
		t.Fatal(err)
	}
}

func TestPatchStatusProjectionAndFleetCompliance(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newEnrolled(t, 0)
	observed := f.now.Add(-time.Minute)
	boot := uuid.NewString()
	status := &agentv1.PatchStatusObservation{
		ObservedAt: timestamppb.New(observed), BootId: boot, Available: true,
		Backend:                resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES,
		PendingSecurityUpdates: 2, PendingUpdates: 7, DeferredUpdates: 3, RebootRequired: true,
		MetadataRefreshedAt: timestamppb.New(observed.Add(-time.Hour)), LastSuccessfulUpdate: timestamppb.New(observed.Add(-48 * time.Hour)),
		RebootScheduledFor: timestamppb.New(observed.Add(time.Hour)), PolicyInstalled: true,
		LastRun: &agentv1.PatchRunSummary{
			Trigger: agentv1.PatchRunTrigger_PATCH_RUN_TRIGGER_PATCH_NOW, ActionId: uuid.NewString(),
			StartedAt: timestamppb.New(observed.Add(-20 * time.Minute)), FinishedAt: timestamppb.New(observed.Add(-10 * time.Minute)),
			Result: agentv1.PatchRunResult_PATCH_RUN_RESULT_FAILED, Selection: resourcev1.UpdateSelection_UPDATE_SELECTION_SECURITY,
			Diagnostic: &agentv1.PatchRunDiagnostic{Tool: agentv1.PatchRunTool_PATCH_RUN_TOOL_UNATTENDED_UPGRADE, Phase: agentv1.PatchRunPhase_PATCH_RUN_PHASE_INSTALL, ExitCode: 1},
		},
	}
	patchStatusReport(t, f, 1, status)
	generation := uuid.MustParse(f.generation)
	q := devicedb.New(f.conn)
	row, err := q.GetHostPatchStatus(f.ctx, generation)
	if err != nil {
		t.Fatal(err)
	}
	if !row.Available || row.Reason != "" || row.Backend != 1 || row.PendingSecurityUpdates != 2 || row.PendingUpdates != 7 ||
		row.DeferredUpdates != 3 || !row.RebootRequired || !row.PolicyInstalled || row.LastRunResult != 2 ||
		!row.LastRunFinishedAt.Time.Equal(observed.Add(-10*time.Minute)) || !row.ObservedAt.Time.Equal(observed) ||
		!row.RebootScheduledFor.Time.Equal(observed.Add(time.Hour)) || !row.ReceivedAt.Time.Equal(f.now) {
		t.Fatalf("projection lost reported status: %+v", row)
	}
	detail, err := f.svc.GetDevice(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(detail.Msg.GetHost().GetObservation().GetDetails().GetPatchStatus(), status) {
		t.Fatal("device detail changed the published patch status")
	}
	// An active device without any host observation counts as unknown.
	other := uuid.NewString()
	fleetSummaryExec(t, f, `INSERT INTO devices(id,state,enrolled_at) VALUES($1,'active',CURRENT_TIMESTAMP)`, other)
	expect := func(want *adminv1.FleetPatchSummary) {
		t.Helper()
		want.StaleAfterSeconds = inventory.PatchStaleAfterSeconds
		got := fleetSummary(t, f.svc, f.ownerCtx, 0).GetPatchCompliance()
		if !proto.Equal(got, want) {
			t.Fatalf("patch compliance = %v, want %v", got, want)
		}
	}
	expect(&adminv1.FleetPatchSummary{SecurityPendingDevices: 1, UnknownDevices: 1, PendingSecurityUpdates: 2, FailedRunDevices: 1})
	fleetSummaryExec(t, f, "UPDATE host_patch_status SET pending_security_updates=0 WHERE generation_id=$1", generation)
	expect(&adminv1.FleetPatchSummary{RebootRequiredDevices: 1, UnknownDevices: 1, FailedRunDevices: 1})
	fleetSummaryExec(t, f, "UPDATE host_patch_status SET reboot_required=false, last_run_result=1 WHERE generation_id=$1", generation)
	expect(&adminv1.FleetPatchSummary{PatchedDevices: 1, UnknownDevices: 1})
	// A future device clock never extends freshness past the server receipt.
	fleetSummaryExec(t, f, "UPDATE host_patch_status SET observed_at=CURRENT_TIMESTAMP+interval '1 year', received_at=CURRENT_TIMESTAMP-interval '7 hours' WHERE generation_id=$1", generation)
	expect(&adminv1.FleetPatchSummary{StaleDevices: 1, UnknownDevices: 1})
	// Inactive devices are outside the compliance population.
	fleetSummaryExec(t, f, "UPDATE devices SET state='recovery_hold' WHERE id=$1", other)
	expect(&adminv1.FleetPatchSummary{StaleDevices: 1})

	// Unavailable statuses keep no counts and are unknown.
	f.now = f.now.Add(inventory.SnapshotAttemptInterval)
	unavailable := &agentv1.PatchStatusObservation{ObservedAt: timestamppb.New(f.now), BootId: boot, Reason: "executor_unavailable", PendingUpdates: 3, RebootRequired: true}
	patchStatusReport(t, f, 2, unavailable)
	row, err = q.GetHostPatchStatus(f.ctx, generation)
	if err != nil {
		t.Fatal(err)
	}
	if row.Available || row.Reason != "executor_unavailable" || row.PendingUpdates != 0 || row.RebootRequired || row.LastRunResult != 0 || row.LastRunFinishedAt.Valid {
		t.Fatalf("unavailable status kept counts: %+v", row)
	}
	expect(&adminv1.FleetPatchSummary{UnknownDevices: 1})

	// Inventory without patch status removes the generation's projection.
	f.now = f.now.Add(inventory.SnapshotAttemptInterval)
	patchStatusReport(t, f, 3, nil)
	var rows int
	if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM host_patch_status WHERE generation_id=$1", generation).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("historical inventory kept patch status: rows=%d err=%v", rows, err)
	}
	expect(&adminv1.FleetPatchSummary{UnknownDevices: 1})
}

// Arch (pacman) and Tumbleweed (zypper) agents report the rolling backends;
// the projection's backend bound once refused their whole host observation.
func TestPatchStatusProjectsRollingBackends(t *testing.T) {
	parallelDeviceIntegration(t)
	for _, backend := range []resourcev1.OSUpdateBackend{resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_PACMAN, resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_ZYPPER} {
		t.Run(backend.String(), func(t *testing.T) {
			f := newEnrolled(t, 0)
			observed := f.now.Add(-time.Minute)
			patchStatusReport(t, f, 1, &agentv1.PatchStatusObservation{
				ObservedAt: timestamppb.New(observed), BootId: uuid.NewString(), Available: true,
				Backend: backend, PendingUpdates: 4, PolicyInstalled: true, MetadataRefreshedAt: timestamppb.New(observed.Add(-time.Hour)),
			})
			row, err := devicedb.New(f.conn).GetHostPatchStatus(f.ctx, uuid.MustParse(f.generation))
			if err != nil {
				t.Fatal(err)
			}
			if row.Backend != int16(backend) || row.PendingUpdates != 4 || !row.Available {
				t.Fatalf("projection lost rolling backend status: %+v", row)
			}
		})
	}
}
