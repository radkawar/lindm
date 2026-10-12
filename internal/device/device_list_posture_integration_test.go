//go:build integration

package device

import (
	"crypto/sha256"
	"testing"
	"time"

	"lindm/internal/device/inventory"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/identity"
)

func listedPosture(t *testing.T, f *enrolledFixture) *adminv1.Device {
	t.Helper()
	response, err := f.svc.ListDevices(f.ownerCtx, connect.NewRequest(&adminv1.ListDevicesRequest{PageSize: 200}))
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range response.Msg.GetDevices() {
		if device.GetId() == f.deviceID {
			return device
		}
	}
	t.Fatalf("device %s missing from the list", f.deviceID)
	return nil
}

func postureReport(t *testing.T, f *enrolledFixture, sequence uint64, storage *inventoryv1.StorageDetails, patch *agentv1.PatchStatusObservation) {
	t.Helper()
	report := hostObservation(f.generation, sequence, "posture")
	report.Observation.Details = nativeDetailsFixture()
	report.Observation.Details.Storage, report.Observation.Details.PatchStatus = storage, patch
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(report)); err != nil {
		t.Fatal(err)
	}
}

func TestListDevicesPostureNeverFabricatesUnreportedState(t *testing.T) {
	f := newEnrolled(t, 0)
	if device := listedPosture(t, f); device.GetRootEncryption() != adminv1.DeviceRootEncryption_DEVICE_ROOT_ENCRYPTION_UNKNOWN || device.GetUpdates() != nil || device.GetFindings() != nil {
		t.Fatalf("never-reported device acquired posture: %v", device)
	}

	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	_, details := fixtureVirtioStorage()
	mapping := details.GetStorage().GetDevices()[2]
	mapping.Mountpoint = observed(success, "/")
	// patch_status.availability: an available status needs backend, boot and metadata time.
	patch := &agentv1.PatchStatusObservation{
		ObservedAt: timestamppb.New(f.now), BootId: uuid.NewString(), Available: true,
		Backend:                resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES,
		PendingSecurityUpdates: 2, PendingUpdates: 7, RebootRequired: true, PolicyInstalled: true,
		MetadataRefreshedAt: timestamppb.New(f.now.Add(-time.Hour)),
	}
	postureReport(t, f, 1, details.GetStorage(), patch)
	device := listedPosture(t, f)
	wantUpdates := &adminv1.DeviceUpdateStatus{PendingUpdates: 7, PendingSecurityUpdates: 2, RebootRequired: true, ReceivedAt: timestamppb.New(f.now)}
	if device.GetRootEncryption() != adminv1.DeviceRootEncryption_DEVICE_ROOT_ENCRYPTION_ENCRYPTED || !proto.Equal(device.GetUpdates(), wantUpdates) {
		t.Fatalf("reported encrypted root and pending updates were not projected: %v", device)
	}
	// Freshness never trusts the device clock beyond the server receipt (stale after six hours).
	fleetSummaryExec(t, f, "UPDATE host_patch_status SET observed_at=CURRENT_TIMESTAMP+interval '1 year', received_at=CURRENT_TIMESTAMP-interval '7 hours' WHERE generation_id=$1", f.generation)
	if updates := listedPosture(t, f).GetUpdates(); updates == nil || !updates.GetStale() || updates.GetPendingUpdates() != 7 {
		t.Fatalf("old update status was not marked stale: %v", updates)
	}

	// An explicit unencrypted root is NOT_ENCRYPTED; an unavailable update backend is unknown.
	f.now = f.now.Add(inventory.SnapshotAttemptInterval)
	mapping.Encryption = observed(success, "none")
	mapping.Type = observed(success, "part")
	details.Storage.Devices = []*inventoryv1.BlockDevice{details.GetStorage().GetDevices()[0], mapping}
	mapping.Parent = observed(success, details.GetStorage().GetDevices()[0].GetName())
	unavailable := &agentv1.PatchStatusObservation{ObservedAt: timestamppb.New(f.now), BootId: patch.GetBootId(), Reason: "executor_unavailable"}
	postureReport(t, f, 2, details.GetStorage(), unavailable)
	if device := listedPosture(t, f); device.GetRootEncryption() != adminv1.DeviceRootEncryption_DEVICE_ROOT_ENCRYPTION_NOT_ENCRYPTED || device.GetUpdates() != nil {
		t.Fatalf("unencrypted root or unavailable updates misreported: %v", device)
	}

	// Failed storage collection is unknown, never "not encrypted".
	f.now = f.now.Add(inventory.SnapshotAttemptInterval)
	postureReport(t, f, 3, &inventoryv1.StorageDetails{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE}, nil)
	if device := listedPosture(t, f); device.GetRootEncryption() != adminv1.DeviceRootEncryption_DEVICE_ROOT_ENCRYPTION_UNKNOWN || device.GetUpdates() != nil {
		t.Fatalf("missing storage evidence became a classification: %v", device)
	}
}

func TestListDevicesFindingsMatchFreshEvaluationMinusExceptions(t *testing.T) {
	f := newEnrolled(t, 0)
	feedRevision, setID := uuid.NewString(), uuid.NewString()
	fleetSummaryExec(t, f, `INSERT INTO advisory_feeds(id,distro,release,source_url,config_bytes,revision,expires_at,checked_at)
VALUES('posture-feed','ubuntu','24.04','https://example.test/feed','',$1,CURRENT_TIMESTAMP+interval '1 day',CURRENT_TIMESTAMP)`, feedRevision)
	snapshot := f.publishPackages(t, 1, "posture-package")
	fleetSummaryExec(t, f, "UPDATE devices SET state='active',host_received_at=CURRENT_TIMESTAMP WHERE id=$1", f.deviceID)
	fleetSummaryExec(t, f, `INSERT INTO advisory_evaluations(device_id,id,snapshot_id,feed_id,feed_revision,evaluated_at,inventory_at,host_received_at,expires_at,state,reason,finding_digest)
SELECT id,$2,$3,'posture-feed',$4,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,host_received_at,CURRENT_TIMESTAMP+interval '1 day','evaluated','',decode(repeat('00',32),'hex') FROM devices WHERE id=$1`,
		f.deviceID, uuid.NewString(), snapshot, feedRevision)
	severities := []string{"critical", "high", "high", "medium", "unrated"}
	packageDigest := sha256.Sum256([]byte(setID))
	fleetSummaryExec(t, f, `INSERT INTO advisory_finding_sets(id,feed_id,feed_revision,package_digest,state,reason,finding_digest,finding_count,critical_count,high_count,medium_count,low_count,other_count)
VALUES($1,'posture-feed',$2,$3,'evaluated','',decode(repeat('11',32),'hex'),5,1,2,1,0,1)`, setID, feedRevision, packageDigest[:])
	keys := make([]string, len(severities))
	for i, severity := range severities {
		keys[i] = uuid.NewString()
		fleetSummaryExec(t, f, `INSERT INTO advisory_set_findings(set_id,finding_key,advisory_id,package_name,installed_version,fixed_version,architecture,severity,cves,source_url)
VALUES($1,$2,'POSTURE-1','posture-package','1','2','amd64',$3,'{}','https://example.test/feed')`, setID, keys[i], severity)
	}
	if device := listedPosture(t, f); device.GetFindings() != nil {
		t.Fatalf("evaluation without a bound finding set reported findings: %v", device.GetFindings())
	}
	fleetSummaryExec(t, f, "UPDATE advisory_evaluations SET finding_set_id=$1 WHERE device_id=$2", setID, f.deviceID)
	owner, _ := identity.PrincipalFromContext(f.ownerCtx)
	fleetSummaryExec(t, f, `INSERT INTO advisory_exceptions(finding_id,device_id,actor_id,reason,accepted_at,expires_at)
VALUES($1,$2,$3,'posture accepted risk',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+interval '1 day')`, keys[1], f.deviceID, owner.ID)
	want := &adminv1.DeviceFindingCounts{Critical: 1, High: 1, Medium: 1, Other: 1}
	if got := listedPosture(t, f).GetFindings(); !proto.Equal(got, want) {
		t.Fatalf("findings = %v, want %v (accepted exception excluded)", got, want)
	}
	fleetSummaryExec(t, f, "UPDATE advisory_exceptions SET accepted_at=CURRENT_TIMESTAMP-interval '2 hours',expires_at=CURRENT_TIMESTAMP-interval '1 hour' WHERE finding_id=$1", keys[1])
	want.High++
	if got := listedPosture(t, f).GetFindings(); !proto.Equal(got, want) {
		t.Fatalf("expired exception still excluded a finding: %v", got)
	}
	fleetSummaryExec(t, f, "UPDATE advisory_evaluations SET state='partial',reason='base_archive_only',uncovered_packages=1 WHERE device_id=$1", f.deviceID)
	if got := listedPosture(t, f).GetFindings(); got == nil || !got.GetPartial() {
		t.Fatalf("partial coverage was not disclosed: %v", got)
	}
	// Expiry is a read-time decision: an expired evaluation is not checked.
	fleetSummaryExec(t, f, "UPDATE advisory_evaluations SET expires_at=CURRENT_TIMESTAMP-interval '1 hour' WHERE device_id=$1", f.deviceID)
	if got := listedPosture(t, f).GetFindings(); got != nil {
		t.Fatalf("expired evaluation still reported findings: %v", got)
	}
}
