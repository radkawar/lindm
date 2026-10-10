//go:build integration

package device

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/trust"
)

func (f *deviceActionFixture) observeRecoveryReadiness(t *testing.T, observation *agentv1.RecoveryReadinessObservation) {
	t.Helper()
	ageInventoryAdmissions(t, f)
	host, err := devicedb.New(f.svc.pool).GetHostObservation(t.Context(), f.principal.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	details := new(inventoryv1.NativeDetails)
	if err := proto.Unmarshal(host.Details, details); err != nil {
		t.Fatal(err)
	}
	details.RecoveryReadiness = observation
	report := hostObservation(f.generation, uint64(host.Sequence+1), "recovery-readiness-fixture")
	report.Observation.Details = details
	if observation != nil {
		report.Observation.BootId.Value = observation.GetBootId()
	}
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(report)); err != nil {
		t.Fatal(err)
	}
}

func recoveryAdmissionReason(t *testing.T, err error, reason string) {
	t.Helper()
	var failure *connect.Error
	if !errors.As(err, &failure) || failure.Code() != connect.CodeFailedPrecondition || failure.Meta().Get("Lindm-Reason") != reason {
		t.Fatalf("wanted readiness failure %s, got %v", reason, err)
	}
}

func TestRecoveryReadinessBlocksApprovalAndRechecksCreation(t *testing.T) {
	f := newDeviceActionFixture(t)
	client, digest := recoveryArtifactFixture(t, bytes.Repeat([]byte{0x5a}, 8193))
	f.svc.recoveryArtifacts = client
	target := &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, Wwn: "readiness-test-wwn", Serial: "readiness-test-serial", SizeBytes: 1 << 30}
	f.observeStorageTargets(t, target)
	media, err := trust.DeviceActionDigest(target)
	if err != nil {
		t.Fatal(err)
	}
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Sanitize{Sanitize: &agentv1.SanitizeAction{Target: target, Method: agentv1.SanitizeMethod_SANITIZE_METHOD_OVERWRITE, Recovery: &agentv1.RecoveryBootSpec{ImageSha256: digest, MediaSha256: media[:], BootMode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI}}}}
	for _, tc := range []struct {
		name, reason string
		observation  func() *agentv1.RecoveryReadinessObservation
	}{
		{"missing", "device_action_recovery_readiness_missing", func() *agentv1.RecoveryReadinessObservation { return nil }},
		{"stale", "device_action_recovery_readiness_stale", func() *agentv1.RecoveryReadinessObservation {
			return recoveryObservationFixture(time.Now().Add(-6 * time.Minute))
		}},
		{"unsupported", "device_action_recovery_readiness_unsupported", func() *agentv1.RecoveryReadinessObservation {
			o := recoveryObservationFixture(time.Now())
			o.Available = false
			o.Reason = "secure_boot_disabled"
			o.SecureBoot = false
			return o
		}},
		{"forged_smaller_local_size", "device_action_esp_insufficient", func() *agentv1.RecoveryReadinessObservation {
			o := recoveryObservationFixture(time.Now())
			o.ConfiguredImageSha256 = digest
			o.ConfiguredImageSize = proto.Uint64(1)
			return o
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.observeRecoveryReadiness(t, tc.observation())
			request := f.request(proto.CloneOf(spec))
			_, err := f.svc.CreateApproval(f.ownerCtx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_CreateDeviceAction{CreateDeviceAction: request}}))
			recoveryAdmissionReason(t, err, tc.reason)
			var count int
			if err := f.svc.pool.QueryRow(t.Context(), "SELECT count(*) FROM approval_requests WHERE mutation_id=$1", request.GetRequestId()).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatal("known impossible recovery was offered to human reviewers")
			}
		})
	}
	observation := recoveryObservationFixture(time.Now())
	observation.FreeBytes = 12288
	f.observeRecoveryReadiness(t, observation)
	unknown := sha256.Sum256([]byte("unregistered artifact"))
	unknownRequest := f.request(proto.CloneOf(spec))
	unknownRequest.Spec.GetSanitize().Recovery.ImageSha256 = unknown[:]
	_, err = f.svc.CreateApproval(f.ownerCtx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_CreateDeviceAction{CreateDeviceAction: unknownRequest}}))
	recoveryAdmissionReason(t, err, "device_action_recovery_artifact_unavailable")
	readiness, err := f.svc.ListDeviceStorageTargets(f.ownerCtx, connect.NewRequest(&adminv1.ListDeviceStorageTargetsRequest{DeviceId: f.deviceID, ActionKind: "sanitize", RecoveryImageSha256: digest}))
	if err != nil || !readiness.Msg.GetRecoveryReadiness().GetReady() || readiness.Msg.GetRecoveryReadiness().GetImageSize() != 8193 || readiness.Msg.GetRecoveryReadiness().GetNeededBytes() != 12288 {
		t.Fatalf("admin readiness projection: %v %v", readiness, err)
	}
	request := f.request(spec)
	f.approval(t, request)
	observation.ObservedAt = timestamppb.New(time.Now().Add(-6 * time.Minute))
	f.observeRecoveryReadiness(t, observation)
	_, err = f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(request))
	recoveryAdmissionReason(t, err, "device_action_recovery_readiness_stale")
	observation.ObservedAt = timestamppb.Now()
	observation.FreeBytes = 8192
	f.observeRecoveryReadiness(t, observation)
	_, err = f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(request))
	recoveryAdmissionReason(t, err, "device_action_esp_insufficient")
	observation.ObservedAt = timestamppb.Now()
	observation.FreeBytes = 12288
	f.observeRecoveryReadiness(t, observation)
	f.create(t, request)
}
