//go:build integration

package device

import (
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/device/devicedb"
)

// Device encryption status reports the bound keyslot's identical systemd-tpm2
// references against the observed release's requirement: a legacy one-token
// bind on Ubuntu 24.04 reads 1 of 4 until a TPM2 bind completes it.
func TestDeviceEncryptionReportsTPM2TokenReferences(t *testing.T) {
	f := newDeviceActionFixture(t)
	target, virtio := fixtureVirtioStorage()
	details := nativeDetailsFixture()
	details.Storage, details.Tpm = virtio.Storage, virtio.Tpm
	ageInventoryAdmissions(t, f)
	host, err := devicedb.New(f.svc.Pool).GetHostObservation(t.Context(), f.principal.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	report := hostObservation(f.generation, uint64(host.Sequence+1), "noble-tpm")
	report.Observation.OsId = observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, "ubuntu")
	report.Observation.OsVersion = observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, "24.04")
	report.Observation.Details = details
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(report)); err != nil {
		t.Fatal(err)
	}
	status := func() *adminv1.GetDeviceEncryptionResponse {
		t.Helper()
		response, err := f.svc.GetDeviceEncryption(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceEncryptionRequest{DeviceId: f.deviceID}))
		if err != nil {
			t.Fatal(err)
		}
		return response.Msg
	}
	if got := status(); got.GetTpm2TokenReferences() != 0 || got.GetTpm2TokenReferencesRequired() != 0 {
		t.Fatalf("unbound device reported TPM references: %v", got)
	}
	bind := func(revision uint64, references int) {
		t.Helper()
		f.create(t, f.request(&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Tpm2Bind{Tpm2Bind: &agentv1.TPM2BindAction{Target: target, Pcrs: []uint32{7}}}}))
		work := f.work(t)
		start, _ := f.startRequest(t, work)
		if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
			t.Fatal(err)
		}
		tokens := []*agentv1.LUKSTokenObservation{{TokenId: 0, Type: "lindm-recovery", Keyslots: []uint32{2}}}
		for id := range references {
			tokens = append(tokens, &agentv1.LUKSTokenObservation{TokenId: uint32(id + 1), Type: "systemd-tpm2", Keyslots: []uint32{1}})
		}
		verification := &agentv1.DeviceActionVerification{Verified: true, After: &agentv1.DeviceActionObservation{ObservedAt: timestamppb.Now(), Supported: true, Encrypted: true, Tpm2Bound: true, Target: target, OccupiedKeyslots: []uint32{0, 1, 2}, LuksTokens: tokens}}
		if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(f.result(t, work, revision, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, verification))); err != nil {
			t.Fatal(err)
		}
	}
	bind(1, 1)
	if got := status(); got.GetTpm2TokenReferences() != 1 || got.GetTpm2TokenReferencesRequired() != 4 {
		t.Fatalf("legacy bind status = %d of %d, want 1 of 4", got.GetTpm2TokenReferences(), got.GetTpm2TokenReferencesRequired())
	}
	bind(1, 4)
	if got := status(); got.GetTpm2TokenReferences() != 4 || got.GetTpm2TokenReferencesRequired() != 4 {
		t.Fatalf("repaired bind status = %d of %d, want 4 of 4", got.GetTpm2TokenReferences(), got.GetTpm2TokenReferencesRequired())
	}
}
