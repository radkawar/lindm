//go:build integration

package device

import (
	"fmt"
	"testing"

	"lindm/internal/device/dispatch"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/device/devicedb"
)

// Publish through the real inventory RPC, not a request-derived action fallback.
func (f *deviceActionFixture) observeStorageTargets(t *testing.T, targets ...*agentv1.StorageTarget) {
	t.Helper()
	host, err := devicedb.New(f.svc.Pool).GetHostObservation(t.Context(), f.principal.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	details := new(inventoryv1.NativeDetails)
	if err := proto.Unmarshal(host.Details, details); err != nil {
		t.Fatal(err)
	}
	details.Storage = &inventoryv1.StorageDetails{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS}
	for i, target := range targets {
		details.Storage.Devices = append(details.Storage.Devices, fixtureStorageDevice(fmt.Sprintf("disk%d", i), target))
	}
	f.observeStorageDetails(t, details)
}

func (f *deviceActionFixture) observeStorageDetails(t *testing.T, details *inventoryv1.NativeDetails) {
	t.Helper()
	ageInventoryAdmissions(t, f)
	host, err := devicedb.New(f.svc.Pool).GetHostObservation(t.Context(), f.principal.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	report := hostObservation(f.generation, uint64(host.Sequence+1), "storage-selection-fixture")
	report.Observation.Details = details
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(report)); err != nil {
		t.Fatal(err)
	}
}

func (f *deviceActionFixture) storageTargets(t *testing.T, kind string) *adminv1.ListDeviceStorageTargetsResponse {
	t.Helper()
	response, err := f.svc.ListDeviceStorageTargets(f.ownerCtx, connect.NewRequest(&adminv1.ListDeviceStorageTargetsRequest{DeviceId: f.deviceID, ActionKind: kind}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg
}

func TestListDeviceStorageTargetsPublishedFreshnessAndHistoricalIdentity(t *testing.T) {
	f := newDeviceActionFixture(t)
	target := fixtureStorageTarget(uuid.NewString())
	f.observeStorageTargets(t, target)
	got := f.storageTargets(t, "crypto_erase")
	if got.GetEnrollmentGeneration() != f.generation || got.GetHostSequence() != 2 || !got.GetFresh() || got.GetReceivedAt() == nil || got.GetObservedAt() == nil || got.GetUnavailableReason() != "" || len(got.GetTargets()) != 1 || !proto.Equal(got.GetTargets()[0].GetTarget(), target) {
		t.Fatalf("published exact target/freshness missing: %v", got)
	}
	if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE host_observations SET received_at=clock_timestamp()-interval '6 minutes' WHERE generation_id=$1", f.principal.GenerationID); err != nil {
		t.Fatal(err)
	}
	got = f.storageTargets(t, "crypto_erase")
	if got.GetFresh() || got.GetUnavailableReason() != "device_action_inventory_stale" || len(got.GetTargets()) != 1 {
		t.Fatalf("stale observation hidden or advertised fresh: %v", got)
	}
	historical := nativeDetailsFixture()
	historical.Storage = fixtureStorageDetails(fixtureStorageDevice("historical", target)).Storage
	historical.Storage.Devices[0].Identity = nil
	f.observeStorageDetails(t, historical)
	got = f.storageTargets(t, "crypto_erase")
	if !got.GetFresh() || len(got.GetTargets()) != 0 || got.GetUnavailableReason() != "device_action_storage_identity_unavailable" {
		t.Fatalf("historical row invented selectable identity: %v", got)
	}
	if _, err := f.svc.Pool.Exec(t.Context(), "DELETE FROM host_observations WHERE generation_id=$1", f.principal.GenerationID); err != nil {
		t.Fatal(err)
	}
	got = f.storageTargets(t, "crypto_erase")
	if got.GetFresh() || len(got.GetTargets()) != 0 || got.GetHostSequence() != 0 || got.GetUnavailableReason() != "device_action_inventory_unavailable" {
		t.Fatalf("missing publication invented inventory: %v", got)
	}
}

func TestListDeviceStorageTargetsVirtioFallbackAndDuplicateSerial(t *testing.T) {
	f := newDeviceActionFixture(t)
	target, virtio := fixtureVirtioStorage()
	details := nativeDetailsFixture()
	details.Storage, details.Tpm = virtio.Storage, virtio.Tpm
	f.observeStorageDetails(t, details)
	for _, kind := range []string{"escrow_rotate", "tpm2_bind", "crypto_erase"} {
		got := f.storageTargets(t, kind)
		if !got.GetFresh() || got.GetUnavailableReason() != "" || len(got.GetTargets()) != 1 || !proto.Equal(got.GetTargets()[0].GetTarget(), target) {
			t.Fatalf("published exact fallback missing for %s: %v", kind, got)
		}
	}
	if got := f.storageTargets(t, "sanitize"); len(got.GetTargets()) != 0 {
		t.Fatalf("fallback weakened sanitize identity: %v", got)
	}
	duplicate := proto.CloneOf(details.Storage.Devices[0])
	duplicate.Name, duplicate.Identity.BackingDisk.Value = "vdb", "vdb"
	duplicate.Identity.GptDiskGuid.Value = uuid.NewString()
	details.Storage.Devices = append(details.Storage.Devices, duplicate)
	f.observeStorageDetails(t, details)
	got := f.storageTargets(t, "crypto_erase")
	if !got.GetFresh() || len(got.GetTargets()) != 0 || got.GetUnavailableReason() != "device_action_storage_identity_unavailable" {
		t.Fatalf("duplicate physical serial remained selectable: %v", got)
	}
}

func TestStorageActionFallbackBasisChangesRejectedAtCreateAndStart(t *testing.T) {
	for _, downgrade := range []bool{false, true} {
		t.Run(fmt.Sprintf("downgrade=%t", downgrade), func(t *testing.T) {
			f := newDeviceActionFixture(t)
			fallback, virtio := fixtureVirtioStorage()
			details := nativeDetailsFixture()
			details.Storage = virtio.Storage
			wwn := proto.CloneOf(fallback)
			wwn.IdentityBasis, wwn.Wwn = agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, "native-wwn"
			wwn.GptDiskGuid, wwn.DiskSizeBytes = "", 0
			observeBasis := func(withWWN bool) {
				for _, device := range details.Storage.Devices {
					device.Identity.Wwn = observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE, "")
					if withWWN {
						device.Identity.Wwn = observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, wwn.GetWwn())
					}
				}
				f.observeStorageDetails(t, details)
			}
			observeBasis(downgrade)
			approved, changed := fallback, wwn
			if downgrade {
				approved, changed = wwn, fallback
			}
			mismatch := f.request(storageActionSpecs(f, changed)["escrow_rotate"])
			if _, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(mismatch)); rpcReason(err) != "device_action_storage_target_mismatch" {
				t.Fatalf("create accepted a different valid basis: %v", err)
			}
			request := f.request(storageActionSpecs(f, approved)["escrow_rotate"])
			action := f.create(t, request)
			start, _ := f.startRequest(t, f.work(t))
			observeBasis(!downgrade)
			if replay := f.create(t, request); replay.GetActionId() != action.GetActionId() {
				t.Fatal("basis change replaced durable approved action")
			}
			if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); rpcReason(err) != "device_action_storage_target_mismatch" {
				t.Fatalf("start silently changed signed identity basis: %v", err)
			}
			var grant []byte
			if err := f.svc.Pool.QueryRow(t.Context(), "SELECT start_grant_envelope FROM device_actions WHERE id=$1", action.GetActionId()).Scan(&grant); err != nil || len(grant) != 0 {
				t.Fatalf("basis mismatch signed start authority: %v", err)
			}
			observeBasis(downgrade)
			if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
				t.Fatalf("restored exact basis could not recover: %v", err)
			}
		})
	}
}

func storageActionSpecs(f *deviceActionFixture, target *agentv1.StorageTarget) map[string]*agentv1.DeviceActionSpec {
	return map[string]*agentv1.DeviceActionSpec{
		"escrow_rotate": {Action: &agentv1.DeviceActionSpec_EscrowRotate{EscrowRotate: &agentv1.EscrowRotateAction{Target: target, EscrowKeyId: f.svc.Escrow.KeyID(), EscrowPublicKey: f.svc.Escrow.PublicKey()}}},
		"tpm2_bind":     {Action: &agentv1.DeviceActionSpec_Tpm2Bind{Tpm2Bind: &agentv1.TPM2BindAction{Target: target, Pcrs: []uint32{7}}}},
		"crypto_erase":  {Action: &agentv1.DeviceActionSpec_CryptoErase{CryptoErase: &agentv1.CryptoEraseAction{Target: target, Mode: agentv1.CryptoEraseMode_CRYPTO_ERASE_MODE_OFFLINE}}},
		"sanitize":      {Action: &agentv1.DeviceActionSpec_Sanitize{Sanitize: &agentv1.SanitizeAction{Target: &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, Wwn: target.GetWwn(), Serial: target.GetSerial(), SizeBytes: target.GetSizeBytes()}, Method: agentv1.SanitizeMethod_SANITIZE_METHOD_OVERWRITE}}},
	}
}

func TestStorageActionCreateRejectsUnobservedTupleEveryKind(t *testing.T) {
	f := newDeviceActionFixture(t)
	target := fixtureStorageTarget(uuid.NewString())
	for kind, spec := range storageActionSpecs(f, target) {
		t.Run(kind, func(t *testing.T) {
			observedTarget := proto.CloneOf(target)
			if kind == "sanitize" {
				observedTarget.LuksUuid = ""
			}
			observedTarget.Serial += "-replacement"
			details := nativeDetailsFixture()
			details.Storage = fixtureStorageDetails(fixtureStorageDevice("disk", observedTarget)).Storage
			details.Tpm = &inventoryv1.TpmDetails{Present: &inventoryv1.ObservedBool{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: true}, Version: observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, "2")}
			f.observeStorageDetails(t, details)
			request := f.request(spec)
			if dispatch.DestructiveDeviceAction(spec) {
				f.approval(t, request)
			}
			if _, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(request)); rpcReason(err) != "device_action_storage_target_mismatch" {
				t.Fatalf("unobserved exact tuple accepted: %v", err)
			}
			if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE host_observations SET received_at=clock_timestamp()-interval '6 minutes' WHERE generation_id=$1", f.principal.GenerationID); err != nil {
				t.Fatal(err)
			}
			if _, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(request)); rpcReason(err) != "device_action_inventory_stale" {
				t.Fatalf("stale storage selection accepted: %v", err)
			}
		})
	}
	var count int
	if err := f.svc.Pool.QueryRow(t.Context(), "SELECT count(*) FROM device_actions WHERE device_id=$1", f.principal.DeviceID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rejected selection persisted signed intent: count=%d err=%v", count, err)
	}
}

func TestStorageActionStartRechecksLatestInventoryAndCreateReplayIsDurable(t *testing.T) {
	for _, variant := range []string{"mismatch", "stale"} {
		t.Run(variant, func(t *testing.T) {
			f := newDeviceActionFixture(t)
			target := fixtureStorageTarget(uuid.NewString())
			f.observeStorageTargets(t, target)
			request := f.request(storageActionSpecs(f, target)["escrow_rotate"])
			action := f.create(t, request)
			start, _ := f.startRequest(t, f.work(t))
			if variant == "mismatch" {
				replacement := proto.CloneOf(target)
				replacement.Wwn += "-replacement"
				f.observeStorageTargets(t, replacement)
			} else if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE host_observations SET received_at=clock_timestamp()-interval '6 minutes' WHERE generation_id=$1", f.principal.GenerationID); err != nil {
				t.Fatal(err)
			}
			if replay := f.create(t, request); replay.GetActionId() != action.GetActionId() {
				t.Fatal("retry minted or replaced durable action")
			}
			want := "device_action_storage_target_mismatch"
			if variant == "stale" {
				want = "device_action_inventory_stale"
			}
			if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); rpcReason(err) != want {
				t.Fatalf("start ignored latest inventory: %v", err)
			}
			var grant []byte
			if err := f.svc.Pool.QueryRow(t.Context(), "SELECT start_grant_envelope FROM device_actions WHERE id=$1", action.GetActionId()).Scan(&grant); err != nil || len(grant) != 0 {
				t.Fatalf("rejected selection signed start authority: %v", err)
			}
			f.observeStorageTargets(t, target)
			if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
				t.Fatalf("unchanged request could not recover after fresh exact observation: %v", err)
			}
		})
	}
}

func TestStorageActionNativeScopeMismatchAndCompleteLiveSet(t *testing.T) {
	f := newDeviceActionFixture(t)
	target := fixtureStorageTarget("")
	details := nativeDetailsFixture()
	device := fixtureStorageDevice("nvme0n1", target)
	device.Identity.Nvme = &inventoryv1.ObservedNVMeScope{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Scope: fixtureNVMeScope()}
	details.Storage = fixtureStorageDetails(device).Storage
	f.observeStorageDetails(t, details)
	selected := f.storageTargets(t, "sanitize")
	if len(selected.GetTargets()) != 1 || !proto.Equal(selected.GetTargets()[0].GetNvme(), device.Identity.Nvme.Scope) {
		t.Fatal("native scope was not projected exactly")
	}
	spec := storageActionSpecs(f, target)["sanitize"]
	spec.GetSanitize().Method = agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_USER_DATA
	spec.GetSanitize().NvmeScope = proto.CloneOf(selected.GetTargets()[0].GetNvme())
	spec.GetSanitize().NvmeScope.Identity.ControllerFirmware = "changed"
	request := f.request(spec)
	f.approval(t, request)
	if _, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(request)); rpcReason(err) != "device_action_storage_target_mismatch" {
		t.Fatalf("altered native identity accepted: %v", err)
	}
	first, second := fixtureStorageTarget(uuid.NewString()), fixtureStorageTarget(uuid.NewString())
	f.observeStorageTargets(t, first, second)
	live := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_CryptoErase{CryptoErase: &agentv1.CryptoEraseAction{Mode: agentv1.CryptoEraseMode_CRYPTO_ERASE_MODE_LIVE_ROOT_HEADER, Targets: []*agentv1.StorageTarget{first}}}}
	request = f.request(live)
	f.approval(t, request)
	if _, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(request)); rpcReason(err) != "device_action_storage_target_set_mismatch" {
		t.Fatalf("live erasure omitted observed encrypted target: %v", err)
	}
}
