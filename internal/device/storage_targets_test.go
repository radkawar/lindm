package device

import (
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/device/devicedb"
)

func fixtureStorageTarget(luks string) *agentv1.StorageTarget {
	return &agentv1.StorageTarget{LuksUuid: luks, Wwn: "wwn-" + luks, Serial: "serial-" + luks, SizeBytes: 1 << 30}
}

func fixtureStorageDevice(name string, target *agentv1.StorageTarget) *inventoryv1.BlockDevice {
	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	unavailable := inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE
	text := func(value string) *inventoryv1.ObservedString {
		if value == "" {
			return observed(unavailable, "")
		}
		return observed(success, value)
	}
	number := func() *inventoryv1.ObservedUint64 { return &inventoryv1.ObservedUint64{Status: unavailable} }
	identity := &inventoryv1.StorageIdentity{
		Transport: text("sata"), Model: text("fixture storage"), Serial: text(target.GetSerial()), Firmware: text("1"), Wwn: text(target.GetWwn()), Eui: text(""),
		PartitionUuid: text(""), PartitionType: text(""), FilesystemUuid: text(""), LuksUuid: text(target.GetLuksUuid()), LuksVersion: text(""),
		LuksKeyslotCount: number(), LuksTokenCount: number(), LuksTokenTypes: text(""), BackingDisk: text(name),
		RootBacking: &inventoryv1.ObservedBool{Status: success}, Nvme: &inventoryv1.ObservedNVMeScope{Status: unavailable},
	}
	device := &inventoryv1.BlockDevice{Name: name, Type: text("disk"), Parent: text(""), SizeBytes: &inventoryv1.ObservedUint64{Status: success, Value: target.GetSizeBytes()}, Filesystem: text(""), Mountpoint: text(""), Encryption: text("none"), Identity: identity}
	if target.GetLuksUuid() != "" {
		device.Filesystem, device.Encryption, identity.LuksVersion = text("crypto_LUKS"), text("luks"), text("2")
	}
	return device
}

func fixtureStorageDetails(devices ...*inventoryv1.BlockDevice) *inventoryv1.NativeDetails {
	return &inventoryv1.NativeDetails{Storage: &inventoryv1.StorageDetails{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Devices: devices}}
}

func TestObservedStorageTargetsRejectIncompleteIdentity(t *testing.T) {
	target := fixtureStorageTarget(uuid.NewString())
	for _, test := range []struct {
		name   string
		change func(*inventoryv1.BlockDevice)
	}{
		{"historical", func(d *inventoryv1.BlockDevice) { d.Identity = nil }},
		{"missing serial", func(d *inventoryv1.BlockDevice) { d.Identity.Serial.Value = "" }},
		{"unobserved serial", func(d *inventoryv1.BlockDevice) {
			d.Identity.Serial.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE
		}},
		{"missing wwn", func(d *inventoryv1.BlockDevice) { d.Identity.Wwn.Value = "" }},
		{"missing size", func(d *inventoryv1.BlockDevice) { d.SizeBytes.Value = 0 }},
		{"missing luks", func(d *inventoryv1.BlockDevice) { d.Identity.LuksUuid.Value = "" }},
		{"invalid luks", func(d *inventoryv1.BlockDevice) { d.Identity.LuksUuid.Value = "not-a-uuid" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			device := fixtureStorageDevice("sda", target)
			test.change(device)
			got, reason := observedStorageTargets(fixtureStorageDetails(device), "crypto_erase")
			if len(got) != 0 || reason != "device_action_storage_identity_unavailable" {
				t.Fatalf("incomplete identity selectable: %v %s", got, reason)
			}
		})
	}
}

func TestObservedStorageTargetsKindsAndTopology(t *testing.T) {
	target := fixtureStorageTarget(uuid.NewString())
	container := fixtureStorageDevice("sda1", target)
	container.Type.Value, container.Parent.Value, container.Identity.BackingDisk.Value = "part", "sda", "sda"
	container.Identity.RootBacking.Value = true
	disk := fixtureStorageDevice("sda", fixtureStorageTarget(""))
	details := fixtureStorageDetails(disk, container)
	for _, kind := range []string{"escrow_rotate", "crypto_erase"} {
		got, reason := observedStorageTargets(details, kind)
		if reason != "" || len(got) != 1 || !proto.Equal(got[0].GetTarget(), target) || !got[0].GetRootBacking() {
			t.Fatalf("exact LUKS selection for %s: %v %s", kind, got, reason)
		}
	}
	if got, _ := observedStorageTargets(details, "sanitize"); len(got) != 0 {
		t.Fatal("disk with encrypted descendant selectable")
	}
	if got, reason := observedStorageTargets(details, "tpm2_bind"); len(got) != 0 || reason != "device_action_tpm2_unavailable" {
		t.Fatal("TPM2 absence ignored")
	}
	details.Tpm = &inventoryv1.TpmDetails{Present: &inventoryv1.ObservedBool{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: true}, Version: observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, "2")}
	if got, reason := observedStorageTargets(details, "tpm2_bind"); len(got) != 1 || reason != "" {
		t.Fatal("available TPM2 did not expose LUKS container")
	}
	container.Encryption.Value, container.Filesystem.Value, container.Identity.LuksUuid.Value = "none", "ext4", ""
	if got, reason := observedStorageTargets(details, "sanitize"); len(got) != 1 || reason != "" || got[0].GetName() != "sda" {
		t.Fatal("sanitize did not restrict selection to whole disk")
	}
	container.Encryption.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE
	if got, _ := observedStorageTargets(details, "sanitize"); len(got) != 0 {
		t.Fatal("unknown descendant encryption treated as unencrypted")
	}
}

func TestObservedStorageTargetExactTupleAndLiveSet(t *testing.T) {
	first, second := fixtureStorageTarget(uuid.NewString()), fixtureStorageTarget(uuid.NewString())
	details := fixtureStorageDetails(fixtureStorageDevice("sda", first), fixtureStorageDevice("sdb", second))
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_CryptoErase{CryptoErase: &agentv1.CryptoEraseAction{Mode: agentv1.CryptoEraseMode_CRYPTO_ERASE_MODE_LIVE_ROOT_HEADER, Targets: []*agentv1.StorageTarget{first, second}}}}
	if err := requireObservedStorageTargets(details, spec); err != nil {
		t.Fatal(err)
	}
	mapping := fixtureStorageDevice("crypt-root", fixtureStorageTarget(""))
	mapping.Type.Value, mapping.Encryption.Value = "crypt", "dm-crypt"
	mapping.Parent = observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, "sda")
	details.Storage.Devices = append(details.Storage.Devices, mapping)
	if err := requireObservedStorageTargets(details, spec); err != nil {
		t.Fatalf("covered encrypted mapping counted as another native container: %v", err)
	}
	mapping.Parent.Value = "unobserved-container"
	if err := requireObservedStorageTargets(details, spec); rpcReason(err) != "device_action_storage_target_set_mismatch" {
		t.Fatalf("uncovered encrypted mapping omitted from live set: %v", err)
	}
	details.Storage.Devices = details.Storage.Devices[:2]
	for _, change := range []func(*agentv1.StorageTarget){
		func(t *agentv1.StorageTarget) { t.Wwn = "different" },
		func(t *agentv1.StorageTarget) { t.Serial = "" },
		func(t *agentv1.StorageTarget) { t.SizeBytes++ },
		func(t *agentv1.StorageTarget) { t.LuksUuid = uuid.NewString() },
	} {
		changed := proto.CloneOf(spec)
		change(changed.GetCryptoErase().Targets[0])
		if err := requireObservedStorageTargets(details, changed); rpcReason(err) != "device_action_storage_target_mismatch" {
			t.Fatalf("changed tuple accepted: %v", err)
		}
	}
	spec.GetCryptoErase().Targets = spec.GetCryptoErase().Targets[:1]
	if err := requireObservedStorageTargets(details, spec); rpcReason(err) != "device_action_storage_target_set_mismatch" {
		t.Fatalf("partial live set accepted: %v", err)
	}
	details.Storage.Devices[1].Identity = nil
	if err := requireObservedStorageTargets(details, spec); rpcReason(err) != "device_action_storage_target_set_mismatch" {
		t.Fatalf("unidentifiable encrypted volume disappeared from live set: %v", err)
	}
}

func fixtureNVMeScope() *agentv1.NVMeSanitizeScope {
	return &agentv1.NVMeSanitizeScope{NamespaceId: 1, Identity: &agentv1.NVMeSanitizeIdentity{Basis: agentv1.NvmeIdentityBasis_NVME_IDENTITY_BASIS_CONTROLLER_SERIAL_NSID, VendorId: 1, SubsystemVendorId: 2, ControllerSerial: "serial-", ControllerModel: "fixture storage", ControllerFirmware: "1", NamespaceSizeBytes: 1 << 30, LbaFormat: 0, LbaDataSizeShift: 9}}
}

func TestObservedNVMeIdentityRequiresExactBasisAndFields(t *testing.T) {
	target := fixtureStorageTarget("")
	device := fixtureStorageDevice("nvme0n1", target)
	device.Identity.Nvme = &inventoryv1.ObservedNVMeScope{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Scope: fixtureNVMeScope()}
	details := fixtureStorageDetails(device)
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Sanitize{Sanitize: &agentv1.SanitizeAction{Target: target, Method: agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_SANITIZE_BLOCK_ERASE, NvmeScope: proto.CloneOf(device.Identity.Nvme.Scope)}}}
	spec.GetSanitize().NvmeScope.ControllerWide = true
	if err := requireObservedStorageTargets(details, spec); err != nil {
		t.Fatalf("explicit effect scope changed identity: %v", err)
	}
	for _, test := range []struct {
		name   string
		change func(*agentv1.NVMeSanitizeScope)
	}{
		{"namespace", func(s *agentv1.NVMeSanitizeScope) { s.NamespaceId++ }},
		{"basis", func(s *agentv1.NVMeSanitizeScope) {
			s.Identity.Basis = agentv1.NvmeIdentityBasis_NVME_IDENTITY_BASIS_NAMESPACE_NID
		}},
		{"vendor", func(s *agentv1.NVMeSanitizeScope) { s.Identity.VendorId++ }},
		{"subsystem vendor", func(s *agentv1.NVMeSanitizeScope) { s.Identity.SubsystemVendorId++ }},
		{"serial", func(s *agentv1.NVMeSanitizeScope) { s.Identity.ControllerSerial += "x" }},
		{"model", func(s *agentv1.NVMeSanitizeScope) { s.Identity.ControllerModel += "x" }},
		{"firmware", func(s *agentv1.NVMeSanitizeScope) { s.Identity.ControllerFirmware += "x" }},
		{"size", func(s *agentv1.NVMeSanitizeScope) { s.Identity.NamespaceSizeBytes++ }},
		{"format", func(s *agentv1.NVMeSanitizeScope) { s.Identity.LbaFormat++ }},
		{"shift", func(s *agentv1.NVMeSanitizeScope) { s.Identity.LbaDataSizeShift++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := proto.CloneOf(spec)
			test.change(changed.GetSanitize().NvmeScope)
			if err := requireObservedStorageTargets(details, changed); rpcReason(err) != "device_action_storage_target_mismatch" {
				t.Fatalf("native identity mutation accepted: %v", err)
			}
		})
	}
}

func TestActionInventoryFreshBoundary(t *testing.T) {
	now := time.Now()
	for _, test := range []struct {
		age   time.Duration
		fresh bool
	}{{0, true}, {5 * time.Minute, true}, {5*time.Minute + time.Nanosecond, false}, {-time.Nanosecond, false}} {
		host := devicedb.GetHostObservationRow{ReceivedAt: pgtype.Timestamptz{Time: now.Add(-test.age), Valid: true}}
		if actionInventoryFresh(host, now) != test.fresh {
			t.Fatalf("receipt age %s freshness changed", test.age)
		}
	}
	if actionInventoryFresh(devicedb.GetHostObservationRow{}, now) {
		t.Fatal("missing receipt is fresh")
	}
}
func rpcReason(err error) string {
	var connectErr *connect.Error
	if errors.As(err, &connectErr) {
		return connectErr.Message()
	}
	return ""
}
