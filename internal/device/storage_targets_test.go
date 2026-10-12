package device

import (
	"errors"
	"testing"
	"time"

	"lindm/internal/device/inventory"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/device/devicedb"
)

func fixtureStorageTarget(luks string) *agentv1.StorageTarget {
	return &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, LuksUuid: luks, Wwn: "wwn-" + luks, Serial: "serial-" + luks, SizeBytes: 1 << 30}
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
		GptDiskGuid: text(target.GetGptDiskGuid()),
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

func fixtureVirtioStorage() (*agentv1.StorageTarget, *inventoryv1.NativeDetails) {
	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	target := &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_SERIAL_GPT_LUKS, Serial: "virtio-root", SizeBytes: 1 << 30, DiskSizeBytes: 2 << 30, GptDiskGuid: uuid.NewString(), LuksUuid: uuid.NewString()}
	diskTarget := proto.CloneOf(target)
	diskTarget.LuksUuid, diskTarget.SizeBytes = "", target.GetDiskSizeBytes()
	disk := fixtureStorageDevice("vda", diskTarget)
	container := fixtureStorageDevice("vda1", target)
	container.Type.Value, container.Identity.BackingDisk.Value = "part", "vda"
	container.Parent = observed(success, "vda")
	container.Identity.RootBacking.Value = true
	mapping := fixtureStorageDevice("crypt-root", diskTarget)
	mapping.Type.Value, mapping.Encryption.Value, mapping.Identity.BackingDisk.Value = "crypt", "dm-crypt", "vda"
	mapping.Parent = observed(success, "vda1")
	mapping.SizeBytes.Value = target.GetSizeBytes() - (16 << 20)
	details := fixtureStorageDetails(disk, container, mapping)
	details.Tpm = &inventoryv1.TpmDetails{Present: &inventoryv1.ObservedBool{Status: success, Value: true}, Version: observed(success, "2")}
	return target, details
}

func TestObservedStorageTargetsVirtioFallback(t *testing.T) {
	target, details := fixtureVirtioStorage()
	for _, kind := range []string{"escrow_rotate", "tpm2_bind", "crypto_erase"} {
		got, reason := inventory.ObservedStorageTargets(details, kind)
		if reason != "" || len(got) != 1 || !proto.Equal(got[0].GetTarget(), target) || got[0].GetName() != "vda1" || !got[0].GetRootBacking() {
			t.Fatalf("exact virtio LUKS selection for %s: %v %s", kind, got, reason)
		}
	}
	if got, _ := inventory.ObservedStorageTargets(details, "sanitize"); len(got) != 0 {
		t.Fatal("LUKS-only fallback exposed for sanitize")
	}
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_CryptoErase{CryptoErase: &agentv1.CryptoEraseAction{Mode: agentv1.CryptoEraseMode_CRYPTO_ERASE_MODE_LIVE_ROOT_HEADER, Targets: []*agentv1.StorageTarget{target}}}}
	if err := inventory.RequireObservedStorageTargets(details, spec); err != nil {
		t.Fatalf("unique serial counted inherited child identities: %v", err)
	}
	details.Storage.Devices = details.Storage.Devices[:1]
	if got, _ := inventory.ObservedStorageTargets(details, "sanitize"); len(got) != 0 {
		t.Fatal("unencrypted no-WWN disk became a sanitize fallback")
	}
}

func TestObservedStorageTargetsRefuseIncompleteFallback(t *testing.T) {
	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	unavailable := inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE
	for _, test := range []struct {
		name   string
		change func(*inventoryv1.BlockDevice, *inventoryv1.BlockDevice)
	}{
		{"unknown container type", func(_, c *inventoryv1.BlockDevice) { c.Type.Status = unavailable }},
		{"mapping container", func(_, c *inventoryv1.BlockDevice) { c.Type.Value = "crypt" }},
		{"whole disk container", func(d, c *inventoryv1.BlockDevice) {
			d.Type.Value, c.Type.Value, c.Identity.BackingDisk.Value = "part", "disk", c.Name
		}},
		{"historical WWN", func(_, c *inventoryv1.BlockDevice) { c.Identity.Wwn = nil }},
		{"failed WWN", func(_, c *inventoryv1.BlockDevice) {
			c.Identity.Wwn.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED
		}},
		{"unknown WWN", func(_, c *inventoryv1.BlockDevice) { c.Identity.Wwn.Status = 0 }},
		{"empty successful WWN", func(_, c *inventoryv1.BlockDevice) { c.Identity.Wwn.Status = success }},
		{"contradictory WWN", func(_, c *inventoryv1.BlockDevice) { c.Identity.Wwn.Value = "unobserved" }},
		{"missing serial", func(_, c *inventoryv1.BlockDevice) { c.Identity.Serial.Value = "" }},
		{"unobserved serial", func(_, c *inventoryv1.BlockDevice) { c.Identity.Serial.Status = unavailable }},
		{"disk serial mismatch", func(d, _ *inventoryv1.BlockDevice) { d.Identity.Serial.Value += "-other" }},
		{"unobserved disk serial", func(d, _ *inventoryv1.BlockDevice) { d.Identity.Serial.Status = unavailable }},
		{"disk has WWN", func(d, _ *inventoryv1.BlockDevice) { d.Identity.Wwn = observed(success, "native-wwn") }},
		{"unobserved disk WWN", func(d, _ *inventoryv1.BlockDevice) { d.Identity.Wwn = nil }},
		{"unknown backing", func(_, c *inventoryv1.BlockDevice) { c.Identity.BackingDisk.Status = unavailable }},
		{"missing backing", func(_, c *inventoryv1.BlockDevice) { c.Identity.BackingDisk.Value = "missing" }},
		{"backing not physical disk", func(d, _ *inventoryv1.BlockDevice) { d.Type.Value = "raid1" }},
		{"unknown disk type", func(d, _ *inventoryv1.BlockDevice) { d.Type.Status = unavailable }},
		{"unknown target size", func(_, c *inventoryv1.BlockDevice) { c.SizeBytes.Status = unavailable }},
		{"zero target size", func(_, c *inventoryv1.BlockDevice) { c.SizeBytes.Value = 0 }},
		{"unknown disk size", func(d, _ *inventoryv1.BlockDevice) { d.SizeBytes.Status = unavailable }},
		{"zero disk size", func(d, _ *inventoryv1.BlockDevice) { d.SizeBytes.Value = 0 }},
		{"smaller disk size", func(d, c *inventoryv1.BlockDevice) { d.SizeBytes.Value = c.SizeBytes.Value - 1 }},
		{"historical GPT", func(_, c *inventoryv1.BlockDevice) { c.Identity.GptDiskGuid = nil }},
		{"missing GPT", func(_, c *inventoryv1.BlockDevice) { c.Identity.GptDiskGuid.Value = "" }},
		{"unknown GPT", func(_, c *inventoryv1.BlockDevice) { c.Identity.GptDiskGuid.Status = unavailable }},
		{"invalid GPT", func(d, c *inventoryv1.BlockDevice) {
			d.Identity.GptDiskGuid.Value, c.Identity.GptDiskGuid.Value = "not-a-guid", "not-a-guid"
		}},
		{"zero GPT", func(d, c *inventoryv1.BlockDevice) {
			d.Identity.GptDiskGuid.Value, c.Identity.GptDiskGuid.Value = uuid.Nil.String(), uuid.Nil.String()
		}},
		{"GPT mismatch", func(d, _ *inventoryv1.BlockDevice) { d.Identity.GptDiskGuid.Value = uuid.NewString() }},
		{"unknown disk GPT", func(d, _ *inventoryv1.BlockDevice) { d.Identity.GptDiskGuid.Status = unavailable }},
		{"missing LUKS", func(_, c *inventoryv1.BlockDevice) { c.Identity.LuksUuid.Value = "" }},
		{"unknown LUKS", func(_, c *inventoryv1.BlockDevice) { c.Identity.LuksUuid.Status = unavailable }},
		{"invalid LUKS", func(_, c *inventoryv1.BlockDevice) { c.Identity.LuksUuid.Value = "not-a-uuid" }},
		{"zero LUKS", func(_, c *inventoryv1.BlockDevice) { c.Identity.LuksUuid.Value = uuid.Nil.String() }},
		{"not encrypted", func(_, c *inventoryv1.BlockDevice) { c.Encryption.Value, c.Filesystem.Value = "none", "ext4" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, details := fixtureVirtioStorage()
			test.change(details.Storage.Devices[0], details.Storage.Devices[1])
			got, reason := inventory.ObservedStorageTargets(details, "crypto_erase")
			if len(got) != 0 || reason != "device_action_storage_identity_unavailable" {
				t.Fatalf("incomplete fallback selectable: %v %s", got, reason)
			}
		})
	}
}

func TestObservedStorageTargetsFallbackRejectsDuplicatePhysicalSerial(t *testing.T) {
	for _, wwn := range []string{"", "another-native-wwn"} {
		t.Run(wwn, func(t *testing.T) {
			target, details := fixtureVirtioStorage()
			otherTarget := proto.CloneOf(target)
			otherTarget.Wwn, otherTarget.LuksUuid, otherTarget.SizeBytes = wwn, "", target.GetDiskSizeBytes()
			other := fixtureStorageDevice("vdb", otherTarget)
			details.Storage.Devices = append(details.Storage.Devices, other)
			if got, reason := inventory.ObservedStorageTargets(details, "crypto_erase"); len(got) != 0 || reason != "device_action_storage_identity_unavailable" {
				t.Fatalf("duplicate physical serial selectable: %v %s", got, reason)
			}
			other.Identity.Serial.Value += "-distinct"
			if got, reason := inventory.ObservedStorageTargets(details, "crypto_erase"); len(got) != 1 || reason != "" {
				t.Fatalf("distinct physical disk blocked fallback: %v %s", got, reason)
			}
		})
	}
}

func TestObservedStorageFallbackExactTupleAndNoDowngrade(t *testing.T) {
	target, details := fixtureVirtioStorage()
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_CryptoErase{CryptoErase: &agentv1.CryptoEraseAction{Mode: agentv1.CryptoEraseMode_CRYPTO_ERASE_MODE_OFFLINE, Target: target}}}
	if err := inventory.RequireObservedStorageTargets(details, spec); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*agentv1.StorageTarget){
		"unspecified basis": func(t *agentv1.StorageTarget) {
			t.IdentityBasis = agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_UNSPECIFIED
		},
		"unknown basis": func(t *agentv1.StorageTarget) { t.IdentityBasis = agentv1.StorageIdentityBasis(99) },
		"changed basis": func(t *agentv1.StorageTarget) {
			t.IdentityBasis = agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL
		},
		"WWN":         func(t *agentv1.StorageTarget) { t.Wwn = "invented-wwn" },
		"serial":      func(t *agentv1.StorageTarget) { t.Serial += "-replacement" },
		"target size": func(t *agentv1.StorageTarget) { t.SizeBytes++ },
		"disk size":   func(t *agentv1.StorageTarget) { t.DiskSizeBytes++ },
		"GPT":         func(t *agentv1.StorageTarget) { t.GptDiskGuid = uuid.NewString() },
		"LUKS":        func(t *agentv1.StorageTarget) { t.LuksUuid = uuid.NewString() },
	} {
		t.Run(name, func(t *testing.T) {
			changed := proto.CloneOf(spec)
			change(changed.GetCryptoErase().Target)
			if err := inventory.RequireObservedStorageTargets(details, changed); rpcReason(err) != "device_action_storage_target_mismatch" {
				t.Fatalf("changed signed fallback accepted: %v", err)
			}
		})
	}
	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	for _, device := range details.Storage.Devices {
		device.Identity.Wwn = observed(success, "native-wwn")
	}
	got, reason := inventory.ObservedStorageTargets(details, "crypto_erase")
	preferred := proto.CloneOf(target)
	preferred.IdentityBasis, preferred.Wwn = agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, "native-wwn"
	preferred.GptDiskGuid, preferred.DiskSizeBytes = "", 0
	if reason != "" || len(got) != 1 || !proto.Equal(got[0].GetTarget(), preferred) {
		t.Fatalf("WWN did not take precedence or retained fallback-only fields: %v %s", got, reason)
	}
	if err := inventory.RequireObservedStorageTargets(details, spec); rpcReason(err) != "device_action_storage_target_mismatch" {
		t.Fatalf("fallback silently accepted in place of observed WWN: %v", err)
	}
	spec.GetCryptoErase().Target = preferred
	if err := inventory.RequireObservedStorageTargets(details, spec); err != nil {
		t.Fatal(err)
	}
	for _, device := range details.Storage.Devices {
		device.Identity.Wwn = observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE, "")
	}
	if err := inventory.RequireObservedStorageTargets(details, spec); rpcReason(err) != "device_action_storage_target_mismatch" {
		t.Fatalf("WWN approval silently downgraded to fallback: %v", err)
	}
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
			got, reason := inventory.ObservedStorageTargets(fixtureStorageDetails(device), "crypto_erase")
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
		got, reason := inventory.ObservedStorageTargets(details, kind)
		if reason != "" || len(got) != 1 || !proto.Equal(got[0].GetTarget(), target) || !got[0].GetRootBacking() {
			t.Fatalf("exact LUKS selection for %s: %v %s", kind, got, reason)
		}
	}
	if got, _ := inventory.ObservedStorageTargets(details, "sanitize"); len(got) != 0 {
		t.Fatal("disk with encrypted descendant selectable")
	}
	if got, reason := inventory.ObservedStorageTargets(details, "tpm2_bind"); len(got) != 0 || reason != "device_action_tpm2_unavailable" {
		t.Fatal("TPM2 absence ignored")
	}
	details.Tpm = &inventoryv1.TpmDetails{Present: &inventoryv1.ObservedBool{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: true}, Version: observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, "2")}
	if got, reason := inventory.ObservedStorageTargets(details, "tpm2_bind"); len(got) != 1 || reason != "" {
		t.Fatal("available TPM2 did not expose LUKS container")
	}
	container.Encryption.Value, container.Filesystem.Value, container.Identity.LuksUuid.Value = "none", "ext4", ""
	if got, reason := inventory.ObservedStorageTargets(details, "sanitize"); len(got) != 1 || reason != "" || got[0].GetName() != "sda" {
		t.Fatal("sanitize did not restrict selection to whole disk")
	}
	container.Encryption.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE
	if got, _ := inventory.ObservedStorageTargets(details, "sanitize"); len(got) != 0 {
		t.Fatal("unknown descendant encryption treated as unencrypted")
	}
}

func TestObservedStorageTargetExactTupleAndLiveSet(t *testing.T) {
	first, second := fixtureStorageTarget(uuid.NewString()), fixtureStorageTarget(uuid.NewString())
	details := fixtureStorageDetails(fixtureStorageDevice("sda", first), fixtureStorageDevice("sdb", second))
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_CryptoErase{CryptoErase: &agentv1.CryptoEraseAction{Mode: agentv1.CryptoEraseMode_CRYPTO_ERASE_MODE_LIVE_ROOT_HEADER, Targets: []*agentv1.StorageTarget{first, second}}}}
	if err := inventory.RequireObservedStorageTargets(details, spec); err != nil {
		t.Fatal(err)
	}
	mapping := fixtureStorageDevice("crypt-root", fixtureStorageTarget(""))
	mapping.Type.Value, mapping.Encryption.Value = "crypt", "dm-crypt"
	mapping.Parent = observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, "sda")
	details.Storage.Devices = append(details.Storage.Devices, mapping)
	if err := inventory.RequireObservedStorageTargets(details, spec); err != nil {
		t.Fatalf("covered encrypted mapping counted as another native container: %v", err)
	}
	mapping.Parent.Value = "unobserved-container"
	if err := inventory.RequireObservedStorageTargets(details, spec); rpcReason(err) != "device_action_storage_target_set_mismatch" {
		t.Fatalf("uncovered encrypted mapping omitted from live set: %v", err)
	}
	details.Storage.Devices = details.Storage.Devices[:2]
	for _, change := range []func(*agentv1.StorageTarget){
		func(t *agentv1.StorageTarget) {
			t.IdentityBasis = agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_UNSPECIFIED
		},
		func(t *agentv1.StorageTarget) {
			t.IdentityBasis = agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_SERIAL_GPT_LUKS
		},
		func(t *agentv1.StorageTarget) { t.GptDiskGuid = uuid.NewString() },
		func(t *agentv1.StorageTarget) { t.DiskSizeBytes = t.SizeBytes },
		func(t *agentv1.StorageTarget) { t.Wwn = "different" },
		func(t *agentv1.StorageTarget) { t.Serial = "" },
		func(t *agentv1.StorageTarget) { t.SizeBytes++ },
		func(t *agentv1.StorageTarget) { t.LuksUuid = uuid.NewString() },
	} {
		changed := proto.CloneOf(spec)
		change(changed.GetCryptoErase().Targets[0])
		if err := inventory.RequireObservedStorageTargets(details, changed); rpcReason(err) != "device_action_storage_target_mismatch" {
			t.Fatalf("changed tuple accepted: %v", err)
		}
	}
	spec.GetCryptoErase().Targets = spec.GetCryptoErase().Targets[:1]
	if err := inventory.RequireObservedStorageTargets(details, spec); rpcReason(err) != "device_action_storage_target_set_mismatch" {
		t.Fatalf("partial live set accepted: %v", err)
	}
	details.Storage.Devices[1].Identity = nil
	if err := inventory.RequireObservedStorageTargets(details, spec); rpcReason(err) != "device_action_storage_target_set_mismatch" {
		t.Fatalf("unidentifiable encrypted volume disappeared from live set: %v", err)
	}
}

// Regression: Pop!_OS's distinst adds a plain dm-crypt swap keyed from
// /dev/urandom beside the LUKS root, which refused every live-root erase. Only
// the agent's native ephemeral-key proof exempts it; anything less is refused.
func TestLiveRootSetExemptsOnlyProvenEphemeralMappings(t *testing.T) {
	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	root := fixtureStorageTarget(uuid.NewString())
	details := fixtureStorageDetails(fixtureStorageDevice("sda", root))
	swapPart := fixtureStorageDevice("sdb", fixtureStorageTarget(""))
	swap := fixtureStorageDevice("cryptswap", fixtureStorageTarget(""))
	swap.Type.Value, swap.Encryption.Value = "crypt", "dm-crypt"
	swap.Parent = observed(success, "sdb")
	details.Storage.Devices = append(details.Storage.Devices, swapPart, swap)
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_CryptoErase{CryptoErase: &agentv1.CryptoEraseAction{Mode: agentv1.CryptoEraseMode_CRYPTO_ERASE_MODE_LIVE_ROOT_HEADER, Targets: []*agentv1.StorageTarget{root}}}}
	for _, key := range []*inventoryv1.ObservedBool{
		nil, // an agent that predates the proof
		{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE},
		{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_INVALID_OUTPUT},
		{Status: success, Value: false},
	} {
		swap.Identity.EphemeralKey = key
		if err := inventory.RequireObservedStorageTargets(details, spec); rpcReason(err) != "device_action_storage_target_set_mismatch" {
			t.Fatalf("unproven plain mapping %v exempted from the live set: %v", key, err)
		}
		if names := inventory.EphemeralKeyMappings(details); len(names) != 0 {
			t.Fatalf("unproven mapping named ephemeral: %v", names)
		}
	}
	swap.Identity.EphemeralKey = &inventoryv1.ObservedBool{Status: success, Value: true}
	if err := inventory.RequireObservedStorageTargets(details, spec); err != nil {
		t.Fatalf("proven ephemeral swap refused: %v", err)
	}
	if names := inventory.EphemeralKeyMappings(details); len(names) != 1 || names[0] != "cryptswap" {
		t.Fatalf("ephemeral mappings = %v", names)
	}
	// The proof belongs to a dm-crypt mapping; a disk claiming it is ignored.
	swapPart.Type.Value, swapPart.Encryption.Value = "crypt", "dm-crypt"
	swapPart.Parent = observed(success, "unobserved")
	if err := inventory.RequireObservedStorageTargets(details, spec); rpcReason(err) != "device_action_storage_target_set_mismatch" {
		t.Fatalf("unproven mapping beneath a proven one exempted: %v", err)
	}
}

func fixtureNVMeScope() *agentv1.NVMeSanitizeScope {
	return &agentv1.NVMeSanitizeScope{NamespaceId: 1, Identity: &agentv1.NVMeSanitizeIdentity{Basis: agentv1.NvmeIdentityBasis_NVME_IDENTITY_BASIS_CONTROLLER_SERIAL_NSID, VendorId: 1, SubsystemVendorId: 2, ControllerSerial: "serial-", ControllerModel: "fixture storage", ControllerFirmware: "1", NamespaceSizeBytes: 1 << 30, LbaDataSizeShift: 9}}
}

func TestObservedNVMeIdentityRequiresExactBasisAndFields(t *testing.T) {
	target := fixtureStorageTarget("")
	device := fixtureStorageDevice("nvme0n1", target)
	device.Identity.Nvme = &inventoryv1.ObservedNVMeScope{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Scope: fixtureNVMeScope()}
	details := fixtureStorageDetails(device)
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Sanitize{Sanitize: &agentv1.SanitizeAction{Target: target, Method: agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_SANITIZE_BLOCK_ERASE, NvmeScope: proto.CloneOf(device.Identity.Nvme.Scope)}}}
	spec.GetSanitize().NvmeScope.ControllerWide = true
	if err := inventory.RequireObservedStorageTargets(details, spec); err != nil {
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
		{"shift", func(s *agentv1.NVMeSanitizeScope) { s.Identity.LbaDataSizeShift++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := proto.CloneOf(spec)
			test.change(changed.GetSanitize().NvmeScope)
			if err := inventory.RequireObservedStorageTargets(details, changed); rpcReason(err) != "device_action_storage_target_mismatch" {
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
		if inventory.ActionInventoryFresh(host, now) != test.fresh {
			t.Fatalf("receipt age %s freshness changed", test.age)
		}
	}
	if inventory.ActionInventoryFresh(devicedb.GetHostObservationRow{}, now) {
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
