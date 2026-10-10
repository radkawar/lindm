//go:build linux

package inventory

import (
	"context"
	"io"
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func TestStorageIdentitySchemaAvailability(t *testing.T) {
	unavailableText := func() *inventoryv1.ObservedString { return &inventoryv1.ObservedString{Status: unavailable} }
	identity := &inventoryv1.StorageIdentity{
		Transport: unavailableText(), Model: unavailableText(), Serial: unavailableText(),
		Firmware: unavailableText(), Wwn: unavailableText(), Eui: unavailableText(),
		PartitionUuid: unavailableText(), PartitionType: unavailableText(), FilesystemUuid: unavailableText(),
		LuksUuid: unavailableText(), LuksVersion: unavailableText(), LuksTokenTypes: unavailableText(),
		LuksKeyslotCount: &inventoryv1.ObservedUint64{Status: unavailable},
		LuksTokenCount:   &inventoryv1.ObservedUint64{Status: unavailable},
		BackingDisk:      unavailableText(), RootBacking: &inventoryv1.ObservedBool{Status: unavailable},
		Nvme:        &inventoryv1.ObservedNVMeScope{Status: unavailable},
		GptDiskGuid: unavailableText(),
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(identity))
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(identity); err != nil {
		t.Fatalf("explicit unavailable identity: %v", err)
	}
	for name, mutate := range map[string]func(*inventoryv1.StorageIdentity){
		"missing field":                 func(v *inventoryv1.StorageIdentity) { v.Serial = nil },
		"unavailable serial with value": func(v *inventoryv1.StorageIdentity) { v.Serial.Value = "invented" },
		"empty successful UUID":         func(v *inventoryv1.StorageIdentity) { v.LuksUuid.Status = success },
		"unavailable GPT with value":    func(v *inventoryv1.StorageIdentity) { v.GptDiskGuid.Value = "49865c36-1e3a-4d2b-b719-89144a6e179e" },
		"empty successful GPT":          func(v *inventoryv1.StorageIdentity) { v.GptDiskGuid.Status = success },
		"permission denied with slots": func(v *inventoryv1.StorageIdentity) {
			v.LuksKeyslotCount.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED
			v.LuksKeyslotCount.Value = 1
		},
		"successful missing NVMe": func(v *inventoryv1.StorageIdentity) { v.Nvme.Status = success },
	} {
		t.Run(name, func(t *testing.T) {
			changed := proto.CloneOf(identity)
			mutate(changed)
			if err := validator.Validate(changed); err == nil {
				t.Fatal("invalid identity admitted")
			}
		})
	}
	historical := proto.CloneOf(identity)
	historical.GptDiskGuid = nil
	if err := validator.Validate(historical); err != nil {
		t.Fatalf("historical missing GPT observation: %v", err)
	}
}

func TestStorageNVMeObservationRequiresExactReadOnlyScope(t *testing.T) {
	observed := &inventoryv1.ObservedNVMeScope{Status: success, Scope: &agentv1.NVMeSanitizeScope{
		NamespaceId: 1,
		Identity: &agentv1.NVMeSanitizeIdentity{
			Basis:    agentv1.NvmeIdentityBasis_NVME_IDENTITY_BASIS_NAMESPACE_NID,
			VendorId: 0x1b36, ControllerSerial: "lab-serial", ControllerModel: "lab-model", ControllerFirmware: "1.0",
			NamespaceSizeBytes: 4096, LbaDataSizeShift: 9,
		},
	}}
	validator, err := protovalidate.New(protovalidate.WithMessages(observed))
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(observed); err != nil {
		t.Fatalf("exact scope: %v", err)
	}
	for name, mutate := range map[string]func(*inventoryv1.ObservedNVMeScope){
		"unknown basis":        func(v *inventoryv1.ObservedNVMeScope) { v.Scope.Identity.Basis = 0 },
		"missing serial":       func(v *inventoryv1.ObservedNVMeScope) { v.Scope.Identity.ControllerSerial = "" },
		"missing namespace":    func(v *inventoryv1.ObservedNVMeScope) { v.Scope.NamespaceId = 0 },
		"controller authority": func(v *inventoryv1.ObservedNVMeScope) { v.Scope.ControllerWide = true },
		"failed with scope":    func(v *inventoryv1.ObservedNVMeScope) { v.Status = unavailable },
	} {
		t.Run(name, func(t *testing.T) {
			changed := proto.CloneOf(observed)
			mutate(changed)
			if err := validator.Validate(changed); err == nil {
				t.Fatal("invalid native scope admitted")
			}
		})
	}
}

func TestUploadCollectionDefersStorageToRoot(t *testing.T) {
	sources := fixtureDetails(t.TempDir())
	sources.rootObservation = true
	run := sources.run
	sources.run = func(ctx context.Context, command backend, consume func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
		if command.name == "lsblk" || command.name == "cryptsetup" || command.name == "nvme" {
			t.Fatalf("network collection repeated privileged storage probe: %s", command.name)
		}
		return run(ctx, command, consume)
	}
	details := collectDetails(t.Context(), sources)
	if details.Storage.Status != unavailable || len(details.Storage.Devices) != 0 {
		t.Fatal("network collection fabricated root storage evidence")
	}
}
