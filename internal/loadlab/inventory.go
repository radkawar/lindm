package loadlab

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	devicev1 "lindm/gen/lindm/device/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

type packageData struct {
	batches     [][]byte
	descriptors []*devicev1.PackageBatchDescriptor
}

// One interrupted upload is retained until the next normal inventory cycle.
// A new manifest cannot replace an admitted, still-open server snapshot.
type pendingInventoryUpload struct {
	host         *devicev1.ReportHostObservationRequest
	manifest     *devicev1.PackageSnapshotManifest
	hostAccepted bool
	begun        bool
	nextBatch    int
}

func packages(count int) (packageData, error) {
	var data packageData
	for start := 0; start < count; start += 500 {
		batch := &inventoryv1.PackageBatch{}
		for i := start; i < min(start+500, count); i++ {
			batch.Packages = append(batch.Packages, &inventoryv1.Package{Name: fmt.Sprintf("libload-package-%05d", i), Version: fmt.Sprintf("1:%d.24.04-0ubuntu1.7", i%17), Architecture: "amd64", Manager: "dpkg"})
		}
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(batch)
		if err != nil {
			return data, err
		}
		digest := sha256.Sum256(encoded)
		data.batches = append(data.batches, encoded)
		data.descriptors = append(data.descriptors, &devicev1.PackageBatchDescriptor{Index: uint32(start / 500), Sha256: digest[:], Count: uint32(len(batch.Packages)), EncodedSize: uint32(len(encoded))})
	}
	return data, nil
}
func observed(value string) *inventoryv1.ObservedString {
	return &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: value}
}
func (r *runner) inventory(ctx context.Context, d *simulatedDevice, index int) error {
	if d.inventoryUpload == nil {
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		now := stamp()
		d.hostSequence++
		d.packageSequence++
		host := r.historicalHost
		if index != 0 || host == nil {
			host = &inventoryv1.HostObservation{StartedAt: now, FinishedAt: now, BootId: observed(d.boot), Hostname: observed(label(index)), OsId: observed("ubuntu"), OsVersion: observed("24.04"), Architecture: observed("x86_64"), KernelRelease: observed("6.8.0-90-generic"), HardwareVendor: observed("Lindm capacity simulator"), HardwareModel: observed("Synthetic, not native inventory"), HardwareSerial: observed(label(index))}
			host.Details = syntheticNativeDetails()
		}
		d.inventoryUpload = &pendingInventoryUpload{
			host:     &devicev1.ReportHostObservationRequest{EnrollmentGeneration: d.generation, SessionEpoch: d.epoch, Sequence: d.hostSequence, Observation: host},
			manifest: &devicev1.PackageSnapshotManifest{SnapshotId: id.String(), CreatedAt: now, EnrollmentGeneration: d.generation, Sequence: d.packageSequence, StartedAt: now, FinishedAt: now, Backend: "dpkg-query", Batches: r.packages.descriptors},
		}
		r.inventoryCycles.Add(1)
	}
	pending := d.inventoryUpload
	if !pending.hostAccepted {
		receipt, err := d.client.ReportHostObservation(ctx, connect.NewRequest(pending.host))
		if err != nil {
			return err
		}
		if receipt.Msg.GetAcceptedSequence() != pending.host.GetSequence() {
			return errors.New("host observation sequence was not accepted")
		}
		pending.hostAccepted = true
	}
	if !pending.begun {
		if _, err := d.client.BeginPackageSnapshot(ctx, connect.NewRequest(&devicev1.BeginPackageSnapshotRequest{EnrollmentGeneration: d.generation, SessionEpoch: d.epoch, Manifest: pending.manifest})); err != nil {
			return err
		}
		pending.begun = true
	}
	for pending.nextBatch < len(r.packages.batches) {
		index := pending.nextBatch
		if _, err := d.client.PutPackageBatch(ctx, connect.NewRequest(&devicev1.PutPackageBatchRequest{EnrollmentGeneration: d.generation, SessionEpoch: d.epoch, SnapshotId: pending.manifest.GetSnapshotId(), BatchIndex: uint32(index), Batch: r.packages.batches[index]})); err != nil {
			return err
		}
		pending.nextBatch++
	}
	committed, err := d.client.CommitPackageSnapshot(ctx, connect.NewRequest(&devicev1.CommitPackageSnapshotRequest{EnrollmentGeneration: d.generation, SessionEpoch: d.epoch, Manifest: pending.manifest}))
	if err != nil {
		return err
	}
	if committed.Msg.GetState() != inventoryv1.SnapshotState_SNAPSHOT_STATE_COMMITTED || committed.Msg.GetPublishedSequence() != pending.manifest.GetSequence() {
		return errors.New("package snapshot was not published")
	}
	d.inventoryUpload = nil
	return nil
}

// The capacity simulator has no native sessions. Publish an explicit synthetic
// zero so the console can exercise non-destructive action admission, while
// leaving hardware, storage and encryption capabilities unavailable.
func syntheticNativeDetails() *inventoryv1.NativeDetails {
	unavailable := inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE
	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	text := func() *inventoryv1.ObservedString { return &inventoryv1.ObservedString{Status: unavailable} }
	number := func() *inventoryv1.ObservedUint64 { return &inventoryv1.ObservedUint64{Status: unavailable} }
	boolean := func() *inventoryv1.ObservedBool { return &inventoryv1.ObservedBool{Status: unavailable} }
	return &inventoryv1.NativeDetails{
		Cpu:               &inventoryv1.CpuDetails{Model: text(), LogicalCores: number(), PhysicalCores: number(), X86_64Level: text()},
		Memory:            &inventoryv1.MemoryDetails{TotalBytes: number(), AvailableBytes: number(), SwapTotalBytes: number()},
		Storage:           &inventoryv1.StorageDetails{Status: unavailable},
		Network:           &inventoryv1.NetworkDetails{Status: unavailable},
		Firmware:          &inventoryv1.FirmwareDetails{Mode: text(), SecureBoot: text()},
		Tpm:               &inventoryv1.TpmDetails{Present: boolean(), Version: text()},
		Power:             &inventoryv1.PowerDetails{Chassis: text(), Batteries: &inventoryv1.BatteryDetails{Status: unavailable}},
		Sessions:          &inventoryv1.SessionCounts{Users: &inventoryv1.ObservedUint64{Status: success}, Sessions: &inventoryv1.ObservedUint64{Status: success}},
		LocalUsers:        &inventoryv1.LocalUsers{Status: unavailable},
		KernelModuleCount: number(), UptimeSeconds: number(), BootTimeUnixSeconds: number(),
		Backends: &inventoryv1.BackendDetails{Dpkg: boolean(), Rpm: boolean(), Pacman: boolean(), Zypper: boolean(), RpmOstree: boolean(), Nix: boolean(), Flatpak: boolean(), Snap: boolean()},
		Flatpak:  &inventoryv1.ApplicationDetails{Status: unavailable}, Snap: &inventoryv1.ApplicationDetails{Status: unavailable},
	}
}
