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
		host := &inventoryv1.HostObservation{StartedAt: now, FinishedAt: now, BootId: observed(d.boot), Hostname: observed(label(index)), OsId: observed("ubuntu"), OsVersion: observed("24.04"), Architecture: observed("x86_64"), KernelRelease: observed("6.8.0-90-generic"), HardwareVendor: observed("Lindm capacity simulator"), HardwareModel: observed("Synthetic, not native inventory"), HardwareSerial: observed(label(index))}
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
