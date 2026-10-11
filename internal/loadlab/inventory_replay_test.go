package loadlab

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/gen/lindm/device/v1/devicev1connect"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// This is a unit test of harness checkpoints, not a PostgreSQL/package integration test.
type inventoryReplayClient struct {
	devicev1connect.DeviceServiceClient
	t                                              *testing.T
	phase                                          string
	failed                                         bool
	hostCalls, beginCalls, batchCalls, commitCalls int
	expected                                       *devicev1.PackageSnapshotManifest
}

func (c *inventoryReplayClient) failure(phase string) error {
	if c.phase == phase && !c.failed {
		c.failed = true
		return connect.NewError(connect.CodeResourceExhausted, errors.New("injected admission pressure"))
	}
	return nil
}
func (c *inventoryReplayClient) ReportHostObservation(_ context.Context, req *connect.Request[devicev1.ReportHostObservationRequest]) (*connect.Response[devicev1.ReportHostObservationResponse], error) {
	c.hostCalls++
	if err := c.failure("host"); err != nil {
		return nil, err
	}
	return connect.NewResponse(&devicev1.ReportHostObservationResponse{AcceptedSequence: req.Msg.GetSequence()}), nil
}
func (c *inventoryReplayClient) BeginPackageSnapshot(_ context.Context, req *connect.Request[devicev1.BeginPackageSnapshotRequest]) (*connect.Response[devicev1.BeginPackageSnapshotResponse], error) {
	c.beginCalls++
	c.checkManifest(req.Msg.GetManifest())
	if err := c.failure("begin"); err != nil {
		return nil, err
	}
	return connect.NewResponse(&devicev1.BeginPackageSnapshotResponse{}), nil
}
func (c *inventoryReplayClient) PutPackageBatch(_ context.Context, req *connect.Request[devicev1.PutPackageBatchRequest]) (*connect.Response[devicev1.PutPackageBatchResponse], error) {
	c.batchCalls++
	if c.expected != nil && req.Msg.GetSnapshotId() != c.expected.GetSnapshotId() {
		c.t.Fatal("batch switched admitted snapshot identity")
	}
	if req.Msg.GetBatchIndex() == 1 {
		if err := c.failure("batch"); err != nil {
			return nil, err
		}
	}
	return connect.NewResponse(&devicev1.PutPackageBatchResponse{}), nil
}
func (c *inventoryReplayClient) CommitPackageSnapshot(_ context.Context, req *connect.Request[devicev1.CommitPackageSnapshotRequest]) (*connect.Response[devicev1.CommitPackageSnapshotResponse], error) {
	c.commitCalls++
	c.checkManifest(req.Msg.GetManifest())
	if err := c.failure("commit"); err != nil {
		return nil, err
	}
	return connect.NewResponse(&devicev1.CommitPackageSnapshotResponse{State: inventoryv1.SnapshotState_SNAPSHOT_STATE_COMMITTED, PublishedSequence: req.Msg.GetManifest().GetSequence()}), nil
}
func (c *inventoryReplayClient) checkManifest(manifest *devicev1.PackageSnapshotManifest) {
	c.t.Helper()
	if c.expected != nil && !proto.Equal(c.expected, manifest) {
		c.t.Fatal("interrupted upload changed manifest bytes or sequence")
	}
}
func TestInventoryRetainsInterruptedUpload(t *testing.T) {
	for _, phase := range []string{"host", "begin", "batch", "commit"} {
		t.Run(phase, func(t *testing.T) {
			data, err := packages(2000, nil)
			if err != nil {
				t.Fatal(err)
			}
			client := &inventoryReplayClient{t: t, phase: phase}
			d := &simulatedDevice{client: client, generation: "generation", boot: "boot", epoch: 1}
			r := &runner{packages: data}
			if err := r.inventory(t.Context(), d, 0); connect.CodeOf(err) != connect.CodeResourceExhausted {
				t.Fatalf("original failure suppressed: %v", err)
			}
			if d.inventoryUpload == nil {
				t.Fatal("failed upload checkpoint lost")
			}
			client.expected = proto.CloneOf(d.inventoryUpload.manifest)
			if err := r.inventory(t.Context(), d, 0); err != nil {
				t.Fatal(err)
			}
			if d.inventoryUpload != nil || d.hostSequence != 1 || d.packageSequence != 1 || r.inventoryCycles.Load() != 1 {
				t.Fatal("retry created another collection or retained a completed checkpoint")
			}
			wantHost, wantBegin, wantBatch, wantCommit := 1, 1, 4, 1
			switch phase {
			case "host":
				wantHost++
			case "begin":
				wantBegin++
			case "batch":
				wantBatch++
			case "commit":
				wantCommit++
			}
			if client.hostCalls != wantHost || client.beginCalls != wantBegin || client.batchCalls != wantBatch || client.commitCalls != wantCommit {
				t.Fatalf("successful phases replayed: host=%d begin=%d batch=%d commit=%d", client.hostCalls, client.beginCalls, client.batchCalls, client.commitCalls)
			}
			client.expected = nil
			if err := r.inventory(t.Context(), d, 0); err != nil {
				t.Fatal(err)
			}
			if d.packageSequence != 2 || r.inventoryCycles.Load() != 2 {
				t.Fatal("next normal collection reused completed snapshot")
			}
		})
	}
}
