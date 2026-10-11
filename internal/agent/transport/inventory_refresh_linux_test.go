//go:build linux

package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/gen/lindm/agent/v1/agentv1connect"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/gen/lindm/device/v1/devicev1connect"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/agent/config"
	"lindm/internal/agent/spool"
	"lindm/internal/rpcreason"
)

// These boundaries exercise actual collection scheduling, SQLite spool promotion,
// batching, publication ordering and exact receipt relay. Cryptographic receipt
// rejection and protected-journal durability are exercised in executor tests.
type refreshTransportFixture struct {
	t                                   *testing.T
	r                                   *runner
	status                              *agentv1.DeviceActionStatus
	connection                          *agentv1.GetConnectionResponse
	manifest                            *devicev1.PackageSnapshotManifest
	host, packages                      uint64
	boundHost, boundPackages            uint64
	hostCalls, beginCalls, staleUploads int
	publicationRequests                 int
	superseded                          []string
	batches, collections, confirmations int
	committed                           bool
	failCommit                          bool
	failPublication                     bool
	failExecutorConfirmation            bool
	publicationErr                      error
	hostErr                             error
	snapshotState                       inventoryv1.SnapshotState
	receipt                             []byte
	boot                                string
	readiness                           *agentv1.RecoveryReadinessObservation
	readinessErr                        error
	readinessCalls                      int
	publishedHost                       *inventoryv1.HostObservation
}

type refreshTransportExecutor struct {
	agentv1connect.ExecutorServiceClient
	f *refreshTransportFixture
}
type refreshTransportServer struct {
	devicev1connect.DeviceServiceClient
	f *refreshTransportFixture
}

func newRefreshTransportFixture(t *testing.T) *refreshTransportFixture {
	t.Helper()
	f := &refreshTransportFixture{t: t, host: 9, packages: 3, receipt: []byte("exact signed publication envelope\n")}
	f.boot = uuid.NewString()
	f.readiness = &agentv1.RecoveryReadinessObservation{BootId: f.boot, Available: true, EspUuid: "1234-5678", EspPath: "/boot/efi", FreeBytes: 16384, AllocationUnitBytes: 4096, SecureBoot: true, UkiCapable: true}
	now := timestamppb.Now()
	digest := sha256.Sum256([]byte("signed refresh intent"))
	f.status = &agentv1.DeviceActionStatus{ActionId: uuid.NewString(), IntentSha256: digest[:], State: agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING, Failure: agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_NONE, AcceptedAt: now, StartedAt: now, Before: &agentv1.DeviceActionObservation{ObservedAt: now, Supported: true}, RefreshInventory: true}
	f.connection = &agentv1.GetConnectionResponse{DeploymentId: uuid.NewString(), DeviceId: uuid.NewString(), EnrollmentGeneration: uuid.NewString(), SessionEpoch: 1, SessionEpochUsable: true, RenewAfter: timestamppb.New(time.Now().Add(time.Hour))}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	e := &refreshTransportExecutor{f: f}
	f.r = &runner{document: &config.Document{SpoolDirectory: dir}, executor: e, authorityGate: make(authorityGate, 1), status: &agentv1.TransportStatus{}, cache: connectionCache{connection: proto.CloneOf(f.connection), servers: &connections{device: &refreshTransportServer{f: f}}}}
	f.r.collectInventory = func(context.Context) (*inventoryv1.NativeObservation, error) {
		f.collections++
		observation := refreshObservation(time.Now())
		observation.Host.BootId.Value = f.boot
		observation.Host.Details = unavailableNativeDetails()
		return observation, nil
	}
	t.Cleanup(func() {
		if f.r.store != nil {
			if err := f.r.store.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	return f
}

func refreshObservation(startedAt time.Time) *inventoryv1.NativeObservation {
	now := timestamppb.New(startedAt)
	value := func(s string) *inventoryv1.ObservedString {
		return &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: s}
	}
	return &inventoryv1.NativeObservation{Host: &inventoryv1.HostObservation{StartedAt: now, FinishedAt: now, BootId: value(uuid.NewString()), Hostname: value("refreshed"), OsId: value("debian"), OsVersion: value("13"), Architecture: value("amd64"), KernelRelease: value("6.12"), HardwareVendor: value("vendor"), HardwareModel: value("model"), HardwareSerial: value("serial")}, Packages: &inventoryv1.PackageObservation{StartedAt: now, FinishedAt: now, Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Backend: "dpkg", Packages: []*inventoryv1.Package{{Name: "fresh-package", Version: "2", Architecture: "amd64", Manager: "dpkg"}}}}
}

func (f *refreshTransportFixture) queue(observation *inventoryv1.NativeObservation) {
	f.t.Helper()
	if err := f.r.bind(f.t.Context(), f.connection); err != nil {
		f.t.Fatal(err)
	}
	if err := f.r.store.Synchronize(f.t.Context(), f.host, f.packages); err != nil {
		f.t.Fatal(err)
	}
	if err := f.r.store.Queue(f.t.Context(), observation); err != nil {
		f.t.Fatal(err)
	}
}

func (f *refreshTransportFixture) reopen() {
	f.t.Helper()
	if err := f.r.store.Close(); err != nil {
		f.t.Fatal(err)
	}
	var err error
	f.r.store, err = spool.Open(f.t.Context(), f.r.document.SpoolDirectory, f.r.identity)
	if err != nil {
		f.t.Fatal(err)
	}
}

func refreshNotPublished() error {
	err := connect.NewError(connect.CodeFailedPrecondition, errors.New("refresh inventory is not published"))
	rpcreason.Set(err, "inventory_refresh_not_published")
	return err
}

func (e *refreshTransportExecutor) GetConnection(context.Context, *connect.Request[agentv1.GetConnectionRequest]) (*connect.Response[agentv1.GetConnectionResponse], error) {
	return connect.NewResponse(proto.CloneOf(e.f.connection)), nil
}
func (*refreshTransportExecutor) GetAgentUpdate(context.Context, *connect.Request[agentv1.GetAgentUpdateRequest]) (*connect.Response[agentv1.GetAgentUpdateResponse], error) {
	return connect.NewResponse(&agentv1.GetAgentUpdateResponse{}), nil
}
func (e *refreshTransportExecutor) PrepareSession(context.Context, *connect.Request[agentv1.PrepareSessionRequest]) (*connect.Response[agentv1.PrepareSessionResponse], error) {
	return connect.NewResponse(&agentv1.PrepareSessionResponse{Result: &agentv1.PrepareSessionResponse_Accepted{Accepted: &agentv1.AcceptedSession{SessionEpoch: 1}}}), nil
}
func (e *refreshTransportExecutor) GetDeviceAction(context.Context, *connect.Request[agentv1.GetDeviceActionRequest]) (*connect.Response[agentv1.GetDeviceActionResponse], error) {
	return connect.NewResponse(&agentv1.GetDeviceActionResponse{Status: proto.CloneOf(e.f.status)}), nil
}
func (e *refreshTransportExecutor) ConfirmDeviceActionInventory(_ context.Context, req *connect.Request[agentv1.ConfirmDeviceActionInventoryRequest]) (*connect.Response[agentv1.ConfirmDeviceActionInventoryResponse], error) {
	f := e.f
	if !f.committed || !bytes.Equal(req.Msg.GetReceiptEnvelope(), f.receipt) || req.Msg.GetActionId() != f.status.GetActionId() {
		f.t.Fatal("completion preceded publication or rewrote its receipt")
	}
	if f.failExecutorConfirmation {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("protected confirmation unavailable"))
	}
	f.confirmations++
	f.status.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED
	f.status.CompletedAt = timestamppb.Now()
	f.status.Verification = &agentv1.DeviceActionVerification{Verified: true, After: proto.CloneOf(f.status.GetBefore()), InventorySequence: f.boundPackages}
	return connect.NewResponse(&agentv1.ConfirmDeviceActionInventoryResponse{Status: proto.CloneOf(f.status)}), nil
}
func (s *refreshTransportServer) GetSyncState(context.Context, *connect.Request[devicev1.GetSyncStateRequest]) (*connect.Response[devicev1.GetSyncStateResponse], error) {
	return connect.NewResponse(&devicev1.GetSyncStateResponse{SessionEpoch: 1, HostSequence: s.f.host, PackageSequence: s.f.packages, ServerTime: timestamppb.Now()}), nil
}
func (s *refreshTransportServer) ReportHostObservation(_ context.Context, req *connect.Request[devicev1.ReportHostObservationRequest]) (*connect.Response[devicev1.ReportHostObservationResponse], error) {
	f := s.f
	f.hostCalls++
	if req.Msg.GetObservation().GetStartedAt().AsTime().Before(f.status.GetStartedAt().AsTime()) {
		f.staleUploads++
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("routine host cooldown"))
	}
	if f.hostErr != nil {
		return nil, f.hostErr
	}
	if req.Msg.GetObservation().GetHostname().GetValue() != "refreshed" {
		f.t.Fatal("fresh host was not fully collected")
	}
	if f.boundHost != 0 && f.boundHost != req.Msg.GetSequence() {
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("refresh host admission already spent"))
	}
	f.boundHost = req.Msg.GetSequence()
	f.host = max(f.host, f.boundHost)
	s.f.publishedHost = proto.CloneOf(req.Msg.GetObservation())
	return connect.NewResponse(&devicev1.ReportHostObservationResponse{AcceptedSequence: f.host, ServerTime: timestamppb.Now()}), nil
}
func (s *refreshTransportServer) BeginPackageSnapshot(_ context.Context, req *connect.Request[devicev1.BeginPackageSnapshotRequest]) (*connect.Response[devicev1.BeginPackageSnapshotResponse], error) {
	f := s.f
	f.beginCalls++
	manifest := req.Msg.GetManifest()
	if manifest.GetStartedAt().AsTime().Before(f.status.GetStartedAt().AsTime()) {
		f.staleUploads++
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("routine package cooldown"))
	}
	if f.boundPackages != 0 && f.boundPackages != manifest.GetSequence() {
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("refresh package admission already spent"))
	}
	if f.manifest != nil && !proto.Equal(f.manifest, manifest) {
		if !f.manifest.GetStartedAt().AsTime().Before(f.status.GetStartedAt().AsTime()) {
			f.t.Fatal("same-action immutable manifest changed")
		}
		f.superseded = append(f.superseded, f.manifest.GetSnapshotId())
	}
	f.manifest = proto.CloneOf(manifest)
	f.boundPackages = manifest.GetSequence()
	f.packages = max(f.packages, f.boundPackages)
	state := inventoryv1.SnapshotState_SNAPSHOT_STATE_STAGING
	if f.committed {
		state = inventoryv1.SnapshotState_SNAPSHOT_STATE_COMMITTED
	} else if f.snapshotState != inventoryv1.SnapshotState_SNAPSHOT_STATE_UNSPECIFIED {
		state = f.snapshotState
	}
	return connect.NewResponse(&devicev1.BeginPackageSnapshotResponse{State: state, PackageSequence: f.packages, ServerTime: timestamppb.Now()}), nil
}
func (s *refreshTransportServer) ReportPackageAttempt(context.Context, *connect.Request[devicev1.ReportPackageAttemptRequest]) (*connect.Response[devicev1.ReportPackageAttemptResponse], error) {
	s.f.staleUploads++
	return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("routine failed-package cooldown"))
}
func (s *refreshTransportServer) PutPackageBatch(_ context.Context, req *connect.Request[devicev1.PutPackageBatchRequest]) (*connect.Response[devicev1.PutPackageBatchResponse], error) {
	batch := new(inventoryv1.PackageBatch)
	if err := proto.Unmarshal(req.Msg.GetBatch(), batch); err != nil {
		s.f.t.Fatal(err)
	}
	if len(batch.GetPackages()) != 1 || batch.GetPackages()[0].GetName() != "fresh-package" {
		s.f.t.Fatal("full collection batch was not uploaded")
	}
	s.f.batches++
	return connect.NewResponse(&devicev1.PutPackageBatchResponse{State: inventoryv1.SnapshotState_SNAPSHOT_STATE_STAGING, ServerTime: timestamppb.Now()}), nil
}
func (s *refreshTransportServer) CommitPackageSnapshot(_ context.Context, req *connect.Request[devicev1.CommitPackageSnapshotRequest]) (*connect.Response[devicev1.CommitPackageSnapshotResponse], error) {
	if s.f.failCommit {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("publication unavailable"))
	}
	if s.f.batches != 1 || !proto.Equal(s.f.manifest, req.Msg.GetManifest()) {
		s.f.t.Fatal("commit omitted full batches or changed manifest")
	}
	s.f.committed = true
	s.f.packages = req.Msg.GetManifest().GetSequence()
	return connect.NewResponse(&devicev1.CommitPackageSnapshotResponse{State: inventoryv1.SnapshotState_SNAPSHOT_STATE_COMMITTED, PackageSequence: s.f.packages, PublishedSequence: s.f.packages, ServerTime: timestamppb.Now()}), nil
}
func (s *refreshTransportServer) ConfirmRefreshInventoryPublication(_ context.Context, req *connect.Request[devicev1.ConfirmRefreshInventoryPublicationRequest]) (*connect.Response[devicev1.ConfirmRefreshInventoryPublicationResponse], error) {
	f := s.f
	f.publicationRequests++
	if req.Msg.GetActionId() != f.status.GetActionId() || req.Msg.GetSessionEpoch() != f.connection.GetSessionEpoch() {
		f.t.Fatal("receipt requested outside the action's session")
	}
	if f.publicationErr != nil {
		return nil, f.publicationErr
	}
	if !f.committed || f.boundHost == 0 || f.boundPackages == 0 {
		return nil, refreshNotPublished()
	}
	if f.failPublication {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("publication confirmation unavailable"))
	}
	return connect.NewResponse(&devicev1.ConfirmRefreshInventoryPublicationResponse{ReceiptEnvelope: f.receipt}), nil
}

func TestInventoryRefreshPublishesFullSnapshotBeforeCompletion(t *testing.T) {
	f := newRefreshTransportFixture(t)
	if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err != nil {
		t.Fatal(err)
	}
	if f.collections != 1 || f.confirmations != 1 || f.packages != 4 || f.host != 10 {
		t.Fatalf("refresh failed independent sequence publication: collections=%d confirms=%d host=%d packages=%d", f.collections, f.confirmations, f.host, f.packages)
	}
	if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err != nil {
		t.Fatal(err)
	}
	if f.collections != 1 || f.confirmations != 1 {
		t.Fatal("completed action replay recollected")
	}
}

func TestInventoryRefreshStagingNeverSucceedsAndPendingSurvivesRestart(t *testing.T) {
	f := newRefreshTransportFixture(t)
	f.failCommit = true
	if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err == nil {
		t.Fatal("staging counted as published")
	}
	if f.confirmations != 0 || f.status.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING {
		t.Fatal("unpublished collection completed action")
	}
	pending, ok, err := f.r.store.PendingPackage(t.Context())
	if err != nil || !ok || !pending.BeginAccepted || len(pending.AcceptedBatches) != 1 {
		t.Fatalf("full pending snapshot not durable: %v", err)
	}
	if err := f.r.store.Close(); err != nil {
		t.Fatal(err)
	}
	f.r.store, err = spool.Open(t.Context(), f.r.document.SpoolDirectory, f.r.identity)
	if err != nil {
		t.Fatal(err)
	}
	recovered, ok, err := f.r.store.PendingPackage(t.Context())
	if err != nil || !ok || !proto.Equal(recovered.Manifest, pending.Manifest) {
		t.Fatalf("restart lost immutable upload: %v", err)
	}
	f.failCommit = false
	if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err != nil {
		t.Fatal(err)
	}
	if f.batches != 1 || f.collections != 1 || !f.committed || f.confirmations != 1 {
		t.Fatal("resume recollected, resent an acknowledged batch or missed publication")
	}
}

func TestInventoryRefreshDoesNotCollectUnknownOrFailedPackages(t *testing.T) {
	t.Run("unknown", func(t *testing.T) {
		f := newRefreshTransportFixture(t)
		f.status.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN
		f.status.Failure = agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_INTERRUPTED
		f.status.CompletedAt = timestamppb.Now()
		if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err == nil {
			t.Fatal("unknown consumed action authorized another collection")
		}
		if f.collections != 0 || f.confirmations != 0 {
			t.Fatal("unknown action triggered collection or completion")
		}
	})
	t.Run("partial", func(t *testing.T) {
		f := newRefreshTransportFixture(t)
		collect := f.r.collectInventory
		f.r.collectInventory = func(ctx context.Context) (*inventoryv1.NativeObservation, error) {
			observation, err := collect(ctx)
			if err != nil {
				return nil, err
			}
			observation.Packages.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE
			observation.Packages.Packages = nil
			return observation, nil
		}
		if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err == nil {
			t.Fatal("failed package collection satisfied full refresh")
		}
		if f.manifest != nil || f.confirmations != 0 {
			t.Fatal("partial collection published as full snapshot")
		}
	})
}

func TestInventoryRefreshSupersedesRoutineBacklogBeforeUpload(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		host, packages, failed bool
		queued, admitted       bool
	}{
		{name: "successful-pending", host: true, packages: true},
		{name: "failed-pending", host: true, packages: true, failed: true},
		{name: "host-only", host: true},
		{name: "package-only", packages: true},
		{name: "failed-package-only", packages: true, failed: true},
		{name: "queued-only", queued: true},
		{name: "pending-and-stale-queued", host: true, packages: true, queued: true},
		{name: "already-admitted-staging", host: true, packages: true, queued: true, admitted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRefreshTransportFixture(t)
			old := refreshObservation(f.status.GetStartedAt().AsTime().Add(-time.Minute))
			if tc.failed {
				old.Packages.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE
				old.Packages.Packages = nil
			}
			f.queue(old)
			wantHost, wantPackages := uint64(10), uint64(4)
			if tc.host {
				host, err := f.r.store.PromoteHost(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				wantHost = host.Sequence + 1
				if tc.admitted {
					f.host = host.Sequence
				}
			}
			var oldSnapshot string
			if tc.packages {
				packages, err := f.r.store.PromotePackage(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				wantPackages = packages.Sequence + 1
				if tc.admitted {
					f.manifest = proto.CloneOf(packages.Manifest)
					oldSnapshot = packages.Manifest.GetSnapshotId()
					f.packages = packages.Sequence
					if err := f.r.store.MarkBegin(t.Context()); err != nil {
						t.Fatal(err)
					}
					if err := f.r.store.MarkBatchAccepted(t.Context(), 0); err != nil {
						t.Fatal(err)
					}
				}
			}
			if tc.queued {
				f.queue(refreshObservation(f.status.GetStartedAt().AsTime().Add(-time.Second)))
			}
			f.r.waiting = old
			if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err != nil {
				t.Fatal(err)
			}
			if f.collections != 1 || f.hostCalls != 1 || f.beginCalls != 1 || f.staleUploads != 0 || f.batches != 1 || f.confirmations != 1 {
				t.Fatalf("refresh drained routine backlog instead of replacing it: collect=%d host=%d begin=%d stale=%d batches=%d confirmations=%d", f.collections, f.hostCalls, f.beginCalls, f.staleUploads, f.batches, f.confirmations)
			}
			if f.boundHost != wantHost || f.boundPackages != wantPackages || f.r.waiting != nil {
				t.Fatalf("refresh reused old allocation or waiting collection: host=%d packages=%d", f.boundHost, f.boundPackages)
			}
			if tc.admitted && (len(f.superseded) != 1 || f.superseded[0] != oldSnapshot || f.manifest.GetSnapshotId() == oldSnapshot) {
				t.Fatal("fresh admission did not replace the already admitted old snapshot")
			}
		})
	}
}

func TestInventoryRefreshResumesDurableCollectionAtEveryPromotionBoundary(t *testing.T) {
	for _, tc := range []struct {
		name                                     string
		superseded, host, packages, acknowledged bool
		staleQueued, freshQueued                 bool
	}{
		{name: "queued-before-supersede"},
		{name: "superseded-before-promotion", superseded: true},
		{name: "host-promoted-package-queued", superseded: true, host: true},
		{name: "both-promoted", superseded: true, host: true, packages: true},
		{name: "host-acknowledged-package-queued", superseded: true, host: true, acknowledged: true},
		{name: "host-acknowledged-package-pending", superseded: true, host: true, packages: true, acknowledged: true},
		{name: "package-pending-with-unrelated-queued-host", superseded: true, host: true, packages: true, acknowledged: true, staleQueued: true},
		{name: "package-pending-with-newer-queued-host", superseded: true, host: true, packages: true, acknowledged: true, freshQueued: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRefreshTransportFixture(t)
			f.queue(refreshObservation(f.status.GetStartedAt().AsTime().Add(-time.Minute)))
			if _, err := f.r.store.PromoteHost(t.Context()); err != nil {
				t.Fatal(err)
			}
			if _, err := f.r.store.PromotePackage(t.Context()); err != nil {
				t.Fatal(err)
			}
			f.queue(refreshObservation(time.Now()))
			if tc.superseded {
				if err := f.r.store.SupersedeForRefresh(t.Context(), f.status.GetStartedAt().AsTime()); err != nil {
					t.Fatal(err)
				}
			}
			if tc.host {
				host, err := f.r.store.PromoteHost(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if tc.acknowledged {
					f.boundHost, f.host = host.Sequence, host.Sequence
					if err := f.r.store.AcknowledgeHost(t.Context(), host.Sequence, host.Sequence); err != nil {
						t.Fatal(err)
					}
				}
			}
			var manifest *devicev1.PackageSnapshotManifest
			if tc.packages {
				packages, err := f.r.store.PromotePackage(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				manifest = packages.Manifest
			}
			if tc.staleQueued {
				f.queue(refreshObservation(f.status.GetStartedAt().AsTime().Add(-time.Second)))
			}
			if tc.freshQueued {
				f.queue(refreshObservation(time.Now()))
			}
			f.reopen()
			if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err != nil {
				t.Fatal(err)
			}
			wantHostCalls := 1
			if tc.acknowledged && !tc.freshQueued {
				wantHostCalls = 0
			}
			if f.collections != 0 || f.hostCalls != wantHostCalls || f.beginCalls != 1 || f.staleUploads != 0 || f.confirmations != 1 || f.boundHost != 11 || f.boundPackages != 5 {
				t.Fatalf("durable resume recollected or uploaded the wrong tuple: collect=%d host=%d begin=%d stale=%d confirms=%d tuple=%d/%d", f.collections, f.hostCalls, f.beginCalls, f.staleUploads, f.confirmations, f.boundHost, f.boundPackages)
			}
			if manifest != nil && !proto.Equal(manifest, f.manifest) {
				t.Fatal("resume changed the immutable manifest")
			}
		})
	}
}

func TestInventoryRefreshRepairsMixedPendingCollections(t *testing.T) {
	for _, freshHost := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh-package-stale-host", true: "fresh-host-stale-package"}[freshHost], func(t *testing.T) {
			f := newRefreshTransportFixture(t)
			f.queue(refreshObservation(f.status.GetStartedAt().AsTime().Add(-time.Minute)))
			if freshHost {
				if _, err := f.r.store.PromotePackage(t.Context()); err != nil {
					t.Fatal(err)
				}
			} else if _, err := f.r.store.PromoteHost(t.Context()); err != nil {
				t.Fatal(err)
			}
			f.queue(refreshObservation(time.Now()))
			if freshHost {
				if _, err := f.r.store.PromoteHost(t.Context()); err != nil {
					t.Fatal(err)
				}
			} else if _, err := f.r.store.PromotePackage(t.Context()); err != nil {
				t.Fatal(err)
			}
			host, _, err := f.r.store.PendingHost(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			packages, _, err := f.r.store.PendingPackage(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err != nil {
				t.Fatal(err)
			}
			if freshHost {
				if f.boundHost != host.Sequence || f.boundPackages != packages.Sequence+1 {
					t.Fatal("mixed resume replaced the fresh host or reused the stale package sequence")
				}
			} else if f.boundHost != host.Sequence+1 || f.boundPackages != packages.Sequence || !proto.Equal(f.manifest, packages.Manifest) {
				t.Fatal("mixed resume replaced the fresh package or reused the stale host sequence")
			}
			if f.collections != 0 || f.hostCalls != 1 || f.beginCalls != 1 || f.staleUploads != 0 || f.confirmations != 1 {
				t.Fatal("mixed pending state recollected or flushed stale inventory")
			}
		})
	}
}

func TestInventoryRefreshCollectionFailureKeepsOldPending(t *testing.T) {
	for _, failure := range []string{"error", "cancel", "partial", "stale"} {
		t.Run(failure, func(t *testing.T) {
			f := newRefreshTransportFixture(t)
			f.queue(refreshObservation(f.status.GetStartedAt().AsTime().Add(-time.Minute)))
			host, err := f.r.store.PromoteHost(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			packages, err := f.r.store.PromotePackage(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			collectionErr := errors.New("native collection unavailable")
			f.r.collectInventory = func(context.Context) (*inventoryv1.NativeObservation, error) {
				f.collections++
				observation := refreshObservation(time.Now())
				switch failure {
				case "error":
					return nil, collectionErr
				case "cancel":
					cancel()
				case "partial":
					observation.Packages.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE
					observation.Packages.Packages = nil
				case "stale":
					observation = refreshObservation(f.status.GetStartedAt().AsTime().Add(-time.Second))
				}
				return observation, nil
			}
			err = f.r.refreshInventory(ctx, proto.CloneOf(f.status))
			if err == nil || failure == "error" && !errors.Is(err, collectionErr) || failure == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatalf("collection failure lost its error: %v", err)
			}
			keptHost, ok, err := f.r.store.PendingHost(t.Context())
			if err != nil || !ok || keptHost.Sequence != host.Sequence || !proto.Equal(keptHost.Observation, host.Observation) {
				t.Fatalf("collection failure discarded old host: %v", err)
			}
			keptPackages, ok, err := f.r.store.PendingPackage(t.Context())
			if err != nil || !ok || !proto.Equal(keptPackages.Manifest, packages.Manifest) {
				t.Fatalf("collection failure discarded old packages: %v", err)
			}
			if f.collections != 1 || f.hostCalls != 0 || f.beginCalls != 0 || f.confirmations != 0 {
				t.Fatal("failed collection uploaded or fabricated completion")
			}
		})
	}
}

func TestInventoryRefreshHostFailureResumesExactPendingTuple(t *testing.T) {
	f := newRefreshTransportFixture(t)
	f.hostErr = connect.NewError(connect.CodeResourceExhausted, errors.New("host admission temporarily unavailable"))
	f.failCommit = true
	if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err == nil {
		t.Fatal("failed host admission completed refresh")
	}
	host, ok, err := f.r.store.PendingHost(t.Context())
	if err != nil || !ok {
		t.Fatalf("host failure lost pending host: %v", err)
	}
	packages, ok, err := f.r.store.PendingPackage(t.Context())
	if err != nil || !ok || f.beginCalls != 1 || f.confirmations != 0 {
		t.Fatalf("host failure lost the partial package upload: %v", err)
	}
	f.reopen()
	f.hostErr = nil
	f.failCommit = false
	if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err != nil {
		t.Fatal(err)
	}
	if f.collections != 1 || f.boundHost != host.Sequence || !proto.Equal(f.manifest, packages.Manifest) || f.confirmations != 1 {
		t.Fatal("retry recollected or changed pending tuple")
	}
}

func TestInventoryRefreshNonpublicationErrorsNeverAuthorizeRecollection(t *testing.T) {
	for _, code := range []connect.Code{connect.CodeFailedPrecondition, connect.CodeUnavailable, connect.CodePermissionDenied, connect.CodeCanceled} {
		t.Run(code.String(), func(t *testing.T) {
			f := newRefreshTransportFixture(t)
			f.publicationErr = connect.NewError(code, errors.New("not the typed not-published response"))
			if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); connect.CodeOf(err) != code {
				t.Fatalf("publication failure was hidden: %v", err)
			}
			if f.collections != 0 || f.hostCalls != 0 || f.beginCalls != 0 || f.confirmations != 0 {
				t.Fatal("confirmation failure authorized another collection or completion")
			}
		})
	}
}

func TestInventoryRefreshTerminalSnapshotIsNotPublication(t *testing.T) {
	for _, state := range []inventoryv1.SnapshotState{inventoryv1.SnapshotState_SNAPSHOT_STATE_EXPIRED, inventoryv1.SnapshotState_SNAPSHOT_STATE_SUPERSEDED} {
		t.Run(state.String(), func(t *testing.T) {
			f := newRefreshTransportFixture(t)
			f.snapshotState = state
			if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); rpcreason.Get(err) != "inventory_refresh_not_published" {
				t.Fatalf("terminal nonpublication accepted or lost its error: %v", err)
			}
			if f.batches != 0 || f.committed || f.confirmations != 0 {
				t.Fatal("expired or superseded inventory fabricated a publication receipt")
			}
		})
	}
}

func TestInventoryRefreshRecoversPublishedReceiptWithoutLocalPending(t *testing.T) {
	for _, executorFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "server-confirmation-lost", true: "executor-confirmation-lost"}[executorFailure], func(t *testing.T) {
			f := newRefreshTransportFixture(t)
			f.failPublication = !executorFailure
			f.failExecutorConfirmation = executorFailure
			if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err == nil {
				t.Fatal("lost confirmation succeeded")
			}
			if !f.committed || f.confirmations != 0 || f.status.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING {
				t.Fatal("lost confirmation fabricated protected completion")
			}
			if _, ok, err := f.r.store.PendingHost(t.Context()); err != nil || ok {
				t.Fatalf("test did not reach acknowledged host boundary: %v", err)
			}
			if _, ok, err := f.r.store.PendingPackage(t.Context()); err != nil || ok {
				t.Fatalf("test did not reach acknowledged package boundary: %v", err)
			}
			f.reopen()
			// Later routine inventory must not change the action's receipt tuple.
			f.host += 5
			f.packages += 5
			f.failPublication, f.failExecutorConfirmation = false, false
			if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err != nil {
				t.Fatal(err)
			}
			if f.collections != 1 || f.hostCalls != 1 || f.beginCalls != 1 || f.batches != 1 || f.confirmations != 1 || f.status.GetVerification().GetInventorySequence() != f.boundPackages {
				t.Fatal("receipt recovery recollected, republished or used global high-water instead of the action binding")
			}
		})
	}
}

func TestInventoryRefreshIncompleteSameActionPendingNeverRecollects(t *testing.T) {
	for _, failedPackage := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing-package", true: "failed-package"}[failedPackage], func(t *testing.T) {
			f := newRefreshTransportFixture(t)
			observation := refreshObservation(time.Now())
			if failedPackage {
				observation.Packages.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE
				observation.Packages.Packages = nil
			}
			f.queue(observation)
			if _, err := f.r.store.PromoteHost(t.Context()); err != nil {
				t.Fatal(err)
			}
			packages, err := f.r.store.PromotePackage(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if !failedPackage {
				if err := f.r.store.FinishPackage(t.Context(), packages.Sequence, f.packages, spool.TerminalExpired); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err == nil {
				t.Fatal("incomplete pending inventory completed refresh")
			}
			if f.collections != 0 || f.hostCalls != 1 || f.beginCalls != 0 || f.confirmations != 0 {
				t.Fatal("incomplete same-action pending was recollected or confirmed without its missing full package receipt")
			}
		})
	}
}

func TestInventoryRefreshPackageWithoutBoundHostNeverConfirms(t *testing.T) {
	f := newRefreshTransportFixture(t)
	f.queue(refreshObservation(time.Now()))
	host, err := f.r.store.PromoteHost(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.r.store.PromotePackage(t.Context()); err != nil {
		t.Fatal(err)
	}
	// A local/global host acknowledgement is not an action-bound receipt.
	f.host = host.Sequence
	if err := f.r.store.AcknowledgeHost(t.Context(), host.Sequence, f.host); err != nil {
		t.Fatal(err)
	}
	f.queue(refreshObservation(f.status.GetStartedAt().AsTime().Add(-time.Second)))
	if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); rpcreason.Get(err) != "inventory_refresh_not_published" {
		t.Fatalf("package-only tuple was accepted without the bound host: %v", err)
	}
	if f.collections != 0 || f.hostCalls != 0 || f.staleUploads != 0 || !f.committed || f.confirmations != 0 {
		t.Fatal("package-only resume uploaded stale host or fabricated completion from global high-water")
	}
}

func TestInventoryRefreshResumesAfterPeriodicPartialUploadFollowingRestart(t *testing.T) {
	for _, staleHost := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh-host-acked-stale-package", true: "fresh-package-acked-stale-host"}[staleHost], func(t *testing.T) {
			f := newRefreshTransportFixture(t)
			f.queue(refreshObservation(f.status.GetStartedAt().AsTime().Add(-time.Minute)))
			if staleHost {
				if _, err := f.r.store.PromoteHost(t.Context()); err != nil {
					t.Fatal(err)
				}
			} else if _, err := f.r.store.PromotePackage(t.Context()); err != nil {
				t.Fatal(err)
			}
			// The full refresh reached durable Queue, but the process exited
			// before Supersede. Startup's ordinary cycle can acknowledge one
			// fresh domain while the older opposite domain stays rate blocked.
			f.queue(refreshObservation(time.Now()))
			f.reopen()
			if err := f.r.store.Synchronize(t.Context(), f.host, f.packages); err != nil {
				t.Fatal(err)
			}
			authority := &authorized{connection: f.connection, servers: f.r.cache.servers, epoch: f.connection.GetSessionEpoch()}
			if err := flush(t.Context(), f.r.store, authority, f.r.status); connect.CodeOf(err) != connect.CodeResourceExhausted {
				t.Fatalf("test did not reach ordinary partial acknowledgement: %v", err)
			}
			if f.staleUploads != 1 {
				t.Fatal("ordinary cycle did not leave exactly one rate-blocked old domain")
			}
			if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err != nil {
				t.Fatal(err)
			}
			wantHost, wantPackages := uint64(10), uint64(5)
			if staleHost {
				wantHost, wantPackages = 11, 4
			}
			if f.collections != 0 || f.staleUploads != 1 || f.batches != 1 || f.confirmations != 1 || f.boundHost != wantHost || f.boundPackages != wantPackages {
				t.Fatalf("resume failed after ordinary partial receipt: collect=%d stale=%d batches=%d confirms=%d tuple=%d/%d", f.collections, f.staleUploads, f.batches, f.confirmations, f.boundHost, f.boundPackages)
			}
		})
	}
}

func TestInventoryRefreshMissingQueuedCounterpartDoesNotFlushOldPending(t *testing.T) {
	for _, staleHost := range []bool{false, true} {
		t.Run(map[bool]string{false: "stale-package", true: "stale-host"}[staleHost], func(t *testing.T) {
			f := newRefreshTransportFixture(t)
			old := refreshObservation(f.status.GetStartedAt().AsTime().Add(-time.Minute))
			f.queue(old)
			if staleHost {
				if _, err := f.r.store.PromoteHost(t.Context()); err != nil {
					t.Fatal(err)
				}
			} else if _, err := f.r.store.PromotePackage(t.Context()); err != nil {
				t.Fatal(err)
			}
			f.queue(refreshObservation(time.Now()))
			if staleHost {
				if _, err := f.r.store.PromotePackage(t.Context()); err != nil {
					t.Fatal(err)
				}
			} else if _, err := f.r.store.PromoteHost(t.Context()); err != nil {
				t.Fatal(err)
			}
			// A stale queued replacement is not evidence for discarding the
			// old pending domain, even when the other fresh half can upload.
			f.queue(old)
			if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); rpcreason.Get(err) != "inventory_refresh_not_published" {
				t.Fatalf("missing fresh counterpart satisfied refresh: %v", err)
			}
			if f.collections != 0 || f.staleUploads != 0 || f.confirmations != 0 {
				t.Fatal("missing counterpart recollected, flushed stale bytes or fabricated a receipt")
			}
			if staleHost {
				host, ok, err := f.r.store.PendingHost(t.Context())
				if err != nil || !ok || !proto.Equal(host.Observation, old.Host) {
					t.Fatalf("missing counterpart discarded the old host: %v", err)
				}
			} else {
				packages, ok, err := f.r.store.PendingPackage(t.Context())
				if err != nil || !ok || !packages.StartedAt.Equal(old.Packages.GetStartedAt().AsTime()) {
					t.Fatalf("missing counterpart discarded the old packages: %v", err)
				}
			}
		})
	}
}

func TestInventoryRefreshDoesNotMistakeFailedRoutineQueueForAcknowledgedPackages(t *testing.T) {
	f := newRefreshTransportFixture(t)
	observation := refreshObservation(time.Now())
	observation.Packages.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE
	observation.Packages.Packages = nil
	f.queue(observation)
	if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err != nil {
		t.Fatal(err)
	}
	if f.collections != 1 || f.batches != 1 || f.staleUploads != 0 || f.confirmations != 1 {
		t.Fatal("failed routine queue was mistaken for an already acknowledged full refresh")
	}
}
