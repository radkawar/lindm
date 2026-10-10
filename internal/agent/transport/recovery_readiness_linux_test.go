//go:build linux

package transport

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func (e *refreshTransportExecutor) GetRecoveryReadiness(context.Context, *connect.Request[agentv1.GetRecoveryReadinessRequest]) (*connect.Response[agentv1.GetRecoveryReadinessResponse], error) {
	e.f.readinessCalls++
	if e.f.readinessErr != nil {
		return nil, e.f.readinessErr
	}
	observation := proto.CloneOf(e.f.readiness)
	observation.ObservedAt = timestamppb.Now()
	storage, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&inventoryv1.StorageDetails{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS})
	if err != nil {
		e.f.t.Fatal(err)
	}
	return connect.NewResponse(&agentv1.GetRecoveryReadinessResponse{Observation: observation, StorageDetails: storage, StorageObservedAt: timestamppb.Now()}), nil
}

func unavailableNativeDetails() *inventoryv1.NativeDetails {
	const unavailable = inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE
	text := func() *inventoryv1.ObservedString { return &inventoryv1.ObservedString{Status: unavailable} }
	number := func() *inventoryv1.ObservedUint64 { return &inventoryv1.ObservedUint64{Status: unavailable} }
	boolean := func() *inventoryv1.ObservedBool { return &inventoryv1.ObservedBool{Status: unavailable} }
	return &inventoryv1.NativeDetails{
		Cpu:     &inventoryv1.CpuDetails{Model: text(), LogicalCores: number(), PhysicalCores: number(), X86_64Level: text()},
		Memory:  &inventoryv1.MemoryDetails{TotalBytes: number(), AvailableBytes: number(), SwapTotalBytes: number()},
		Storage: &inventoryv1.StorageDetails{Status: unavailable}, Network: &inventoryv1.NetworkDetails{Status: unavailable},
		Firmware: &inventoryv1.FirmwareDetails{Mode: text(), SecureBoot: text()}, Tpm: &inventoryv1.TpmDetails{Present: boolean(), Version: text()},
		Power:    &inventoryv1.PowerDetails{Chassis: text(), Batteries: &inventoryv1.BatteryDetails{Status: unavailable}},
		Sessions: &inventoryv1.SessionCounts{Users: number(), Sessions: number()}, LocalUsers: &inventoryv1.LocalUsers{Status: unavailable},
		KernelModuleCount: number(), UptimeSeconds: number(), BootTimeUnixSeconds: number(),
		Backends: &inventoryv1.BackendDetails{Dpkg: boolean(), Rpm: boolean(), Pacman: boolean(), Zypper: boolean(), RpmOstree: boolean(), Nix: boolean(), Flatpak: boolean(), Snap: boolean()},
		Flatpak:  &inventoryv1.ApplicationDetails{Status: unavailable}, Snap: &inventoryv1.ApplicationDetails{Status: unavailable},
	}
}

func TestPeriodicInventoryQueuesImmutableProtectedReadiness(t *testing.T) {
	f := newRefreshTransportFixture(t)
	if err := f.r.bind(t.Context(), f.connection); err != nil {
		t.Fatal(err)
	}
	if err := f.r.store.Synchronize(t.Context(), f.host, f.packages); err != nil {
		t.Fatal(err)
	}
	if err := f.r.collect(t.Context()); err != nil {
		t.Fatal(err)
	}
	upload, err := f.r.store.PromoteHost(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	got := upload.Observation.GetDetails().GetRecoveryReadiness()
	if !got.GetAvailable() || got.GetEspUuid() != "1234-5678" || got.GetFreeBytes() != 16384 || got.GetBootId() != f.boot || f.readinessCalls != 1 {
		t.Fatalf("periodic spool omitted protected readiness: %v", got)
	}
	if upload.Observation.GetDetails().GetStorage().GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS {
		t.Fatal("root storage observation did not replace unprivileged unavailable storage")
	}
	f.readiness.FreeBytes = 0
	if err := f.r.collect(t.Context()); err != nil {
		t.Fatal(err)
	}
	pending, ok, err := f.r.store.PendingHost(t.Context())
	if err != nil || !ok || !proto.Equal(pending.Observation, upload.Observation) {
		t.Fatalf("new observation changed immutable pending evidence: %v", err)
	}
	if f.readinessCalls != 2 {
		t.Fatal("second collection reused readiness")
	}
}

func TestExplicitRefreshPublishesProtectedReadiness(t *testing.T) {
	f := newRefreshTransportFixture(t)
	if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err != nil {
		t.Fatal(err)
	}
	got := f.publishedHost.GetDetails().GetRecoveryReadiness()
	if !got.GetAvailable() || got.GetFreeBytes() != 16384 || got.GetBootId() != f.boot || f.readinessCalls != 1 || f.confirmations != 1 {
		t.Fatalf("refresh completion omitted root observation: %v", got)
	}
}

func TestReadinessFailureDoesNotFailInventoryPublication(t *testing.T) {
	for _, reason := range []string{"recovery_readiness_not_configured", "recovery_readiness_esp_unreadable", "recovery_readiness_esp_unsupported", "recovery_readiness_executor_unavailable"} {
		t.Run(reason, func(t *testing.T) {
			f := newRefreshTransportFixture(t)
			f.readiness.Available = false
			f.readiness.Reason = reason
			if reason == "recovery_readiness_executor_unavailable" {
				f.readinessErr = errors.New("root RPC unavailable")
			}
			if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err != nil {
				t.Fatal(err)
			}
			got := f.publishedHost.GetDetails().GetRecoveryReadiness()
			if got.GetAvailable() || got.GetReason() != reason || f.confirmations != 1 {
				t.Fatalf("failed observation blocked inventory or implied readiness: %v", got)
			}
		})
	}
}

func TestDirectCollectorDoesNotInventReadiness(t *testing.T) {
	f := newRefreshTransportFixture(t)
	observation, err := f.r.collectInventory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if observation.GetHost().GetDetails().GetRecoveryReadiness() != nil || f.readinessCalls != 0 {
		t.Fatal("direct unprivileged collection claimed protected readiness")
	}
}

type invalidReadinessExecutor struct {
	*refreshTransportExecutor
	mutate func(*agentv1.GetRecoveryReadinessResponse)
}

func (e invalidReadinessExecutor) GetRecoveryReadiness(ctx context.Context, req *connect.Request[agentv1.GetRecoveryReadinessRequest]) (*connect.Response[agentv1.GetRecoveryReadinessResponse], error) {
	response, err := e.refreshTransportExecutor.GetRecoveryReadiness(ctx, req)
	if err == nil {
		e.mutate(response.Msg)
	}
	return response, err
}

func TestProtectedObservationRejectsMalformedOrStaleRootResponse(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*agentv1.GetRecoveryReadinessResponse)
	}{
		{name: "malformed_storage", mutate: func(r *agentv1.GetRecoveryReadinessResponse) { r.StorageDetails = []byte{0xff} }},
		{name: "unknown_storage_fields", mutate: func(r *agentv1.GetRecoveryReadinessResponse) {
			r.StorageDetails = append(r.StorageDetails, 0x98, 0x06, 0x01)
		}},
		{name: "invalid_storage_status", mutate: func(r *agentv1.GetRecoveryReadinessResponse) { r.StorageDetails = []byte{0x08, 0x00} }},
		{name: "changed_boot", mutate: func(r *agentv1.GetRecoveryReadinessResponse) {
			r.Observation.BootId = "794aa3f7-f271-4489-ad95-cd5954ad3426"
		}},
		{name: "stale_readiness", mutate: func(r *agentv1.GetRecoveryReadinessResponse) {
			r.Observation.ObservedAt = timestamppb.New(time.Now().Add(-time.Hour))
		}},
		{name: "future_storage", mutate: func(r *agentv1.GetRecoveryReadinessResponse) {
			r.StorageObservedAt = timestamppb.New(time.Now().Add(time.Hour))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRefreshTransportFixture(t)
			f.r.executor = invalidReadinessExecutor{refreshTransportExecutor: &refreshTransportExecutor{f: f}, mutate: tc.mutate}
			if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err != nil {
				t.Fatal(err)
			}
			details := f.publishedHost.GetDetails()
			if details.GetRecoveryReadiness().GetAvailable() || details.GetRecoveryReadiness().GetReason() == "" || details.GetStorage().GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE {
				t.Fatal("malformed root response became available native evidence")
			}
		})
	}
}
