//go:build linux

package transport

import (
	"context"
	"errors"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func (e *refreshTransportExecutor) GetPatchStatus(context.Context, *connect.Request[agentv1.GetPatchStatusRequest]) (*connect.Response[agentv1.GetPatchStatusResponse], error) {
	e.f.patchStatusCalls++
	if e.f.patchStatusErr != nil {
		return nil, e.f.patchStatusErr
	}
	if e.f.patchStatusResponse != nil {
		return connect.NewResponse(proto.CloneOf(e.f.patchStatusResponse)), nil
	}
	observation := proto.CloneOf(e.f.patchStatus)
	if observation == nil {
		observation = &agentv1.PatchStatusObservation{ObservedAt: timestamppb.Now(), BootId: e.f.boot, Reason: "patch_status_not_computed"}
	}
	return connect.NewResponse(&agentv1.GetPatchStatusResponse{Observation: observation}), nil
}

func availablePatchStatus(boot string) *agentv1.PatchStatusObservation {
	observed := time.Now().Add(-time.Minute)
	return &agentv1.PatchStatusObservation{
		ObservedAt: timestamppb.New(observed), BootId: boot, Available: true,
		Backend:                resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF5_AUTOMATIC,
		PendingSecurityUpdates: 1, PendingUpdates: 4, RebootRequired: true,
		MetadataRefreshedAt: timestamppb.New(observed.Add(-time.Hour)), PolicyInstalled: true,
	}
}

func TestInventoryPublishesExecutorPatchStatusUnmodified(t *testing.T) {
	f := newRefreshTransportFixture(t)
	f.patchStatus = availablePatchStatus(f.boot)
	if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err != nil {
		t.Fatal(err)
	}
	if got := f.publishedHost.GetDetails().GetPatchStatus(); !proto.Equal(got, f.patchStatus) || f.patchStatusCalls != 1 {
		t.Fatalf("published patch status = %v, want executor status", got)
	}
}

func TestPatchStatusFailureDoesNotBlockInventory(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(*refreshTransportFixture)
		reason  string
	}{
		{name: "executor_error", reason: "executor_unavailable", prepare: func(f *refreshTransportFixture) {
			f.patchStatusErr = errors.New("root RPC unavailable")
		}},
		{name: "missing_observation", reason: "patch_status_invalid", prepare: func(f *refreshTransportFixture) {
			f.patchStatusResponse = &agentv1.GetPatchStatusResponse{}
		}},
		{name: "invalid_observation", reason: "patch_status_invalid", prepare: func(f *refreshTransportFixture) {
			observation := availablePatchStatus(f.boot)
			observation.BootId = ""
			f.patchStatusResponse = &agentv1.GetPatchStatusResponse{Observation: observation}
		}},
		{name: "unknown_fields", reason: "patch_status_invalid", prepare: func(f *refreshTransportFixture) {
			observation := availablePatchStatus(f.boot)
			observation.ProtoReflect().SetUnknown([]byte{0xf8, 0x3f, 0x01})
			f.patchStatusResponse = &agentv1.GetPatchStatusResponse{Observation: observation}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRefreshTransportFixture(t)
			tc.prepare(f)
			if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err != nil {
				t.Fatal(err)
			}
			got := f.publishedHost.GetDetails().GetPatchStatus()
			if got.GetAvailable() || got.GetReason() != tc.reason || got.GetBootId() != f.boot || f.confirmations != 1 {
				t.Fatalf("patch status failure blocked inventory or implied status: %v", got)
			}
			if err := protovalidate.Validate(got); err != nil {
				t.Fatalf("failure status cannot be published: %v", err)
			}
			if !f.publishedHost.GetDetails().GetRecoveryReadiness().GetAvailable() {
				t.Fatal("patch status failure suppressed independent recovery readiness")
			}
		})
	}
}

func TestDirectCollectorDoesNotInventPatchStatus(t *testing.T) {
	f := newRefreshTransportFixture(t)
	observation, err := f.r.collectInventory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if observation.GetHost().GetDetails().GetPatchStatus() != nil || f.patchStatusCalls != 0 {
		t.Fatal("direct unprivileged collection claimed protected patch status")
	}
}
