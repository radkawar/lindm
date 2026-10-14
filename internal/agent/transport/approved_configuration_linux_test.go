// SPDX-License-Identifier: Apache-2.0

//go:build linux

package transport

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func (e *refreshTransportExecutor) GetApprovedConfiguration(context.Context, *connect.Request[agentv1.GetApprovedConfigurationRequest]) (*connect.Response[agentv1.GetApprovedConfigurationResponse], error) {
	e.f.approvedCalls++
	if e.f.approvedErr != nil {
		return nil, e.f.approvedErr
	}
	if e.f.approvedResponse != nil {
		return connect.NewResponse(proto.CloneOf(e.f.approvedResponse)), nil
	}
	return connect.NewResponse(&agentv1.GetApprovedConfigurationResponse{Observation: &agentv1.ApprovedConfigurationObservation{ObservedAt: timestamppb.Now()}}), nil
}

func approvedHomeRoots() *agentv1.ApprovedConfigurationObservation {
	return &agentv1.ApprovedConfigurationObservation{
		ObservedAt: timestamppb.Now(),
		HomeRoots:  []*agentv1.NativeApprovedHomeRoot{{RootId: uuid.NewString(), Path: "/home"}},
	}
}

func TestInventoryPublishesExecutorApprovedConfigurationUnmodified(t *testing.T) {
	f := newRefreshTransportFixture(t)
	want := approvedHomeRoots()
	f.approvedResponse = &agentv1.GetApprovedConfigurationResponse{Observation: want}
	if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err != nil {
		t.Fatal(err)
	}
	if got := f.publishedHost.GetDetails().GetApprovedConfiguration(); !proto.Equal(got, want) || f.approvedCalls != 1 {
		t.Fatalf("published approved configuration = %v, want executor report", got)
	}
}

func TestApprovedConfigurationFailureLeavesNoReport(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(*refreshTransportFixture)
	}{
		{name: "executor_error", prepare: func(f *refreshTransportFixture) { f.approvedErr = errors.New("root RPC unavailable") }},
		{name: "missing_observation", prepare: func(f *refreshTransportFixture) {
			f.approvedResponse = &agentv1.GetApprovedConfigurationResponse{}
		}},
		{name: "invalid_root", prepare: func(f *refreshTransportFixture) {
			observation := approvedHomeRoots()
			observation.HomeRoots[0].Path = "/home/../etc"
			f.approvedResponse = &agentv1.GetApprovedConfigurationResponse{Observation: observation}
		}},
		{name: "unknown_fields", prepare: func(f *refreshTransportFixture) {
			observation := approvedHomeRoots()
			observation.ProtoReflect().SetUnknown([]byte{0xf8, 0x3f, 0x01})
			f.approvedResponse = &agentv1.GetApprovedConfigurationResponse{Observation: observation}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRefreshTransportFixture(t)
			tc.prepare(f)
			if err := f.r.refreshInventory(t.Context(), proto.CloneOf(f.status)); err != nil {
				t.Fatal(err)
			}
			if got := f.publishedHost.GetDetails().GetApprovedConfiguration(); got != nil || f.confirmations != 1 {
				t.Fatalf("approved configuration failure published %v or blocked inventory", got)
			}
		})
	}
}

func TestDirectCollectorDoesNotInventApprovedConfiguration(t *testing.T) {
	f := newRefreshTransportFixture(t)
	observation, err := f.r.collectInventory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if observation.GetHost().GetDetails().GetApprovedConfiguration() != nil || f.approvedCalls != 0 {
		t.Fatal("direct unprivileged collection claimed protected approved configuration")
	}
}
