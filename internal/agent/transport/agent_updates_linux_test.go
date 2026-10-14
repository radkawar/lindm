// SPDX-License-Identifier: Apache-2.0

//go:build linux

package transport

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/gen/lindm/device/v1/devicev1connect"
)

func TestHeartbeatReportsRootUpdateAfterLostResponseAndRestart(t *testing.T) {
	f := newRefreshTransportFixture(t)
	root := &updateHeartbeatRoot{refreshTransportExecutor: &refreshTransportExecutor{f: f}, status: &agentv1.AgentUpdateStatus{Enabled: true, Phase: "recovery_required", ObservedAt: timestamppb.Now(), NativeDiagnostic: &agentv1.NativeUpdateDiagnostic{Manager: "apt-get", Phase: "simulate", ExitCode: 100, ErrorLines: []string{"E: package dependency failure"}}}}
	server := &updateHeartbeatServer{loseResponse: true}
	sync := func() error {
		// A fresh cache/gate models network process restart, with no cached success
		// or in-memory acknowledgement to determine whether status is delivered.
		cache := &connectionCache{connection: proto.CloneOf(f.connection), servers: &connections{device: server}}
		_, err := synchronize(t.Context(), root, cache, make(authorityGate, 1))
		return err
	}
	if err := sync(); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("lost response not propagated: %v", err)
	}
	if err := sync(); err != nil {
		t.Fatal(err)
	}
	if root.reads != 2 || len(server.reports) != 2 {
		t.Fatal("restart did not reread and redeliver executor status")
	}
	for _, report := range server.reports {
		if report.GetSessionEpoch() != 1 || !proto.Equal(report.GetAgentUpdate(), root.status) {
			t.Fatalf("heartbeat changed root diagnostic or session: %v", report)
		}
	}
	root.status = nil
	if err := sync(); err != nil {
		t.Fatal(err)
	}
	if server.reports[2].GetAgentUpdate() != nil {
		t.Fatal("missing root status became fabricated healthy state")
	}
	root.readErr = errors.New("executor unavailable")
	if err := sync(); err == nil || len(server.reports) != 3 {
		t.Fatal("failed root read sent fabricated status")
	}
}

type updateHeartbeatRoot struct {
	*refreshTransportExecutor
	status  *agentv1.AgentUpdateStatus
	readErr error
	reads   int
}

func (r *updateHeartbeatRoot) GetAgentUpdate(context.Context, *connect.Request[agentv1.GetAgentUpdateRequest]) (*connect.Response[agentv1.GetAgentUpdateResponse], error) {
	r.reads++
	if r.readErr != nil {
		return nil, r.readErr
	}
	return connect.NewResponse(&agentv1.GetAgentUpdateResponse{Status: proto.CloneOf(r.status)}), nil
}

type updateHeartbeatServer struct {
	devicev1connect.DeviceServiceClient
	reports      []*devicev1.GetSyncStateRequest
	loseResponse bool
}

func (s *updateHeartbeatServer) GetSyncState(_ context.Context, req *connect.Request[devicev1.GetSyncStateRequest]) (*connect.Response[devicev1.GetSyncStateResponse], error) {
	s.reports = append(s.reports, proto.CloneOf(req.Msg))
	if s.loseResponse {
		s.loseResponse = false
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("response lost after server receipt"))
	}
	return connect.NewResponse(&devicev1.GetSyncStateResponse{SessionEpoch: 1, ServerTime: timestamppb.Now()}), nil
}
