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
	"lindm/gen/lindm/agent/v1/agentv1connect"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/gen/lindm/device/v1/devicev1connect"
)

const assistanceTestSession = "5a7df67f-8c0c-4404-95a0-828d7e3a1989"

// The relay hands each server response to the root exactly once, so a failed
// server exchange can never refresh the root's reauthorization window.
func TestAssistanceRelayDeliversDirectivesOnce(t *testing.T) {
	root := &assistanceRoot{}
	server := &assistanceServer{directives: []*agentv1.AssistanceDirective{assistanceTestDirective(false)}}
	loop := &assistanceLoop{
		executor: root, gate: make(authorityGate, 1),
		cache: connectionCache{connection: proto.CloneOf(root.connection()), servers: &connections{device: server}},
	}
	if err := loop.cycle(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(root.received[0]) != 0 || loop.delay() != assistanceActiveInterval {
		t.Fatalf("first cycle: received=%v delay=%v", root.received[0], loop.delay())
	}
	root.reports = []*agentv1.AssistanceReport{{SessionId: assistanceTestSession, Phase: agentv1.AssistancePhase_ASSISTANCE_PHASE_PENDING}}
	server.fail = true
	if err := loop.cycle(t.Context()); err == nil {
		t.Fatal("server failure reported success")
	}
	if len(root.received[1]) != 1 || root.received[1][0].GetInvitation().GetSessionId() != assistanceTestSession {
		t.Fatalf("second cycle delivered %v", root.received[1])
	}
	if !proto.Equal(server.reports[1][0], root.reports[0]) || server.epochs[1] != 1 {
		t.Fatalf("server received reports=%v epoch=%d", server.reports[1], server.epochs[1])
	}
	if loop.delay() != assistanceActiveInterval {
		t.Fatal("open executor report did not keep the active cadence")
	}
	if err := loop.cycle(t.Context()); err == nil {
		t.Fatal("server failure reported success")
	}
	if len(root.received[2]) != 0 {
		t.Fatalf("stale directives were replayed after a failed server exchange: %v", root.received[2])
	}
	root.reports = []*agentv1.AssistanceReport{{SessionId: assistanceTestSession, Phase: agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED, EndCause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED}}
	server.fail = false
	server.directives = []*agentv1.AssistanceDirective{assistanceTestDirective(true)}
	if err := loop.cycle(t.Context()); err != nil {
		t.Fatal(err)
	}
	for range 50 {
		if delay := loop.delay(); delay < assistanceIdleInterval*9/10 || delay >= assistanceIdleInterval*11/10 {
			t.Fatalf("idle delay %v outside 15s ±10%%", delay)
		}
	}
}

func assistanceTestDirective(terminate bool) *agentv1.AssistanceDirective {
	now := time.Now()
	return &agentv1.AssistanceDirective{
		Invitation: &agentv1.AssistanceInvitation{
			SessionId: assistanceTestSession, Mode: agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, Reason: "help", OperatorDisplay: "Operator",
			ConsentDeadline: timestamppb.New(now.Add(2 * time.Minute)), EndsAt: timestamppb.New(now.Add(30 * time.Minute)),
			IceServers: []*agentv1.AssistanceIceServer{{Urls: []string{"turn:relay.example:3478"}, Username: "1:s:device", Credential: "c"}},
		},
		Terminate: terminate,
	}
}

type assistanceRoot struct {
	agentv1connect.ExecutorServiceClient
	received [][]*agentv1.AssistanceDirective
	reports  []*agentv1.AssistanceReport
}

func (r *assistanceRoot) connection() *agentv1.GetConnectionResponse {
	return &agentv1.GetConnectionResponse{SessionEpoch: 1, SessionEpochUsable: true, RenewAfter: timestamppb.New(time.Now().Add(time.Hour))}
}

func (r *assistanceRoot) GetConnection(context.Context, *connect.Request[agentv1.GetConnectionRequest]) (*connect.Response[agentv1.GetConnectionResponse], error) {
	return connect.NewResponse(r.connection()), nil
}

func (*assistanceRoot) PrepareSession(context.Context, *connect.Request[agentv1.PrepareSessionRequest]) (*connect.Response[agentv1.PrepareSessionResponse], error) {
	return connect.NewResponse(&agentv1.PrepareSessionResponse{Result: &agentv1.PrepareSessionResponse_Accepted{Accepted: &agentv1.AcceptedSession{SessionEpoch: 1}}}), nil
}

func (r *assistanceRoot) SyncAssistance(_ context.Context, req *connect.Request[agentv1.SyncAssistanceRequest]) (*connect.Response[agentv1.SyncAssistanceResponse], error) {
	r.received = append(r.received, req.Msg.GetDirectives())
	return connect.NewResponse(&agentv1.SyncAssistanceResponse{Reports: r.reports}), nil
}

type assistanceServer struct {
	devicev1connect.DeviceServiceClient
	directives []*agentv1.AssistanceDirective
	fail       bool
	reports    [][]*agentv1.AssistanceReport
	epochs     []uint64
}

func (s *assistanceServer) SyncAssistance(_ context.Context, req *connect.Request[devicev1.SyncAssistanceRequest]) (*connect.Response[devicev1.SyncAssistanceResponse], error) {
	s.reports = append(s.reports, req.Msg.GetReports())
	s.epochs = append(s.epochs, req.Msg.GetSessionEpoch())
	if s.fail {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("unavailable"))
	}
	return connect.NewResponse(&devicev1.SyncAssistanceResponse{Directives: s.directives}), nil
}
