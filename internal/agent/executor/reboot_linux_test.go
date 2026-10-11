//go:build linux

package executor

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/osupdate"
)

func TestEmployeeSessionEnabledForEveryRebootEntryPoint(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want bool
	}{
		{name: "disabled"},
		{name: "assistance", cfg: Config{RemoteAssistance: &agentv1.RemoteAssistanceConfig{Enabled: true}}, want: true},
		{name: "scheduled updates", cfg: Config{NativeResources: NativeResourceProviders{OSUpdate: &agentv1.NativeOSUpdateProviderConfig{Enabled: true}}}, want: true},
		{name: "patch now only", cfg: Config{ActionProviderConfig: &agentv1.DeviceActionProviderConfig{AllowPatchNow: true}}, want: true},
		{name: "patch now disabled", cfg: Config{ActionProviderConfig: &agentv1.DeviceActionProviderConfig{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.sessionEnabled(); got != tc.want {
				t.Fatalf("employee session enabled=%v, want %v", got, tc.want)
			}
		})
	}
}

type rebootSessionFixture struct {
	notice   *agentv1.OSUpdateRebootNotice
	requests []*agentv1.OSUpdateRebootDeferralRequest
	err      error
}

func (f *rebootSessionFixture) SessionReboot(_ context.Context, request *agentv1.OSUpdateRebootDeferralRequest) (*agentv1.OSUpdateRebootNotice, error) {
	f.requests = append(f.requests, proto.CloneOf(request))
	return proto.CloneOf(f.notice), f.err
}

func TestRebootPromptBoundToUserSessionAndAssistanceEpoch(t *testing.T) {
	f := newAssistanceFixture(t, false)
	provider := &rebootSessionFixture{notice: &agentv1.OSUpdateRebootNotice{ScheduleId: uuid.NewString(), ScheduledFor: timestamppb.New(f.clock())}}
	h := &sessionService{broker: f.broker, reboots: provider}
	response := &agentv1.SyncSessionResponse{LocalSession: &agentv1.AssistanceLocalSession{Uid: 1000, LogindSessionId: "2"}}
	if err := h.syncReboot(t.Context(), 1000, &agentv1.SyncSessionRequest{}, response); err != nil {
		t.Fatal(err)
	}
	token := response.GetReboot().GetScheduleId()
	if token == provider.notice.GetScheduleId() {
		t.Fatal("exposed reusable native schedule identity")
	}
	request := &agentv1.SyncSessionRequest{RebootDeferral: &agentv1.OSUpdateRebootDeferralRequest{ScheduleId: token, RequestId: uuid.NewString(), ScheduledFor: response.GetReboot().GetScheduledFor()}}
	if err := h.syncReboot(t.Context(), 1000, request, response); err != nil {
		t.Fatal(err)
	}
	if got := provider.requests[len(provider.requests)-1]; got.GetScheduleId() != provider.notice.GetScheduleId() {
		t.Fatal("authorized prompt did not bind exact native schedule")
	}
	for _, change := range []func(){
		func() { response.LocalSession.LogindSessionId = "other" },
		func() { response.LocalSession.LogindSessionId = "2"; f.broker.rebootEpoch++ },
	} {
		change()
		if err := h.syncReboot(t.Context(), 1000, request, response); err != nil {
			t.Fatal(err)
		}
		if provider.requests[len(provider.requests)-1] != nil {
			t.Fatal("stale prompt retained authority after local/remote session change")
		}
	}
	if err := h.syncReboot(t.Context(), 1001, request, &agentv1.SyncSessionResponse{LocalSession: &agentv1.AssistanceLocalSession{Uid: 1001, LogindSessionId: "3"}}); err != nil {
		t.Fatal(err)
	}
	if provider.requests[len(provider.requests)-1] != nil {
		t.Fatal("another user reused prompt")
	}
}

func TestRebootDeferralCannotRacePendingAssistance(t *testing.T) {
	f := newAssistanceFixture(t, true)
	provider := &rebootSessionFixture{notice: &agentv1.OSUpdateRebootNotice{ScheduleId: uuid.NewString(), ScheduledFor: timestamppb.New(f.clock())}}
	h := &sessionService{broker: f.broker, reboots: provider}
	response := &agentv1.SyncSessionResponse{LocalSession: &agentv1.AssistanceLocalSession{Uid: 1000, LogindSessionId: "2"}}
	if err := h.syncReboot(t.Context(), 1000, &agentv1.SyncSessionRequest{}, response); err != nil {
		t.Fatal(err)
	}
	request := &agentv1.SyncSessionRequest{RebootDeferral: &agentv1.OSUpdateRebootDeferralRequest{ScheduleId: response.GetReboot().GetScheduleId(), RequestId: uuid.NewString(), ScheduledFor: response.GetReboot().GetScheduledFor()}}
	f.network(&agentv1.AssistanceDirective{Invitation: f.invitation(agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, "")})
	calls := len(provider.requests)
	if err := h.syncReboot(t.Context(), 1000, request, response); err != nil {
		t.Fatal(err)
	}
	if len(provider.requests) != calls || len(h.rebootPrompts) != 0 {
		t.Fatal("assistance allowed reboot mutation or preserved old prompt")
	}
}

func TestEmployeeDeferralBusyPreservesExactPromptForRetry(t *testing.T) {
	f := newAssistanceFixture(t, false)
	provider := &rebootSessionFixture{notice: &agentv1.OSUpdateRebootNotice{ScheduleId: uuid.NewString(), ScheduledFor: timestamppb.New(f.clock())}}
	h := &sessionService{broker: f.broker, reboots: provider}
	response := &agentv1.SyncSessionResponse{LocalSession: &agentv1.AssistanceLocalSession{Uid: 1000, LogindSessionId: "2"}}
	if err := h.syncReboot(t.Context(), 1000, &agentv1.SyncSessionRequest{}, response); err != nil {
		t.Fatal(err)
	}
	prompt := h.rebootPrompts[1000]
	request := &agentv1.SyncSessionRequest{RebootDeferral: &agentv1.OSUpdateRebootDeferralRequest{ScheduleId: prompt.token, RequestId: uuid.NewString(), ScheduledFor: response.GetReboot().GetScheduledFor()}}
	provider.err = osupdate.ErrRunInProgress
	for range 3 {
		err := h.syncReboot(t.Context(), 1000, request, response)
		if connect.CodeOf(mapError(err)) != connect.CodeUnavailable {
			t.Fatalf("busy action was acknowledged or refused: %v", err)
		}
		if h.rebootPrompts[1000] != prompt {
			t.Fatal("busy action invalidated its employee prompt")
		}
	}
	provider.err = nil
	if err := h.syncReboot(t.Context(), 1000, request, response); err != nil {
		t.Fatal(err)
	}
	first := provider.requests[1]
	for _, retry := range provider.requests[2:] {
		if !proto.Equal(first, retry) || retry.GetScheduleId() != prompt.schedule {
			t.Fatal("busy retry changed the native cycle or mutation identity")
		}
	}
}
