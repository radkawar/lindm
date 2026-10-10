//go:build linux

package transport

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
)

func TestDeviceActionLiveRootKeepsPinnedSessionAfterConsumption(t *testing.T) {
	for _, reconnect := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial-start", true: "report-only-reconnect"}[reconnect], func(t *testing.T) {
			f := newDeviceActionRelayFixture(t)
			f.liveRoot = true
			if reconnect {
				f.connection.DeviceActionReportOnly = true
				f.connection.RenewAfter = timestamppb.New(time.Now().Add(-time.Minute))
				f.state = agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED
			}
			if err := f.loop.cycle(t.Context()); err != nil {
				t.Fatal(err)
			}
			if !f.closed || f.reports != 1 || f.confirms != 0 {
				t.Fatalf("live result not delivered: %v", f.events)
			}
			if reconnect && (f.prepares != 0 || f.starts != 0 || f.authorizations != 0) {
				t.Fatal("report-only reconnect attempted execution")
			}
			if !reconnect && f.starts != 1 {
				t.Fatal("initial live action did not start once")
			}
		})
	}
}

func TestDeviceActionReportOnlyRejectsUnusablePinnedSession(t *testing.T) {
	for _, reason := range []string{"unusable", "zero-epoch", "pending-renewal"} {
		t.Run(reason, func(t *testing.T) {
			f := newDeviceActionRelayFixture(t)
			f.connection.DeviceActionReportOnly = true
			switch reason {
			case "unusable":
				f.connection.SessionEpochUsable = false
			case "zero-epoch":
				f.epoch = 0
			case "pending-renewal":
				f.connection.RenewalPending = true
			}
			if err := f.loop.cycle(t.Context()); err == nil {
				t.Fatal("report-only mode inferred a usable session")
			}
			if f.starts != 0 || f.reports != 0 || f.prepares != 0 {
				t.Fatal("unusable pinned session reached action RPCs")
			}
		})
	}
}

func TestDeviceActionRecoveryRelaysExactBootAuthority(t *testing.T) {
	for _, lost := range []string{"", "registration", "commit"} {
		t.Run(lost, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newDeviceActionRelayFixture(t)
				f.enableRecovery()
				f.loseRecoveryRegistration, f.loseRecoveryCommit = lost == "registration", lost == "commit"
				if err := f.loop.dispatchDeviceActions(t.Context()); err != nil {
					t.Fatal(err)
				}
				if lost == "registration" {
					if f.recoveryCommits != 0 || f.closed {
						t.Fatal("missing registration reply became a boot")
					}
					if err := f.loop.dispatchDeviceActions(t.Context()); err != nil {
						t.Fatal(err)
					}
				}
				if f.prepares != 0 || f.starts != 0 || f.authorizations != 0 {
					t.Fatal("recovery handoff took ordinary execution path")
				}
				if f.recoveryRegistrations != 1 || f.recoveryCommits != 1 || f.closed != (lost == "commit") {
					t.Fatalf("boot authority was replaced or boot acceptance became sanitation completion: %v", f.events)
				}
				if lost == "commit" && f.attestedState != agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN {
					t.Fatal("lost boot outcome was reported as success")
				}
				if lost != "commit" {
					if f.attestedState != agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING {
						t.Fatal("boot acceptance invented terminal sanitation proof")
					}
					if err := f.loop.dispatchDeviceActions(t.Context()); err != nil {
						t.Fatal(err)
					}
					if f.recoveryCommits != 1 || f.recoveryRegistrations != 1 {
						t.Fatal("pending recovery boot was rearmed")
					}
				}
			})
		})
	}
}

func TestDeviceActionRecoveryUnknownDoesNotRearmBoot(t *testing.T) {
	f := newDeviceActionRelayFixture(t)
	f.enableRecovery()
	f.state = agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN
	f.work.RecoveryCredentialEnvelope, f.work.RecoveryBootGrantEnvelope = f.recoveryCredential, f.recoveryBootGrant
	if err := f.loop.dispatchDeviceActions(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.recoveryCommits != 0 || f.recoveryRegistrations != 0 || f.starts != 0 || f.attestedState != f.state {
		t.Fatal("unknown boot outcome was rearmed")
	}
}

func TestDeviceActionRecoveryRejectsPartialStoredAuthority(t *testing.T) {
	f := newDeviceActionRelayFixture(t)
	f.enableRecovery()
	f.work.RecoveryCredentialEnvelope = f.recoveryCredential
	if err := f.loop.dispatchDeviceActions(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.recoveryRegistrations != 0 || f.recoveryCommits != 0 || f.closed {
		t.Fatal("partial stored pair minted replacement boot authority")
	}
}

func TestDeviceActionRecoveryCancellationJoins(t *testing.T) {
	for _, phase := range []string{"recovery-prepare", "recovery-register", "recovery-commit"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newDeviceActionRelayFixture(t)
				f.enableRecovery()
				f.blockPhase = phase
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				stop := f.loop.start(ctx)
				defer stop()
				select {
				case <-f.entered:
				case <-ctx.Done():
					t.Fatalf("did not reach %s", phase)
				}
				stop()
				select {
				case <-f.exited:
				default:
					t.Fatal("stop did not join recovery RPC")
				}
			})
		})
	}
}

func (f *deviceActionRelayFixture) enableRecovery() {
	f.work.RecoveryHandoff = true
	f.recoveryProof = []byte(" exact root handoff proof\n")
	f.recoveryCredential = []byte(" exact scoped public recovery credential\n")
	f.recoveryBootGrant = []byte(" exact fresh purpose-separated BOOT grant\n")
}

func (e *deviceActionRelayExecutor) PrepareSession(ctx context.Context, req *connect.Request[agentv1.PrepareSessionRequest]) (*connect.Response[agentv1.PrepareSessionResponse], error) {
	if e.action.connection.GetDeviceActionReportOnly() {
		e.action.t.Fatal("session transition attempted after root journal closed")
	}
	return e.dispatchExecutor.PrepareSession(ctx, req)
}

func (e *deviceActionRelayExecutor) GetExecutionTrust(ctx context.Context, req *connect.Request[agentv1.GetExecutionTrustRequest]) (*connect.Response[agentv1.GetExecutionTrustResponse], error) {
	if e.action.connection.GetDeviceActionReportOnly() {
		e.action.t.Fatal("trust reload attempted after root journal closed")
	}
	return e.dispatchExecutor.GetExecutionTrust(ctx, req)
}

func (s *deviceActionRelayServer) GetResourceWork(ctx context.Context, req *connect.Request[devicev1.GetResourceWorkRequest]) (*connect.Response[devicev1.GetResourceWorkResponse], error) {
	if s.action.connection.GetDeviceActionReportOnly() {
		s.action.t.Fatal("service dispatch attempted during report-only window")
	}
	return s.dispatchServer.GetResourceWork(ctx, req)
}

func (e *deviceActionRelayExecutor) PrepareDeviceActionRecovery(ctx context.Context, req *connect.Request[agentv1.PrepareDeviceActionRecoveryRequest]) (*connect.Response[agentv1.PrepareDeviceActionRecoveryResponse], error) {
	f := e.action
	f.recoveryPrepares++
	if !bytes.Equal(req.Msg.GetIntentEnvelope(), f.intent) {
		f.t.Fatal("recovery intent bytes changed")
	}
	if err := f.phase(ctx, "recovery-prepare"); err != nil {
		return nil, err
	}
	return connect.NewResponse(&agentv1.PrepareDeviceActionRecoveryResponse{HandoffProof: f.recoveryProof, CertificatePem: f.certificate, Status: f.status()}), nil
}

func (s *deviceActionRelayServer) RegisterDeviceActionRecovery(ctx context.Context, req *connect.Request[devicev1.RegisterDeviceActionRecoveryRequest]) (*connect.Response[devicev1.RegisterDeviceActionRecoveryResponse], error) {
	f := s.action
	f.remote(req.Msg.GetSessionEpoch())
	f.recoveryRegistrations++
	if req.Msg.GetActionId() != f.work.GetActionId() || !bytes.Equal(req.Msg.GetHandoffProof(), f.recoveryProof) || !bytes.Equal(req.Msg.GetCertificatePem(), f.certificate) {
		f.t.Fatal("handoff proof/certificate/action changed")
	}
	if err := f.phase(ctx, "recovery-register"); err != nil {
		return nil, err
	}
	f.work.RecoveryCredentialEnvelope, f.work.RecoveryBootGrantEnvelope = f.recoveryCredential, f.recoveryBootGrant
	if f.loseRecoveryRegistration {
		f.loseRecoveryRegistration = false
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("registration reply lost after commit"))
	}
	return connect.NewResponse(&devicev1.RegisterDeviceActionRecoveryResponse{CredentialEnvelope: f.recoveryCredential, BootGrantEnvelope: f.recoveryBootGrant}), nil
}

func (e *deviceActionRelayExecutor) CommitDeviceActionRecovery(ctx context.Context, req *connect.Request[agentv1.CommitDeviceActionRecoveryRequest]) (*connect.Response[agentv1.CommitDeviceActionRecoveryResponse], error) {
	f := e.action
	f.recoveryCommits++
	if req.Msg.GetActionId() != f.work.GetActionId() || !bytes.Equal(req.Msg.GetCredentialEnvelope(), f.recoveryCredential) || !bytes.Equal(req.Msg.GetBootGrantEnvelope(), f.recoveryBootGrant) || f.state != agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED {
		f.t.Fatal("boot pair changed or effect replayed")
	}
	if err := f.phase(ctx, "recovery-commit"); err != nil {
		return nil, err
	}
	// The original device never claims sanitation succeeded merely because
	// reboot was consumed. Only the separate recovery environment can prove it.
	f.state = agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING
	if f.loseRecoveryCommit {
		f.loseRecoveryCommit = false
		f.state = agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("boot reply lost after consumption"))
	}
	return connect.NewResponse(&agentv1.CommitDeviceActionRecoveryResponse{Status: f.status()}), nil
}
