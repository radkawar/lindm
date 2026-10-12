//go:build linux

package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"math"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/rpcreason"
)

func TestDeviceActionRelayUnknownNeverRestarts(t *testing.T) {
	f := newDeviceActionRelayFixture(t)
	f.state = agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN
	f.work.StartGrantEnvelope = f.grant
	f.work.EscrowReceiptEnvelope = f.receipt
	if err := f.loop.dispatchDeviceActions(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.starts != 0 || f.authorizations != 0 || f.confirms != 0 || f.reports != 1 || f.attestedState != f.state {
		t.Fatalf("unknown history was replaced or executed: %v", f.events)
	}
}

func TestDeviceActionRelayLostGrantUsesExactStoredAuthority(t *testing.T) {
	f := newDeviceActionRelayFixture(t)
	f.loseAuthorization = true
	if err := f.loop.dispatchDeviceActions(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.starts != 0 || f.authorizations != 1 || f.closed {
		t.Fatal("lost grant reply became execution")
	}
	if err := f.loop.dispatchDeviceActions(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.starts != 1 || f.authorizations != 1 || !f.closed {
		t.Fatal("stored grant was not replayed exactly")
	}
}

func TestDeviceActionRelayLostStartReportsWithoutRestart(t *testing.T) {
	f := newDeviceActionRelayFixture(t)
	f.loseStart = true
	if err := f.loop.dispatchDeviceActions(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.starts != 1 || f.reports != 1 || f.attestedState != agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN {
		t.Fatal("ambiguous start did not report protected unknown history")
	}
}

func TestDeviceActionRelayEscrowRequiresDurableReceipt(t *testing.T) {
	for _, lost := range []string{"", "report", "confirm"} {
		t.Run(lost, func(t *testing.T) {
			f := newDeviceActionRelayFixture(t)
			f.state = agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW
			f.loseReport, f.loseConfirm = lost == "report", lost == "confirm"
			err := f.loop.dispatchDeviceActions(t.Context())
			if (err != nil) != (lost != "") {
				t.Fatalf("initial result = %v", err)
			}
			if lost == "report" && f.confirms != 0 {
				t.Fatal("retired before committed receipt reached relay")
			}
			if lost != "" {
				if err := f.loop.dispatchDeviceActions(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			if f.confirms != 1 || f.starts != 0 || !f.closed {
				t.Fatalf("receipt resume duplicated effects or missed closure: %v", f.events)
			}
		})
	}
}

func TestDeviceActionRelayRejectsChangedBindings(t *testing.T) {
	for _, change := range []string{"action", "intent", "refresh-intent"} {
		t.Run(change, func(t *testing.T) {
			f := newDeviceActionRelayFixture(t)
			f.state = agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN
			f.badStatus = change
			if err := f.loop.dispatchDeviceActions(t.Context()); err == nil {
				t.Fatal("accepted substituted action/intent")
			}
			if f.starts != 0 || f.reports != 0 || f.confirms != 0 {
				t.Fatal("substitution reached an effect or report")
			}
		})
	}
}

func TestDeviceActionRelayPollBoundPreservesPending(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDeviceActionRelayFixture(t)
		f.state = agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING
		begin := time.Now()
		if err := f.loop.dispatchDeviceActions(t.Context()); err != nil {
			t.Fatal(err)
		}
		if time.Since(begin) != deviceActionPollTimeout || f.closed || f.starts != 0 || f.attestedState != f.state {
			t.Fatal("poll deadline invented a terminal result")
		}
	})
}

// The operator can supply a local owner credential only after preparation, so
// the preparing cycle's start always precedes it. The relay retries that exact
// grant promptly instead of leaving it to the next management cycle, which a
// loaded host delayed past the executor's 30 s challenge (Omarchy live erase).
func TestDeviceActionRelayStartWaitsForLocalCredential(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDeviceActionRelayFixture(t)
		f.missingCredential = 3
		begin := time.Now()
		if err := f.loop.dispatchDeviceActions(t.Context()); err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(begin); elapsed != 3*deviceActionPollInterval || f.starts != 4 || f.authorizations != 1 || !f.closed || f.attestedState != agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED {
			t.Fatalf("credential retry: elapsed %v, starts %d, authorizations %d, closed %v, attested %v", elapsed, f.starts, f.authorizations, f.closed, f.attestedState)
		}
	})
}

func TestDeviceActionRelayCredentialWaitEndsWithChallenge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDeviceActionRelayFixture(t)
		f.missingCredential = math.MaxInt
		begin := time.Now()
		if err := f.loop.dispatchDeviceActions(t.Context()); err != nil {
			t.Fatal(err)
		}
		attempts := int(deviceActionCredentialWait/deviceActionPollInterval) + 1
		if elapsed := time.Since(begin); elapsed != deviceActionCredentialWait || f.starts != attempts || f.closed || f.attestedState != agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED {
			t.Fatalf("unbounded or terminal credential wait: elapsed %v, starts %d, closed %v, attested %v", elapsed, f.starts, f.closed, f.attestedState)
		}
	})
}

func TestDeviceActionRelayManagementCancellationJoins(t *testing.T) {
	for _, phase := range []string{"action-work", "action-prepare", "action-authorize", "action-start", "action-poll", "action-attest", "action-report", "action-confirm"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newDeviceActionRelayFixture(t)
				f.blockPhase = phase
				if phase == "action-poll" {
					f.state = agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING
				}
				if phase == "action-confirm" {
					f.state = agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW
				}
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
					t.Fatal("stop did not join in-flight action RPC")
				}
				if f.loop.cache.servers != nil {
					t.Fatal("stop did not release connections")
				}
			})
		})
	}
}

// Stateful consumer-boundary fixture. These tests exercise relay authority and
// interruption behavior, not native device effects or cryptographic verification.
type deviceActionRelayFixture struct {
	*dispatchFixture
	work                                                     *devicev1.DeviceActionWork
	state                                                    agentv1.DeviceActionState
	attestedState                                            agentv1.DeviceActionState
	receipt                                                  []byte
	confirms                                                 int
	loseStart, loseReport, loseConfirm                       bool
	liveRoot                                                 bool
	missingCredential                                        int
	recoveryProof, recoveryCredential, recoveryBootGrant     []byte
	recoveryPrepares, recoveryRegistrations, recoveryCommits int
	loseRecoveryRegistration, loseRecoveryCommit             bool
}

func newDeviceActionRelayFixture(t *testing.T) *deviceActionRelayFixture {
	t.Helper()
	base := newDispatchFixture(t)
	f := &deviceActionRelayFixture{dispatchFixture: base, state: agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED, receipt: []byte(" exact committed escrow receipt\n")}
	f.work = &devicev1.DeviceActionWork{ActionId: base.work.GetActionId(), IntentEnvelope: f.intent}
	f.loop.executor = &deviceActionRelayExecutor{dispatchExecutor: &dispatchExecutor{f: base}, action: f}
	f.loop.cache.servers.device = &deviceActionRelayServer{dispatchServer: &dispatchServer{f: base}, action: f}
	return f
}

func (f *deviceActionRelayFixture) status() *agentv1.DeviceActionStatus {
	digest := sha256.Sum256(f.intent)
	before := &agentv1.DeviceActionObservation{ObservedAt: timestamppb.Now(), Supported: true}
	status := &agentv1.DeviceActionStatus{ActionId: f.work.GetActionId(), IntentSha256: digest[:], State: f.state, Failure: agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_NONE, AcceptedAt: timestamppb.Now(), Before: before}
	if f.state == agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING || f.state == agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW {
		status.StartedAt = timestamppb.Now()
	}
	if deviceActionTerminal(f.state) {
		status.CompletedAt = timestamppb.Now()
		if f.state != agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED {
			status.Failure = agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_INTERRUPTED
		}
	}
	if f.state == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED || f.state == agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW {
		status.Verification = &agentv1.DeviceActionVerification{Verified: f.state == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, After: before, Escrow: &agentv1.DeviceActionEscrow{EscrowKeyId: strings.Repeat("a", 64), Ciphertext: []byte("encrypted only"), RecoveryKeySha256: digest[:], MetadataSha256: digest[:], NewKeyslot: 2, LuksUuid: "22222222-2222-4222-8222-222222222222"}}
	}
	if f.connection.GetDeviceActionReportOnly() {
		status.ReportOnly = true
		status.StartedAt = timestamppb.Now()
		status.VolatileResult = deviceActionTerminal(f.state)
	}
	switch f.badStatus {
	case "action":
		status.ActionId = "33333333-3333-4333-8333-333333333333"
	case "intent":
		status.IntentSha256 = make([]byte, sha256.Size)
	}
	return status
}

type deviceActionRelayExecutor struct {
	*dispatchExecutor
	action *deviceActionRelayFixture
}

func (e *deviceActionRelayExecutor) PrepareDeviceAction(ctx context.Context, req *connect.Request[agentv1.PrepareDeviceActionRequest]) (*connect.Response[agentv1.PrepareDeviceActionResponse], error) {
	f := e.action
	f.prepares++
	if !bytes.Equal(req.Msg.GetIntentEnvelope(), f.intent) {
		f.t.Fatal("intent bytes changed")
	}
	if err := f.phase(ctx, "action-prepare"); err != nil {
		return nil, err
	}
	return connect.NewResponse(&agentv1.PrepareDeviceActionResponse{Status: f.status(), ChallengeProof: f.challenge}), nil
}

func (e *deviceActionRelayExecutor) StartDeviceAction(ctx context.Context, req *connect.Request[agentv1.StartDeviceActionRequest]) (*connect.Response[agentv1.StartDeviceActionResponse], error) {
	f := e.action
	f.starts++
	if req.Msg.GetActionId() != f.work.GetActionId() || !bytes.Equal(req.Msg.GetStartGrantEnvelope(), f.grant) || f.state != agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED {
		f.t.Fatal("replacement effect or changed start bytes")
	}
	if err := f.phase(ctx, "action-start"); err != nil {
		return nil, err
	}
	if f.missingCredential > 0 {
		// The executor's refusal before consumption: the action stays PREPARED.
		f.missingCredential--
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "device_action_credential_required")
	}
	f.state = agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED
	if f.liveRoot {
		f.connection.DeviceActionReportOnly = true
	}
	if f.loseStart {
		f.state = agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("start reply lost"))
	}
	return connect.NewResponse(&agentv1.StartDeviceActionResponse{Status: f.status()}), nil
}

func (e *deviceActionRelayExecutor) GetDeviceAction(ctx context.Context, req *connect.Request[agentv1.GetDeviceActionRequest]) (*connect.Response[agentv1.GetDeviceActionResponse], error) {
	f := e.action
	f.polls++
	if req.Msg.GetActionId() != f.work.GetActionId() {
		f.t.Fatal("lookup action changed")
	}
	if err := f.phase(ctx, "action-poll"); err != nil {
		return nil, err
	}
	return connect.NewResponse(&agentv1.GetDeviceActionResponse{Status: f.status()}), nil
}

func (e *deviceActionRelayExecutor) ConfirmDeviceActionEscrow(ctx context.Context, req *connect.Request[agentv1.ConfirmDeviceActionEscrowRequest]) (*connect.Response[agentv1.ConfirmDeviceActionEscrowResponse], error) {
	f := e.action
	f.confirms++
	if req.Msg.GetActionId() != f.work.GetActionId() || !bytes.Equal(req.Msg.GetReceiptEnvelope(), f.receipt) || len(f.work.GetEscrowReceiptEnvelope()) == 0 || f.state != agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW {
		f.t.Fatal("retirement without exact durable escrow receipt")
	}
	if err := f.phase(ctx, "action-confirm"); err != nil {
		return nil, err
	}
	f.state = agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED
	if f.loseConfirm {
		f.loseConfirm = false
		f.state = agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("confirm reply lost"))
	}
	return connect.NewResponse(&agentv1.ConfirmDeviceActionEscrowResponse{Status: f.status()}), nil
}

func (e *deviceActionRelayExecutor) AttestDeviceAction(ctx context.Context, req *connect.Request[agentv1.AttestDeviceActionRequest]) (*connect.Response[agentv1.AttestDeviceActionResponse], error) {
	f := e.action
	if req.Msg.GetActionId() != f.work.GetActionId() || !bytes.Equal(req.Msg.GetNonce(), f.lastNonce) || bytes.Equal(req.Msg.GetNonce(), f.initialNonce) {
		f.t.Fatal("attestation nonce/action not refreshed")
	}
	if err := f.phase(ctx, "action-attest"); err != nil {
		return nil, err
	}
	f.attestedState, f.attestedEpoch = f.state, f.epoch
	return connect.NewResponse(&agentv1.AttestDeviceActionResponse{AttestationEnvelope: f.attestation, CertificatePem: f.certificate}), nil
}

type deviceActionRelayServer struct {
	*dispatchServer
	action *deviceActionRelayFixture
}

func (s *deviceActionRelayServer) GetDeviceActionWork(ctx context.Context, req *connect.Request[devicev1.GetDeviceActionWorkRequest]) (*connect.Response[devicev1.GetDeviceActionWorkResponse], error) {
	f := s.action
	f.remote(req.Msg.GetSessionEpoch())
	f.workCalls++
	if err := f.phase(ctx, "action-work"); err != nil {
		return nil, err
	}
	if f.closed {
		return connect.NewResponse(&devicev1.GetDeviceActionWorkResponse{}), nil
	}
	work := proto.CloneOf(f.work)
	if f.workCalls > 1 && f.badStatus == "refresh-intent" {
		work.IntentEnvelope = []byte("substituted")
	}
	work.ResultNonce = make([]byte, 32)
	work.ResultNonce[0] = byte(f.workCalls)
	work.ResultNonceExpiresAt = timestamppb.New(time.Now().Add(time.Minute))
	f.lastNonce = bytes.Clone(work.ResultNonce)
	if f.initialNonce == nil {
		f.initialNonce = bytes.Clone(work.ResultNonce)
	}
	return connect.NewResponse(&devicev1.GetDeviceActionWorkResponse{Work: work}), nil
}

func (s *deviceActionRelayServer) AuthorizeDeviceActionStart(ctx context.Context, req *connect.Request[devicev1.AuthorizeDeviceActionStartRequest]) (*connect.Response[devicev1.AuthorizeDeviceActionStartResponse], error) {
	f := s.action
	grant, err := f.authorizeStart(ctx, req.Msg, f.work.GetActionId(), "action-authorize", func() { f.work.StartGrantEnvelope = f.grant })
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&devicev1.AuthorizeDeviceActionStartResponse{StartGrantEnvelope: grant}), nil
}

func (s *deviceActionRelayServer) ReportDeviceActionResult(ctx context.Context, req *connect.Request[devicev1.ReportDeviceActionResultRequest]) (*connect.Response[devicev1.ReportDeviceActionResultResponse], error) {
	f := s.action
	f.remote(req.Msg.GetSessionEpoch())
	if req.Msg.GetActionId() != f.work.GetActionId() || req.Msg.GetSessionEpoch() != f.attestedEpoch || !bytes.Equal(req.Msg.GetAttestationEnvelope(), f.attestation) || !bytes.Equal(req.Msg.GetCertificatePem(), f.certificate) {
		f.t.Fatal("attestation/certificate/session changed")
	}
	if err := f.phase(ctx, "action-report"); err != nil {
		return nil, err
	}
	f.reports++
	f.closed = deviceActionTerminal(f.attestedState)
	if f.attestedState == agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW {
		f.work.EscrowReceiptEnvelope = f.receipt
	}
	if f.loseReport {
		f.loseReport = false
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("report reply lost after custody commit"))
	}
	return connect.NewResponse(&devicev1.ReportDeviceActionResultResponse{Closed: f.closed, EscrowReceiptEnvelope: f.work.GetEscrowReceiptEnvelope()}), nil
}
