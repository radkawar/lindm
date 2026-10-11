//go:build linux

package executor

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// signedHarness drives one signed-action kind through the executor's public
// RPCs, so the same characterization table covers resources and device actions.
type signedHarness struct {
	f       *resourceFixture
	prepare func(t *testing.T) string
	grant   func(t *testing.T, id string) []byte
	// foreign signs a valid start-role grant over a challenge this executor
	// never issued (a different nonce).
	foreign  func(t *testing.T, id string) []byte
	start    func(ctx context.Context, id string, grant []byte) error
	state    func(t *testing.T, id string) (string, bool)
	await    func(t *testing.T, id string)
	effects  func() int32
	reopen   func(t *testing.T)
	attest   func(t *testing.T, id string, nonce []byte) (*agentv1.DeviceActionAttestation, *agentv1.ResourceExecutionAttestation, error)
	revision func(t *testing.T, id string) int64
}

func resourceHarness(t *testing.T) *signedHarness {
	t.Helper()
	f := newResourceFixture(t, false)
	h := &signedHarness{f: f}
	h.prepare = func(t *testing.T) string {
		intent := f.intent(t, 1)
		f.prepare(t, intent)
		return intent.GetActionId()
	}
	h.grant = func(t *testing.T, id string) []byte {
		record, _ := resourceRow(t, f.svc, id)
		return f.grant(t, record.GetIntent())
	}
	h.foreign = func(t *testing.T, id string) []byte {
		record, _ := resourceRow(t, f.svc, id)
		challenge := proto.CloneOf(record.GetChallenge())
		challenge.Nonce = bytes.Repeat([]byte{9}, 32)
		intent := record.GetIntent()
		return mustSign(t, f.svc.authority, &agentv1.ResourceExecutionStartGrant{Challenge: challenge, ActorId: intent.GetActorId(), AuthorizationVersion: intent.GetAuthorizationVersion(), RootVersion: 1, DelegationVersion: 1, NotBefore: challenge.GetIssuedAt(), ExpiresAt: challenge.GetExpiresAt()}, f.startKey)
	}
	h.start = func(ctx context.Context, id string, grant []byte) error {
		_, err := f.svc.StartResourceExecution(ctx, connect.NewRequest(&agentv1.StartResourceExecutionRequest{ActionId: id, StartGrantEnvelope: grant}))
		return err
	}
	h.state = func(t *testing.T, id string) (string, bool) {
		response, err := f.svc.GetResourceExecution(t.Context(), connect.NewRequest(&agentv1.GetResourceExecutionRequest{ActionId: id}))
		if err != nil {
			t.Fatal(err)
		}
		return response.Msg.GetStatus().GetState().String(), response.Msg.GetStatus().GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED
	}
	h.await = func(t *testing.T, id string) {
		if state := awaitResourceTerminal(t, f.svc, id).GetState(); state != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED {
			t.Fatalf("resource ended %s", state)
		}
	}
	h.effects = f.native.effects.Load
	h.reopen = func(t *testing.T) {
		if err := f.svc.Close(); err != nil {
			t.Fatal(err)
		}
		next, err := New(t.Context(), f.svc.directory, f.options()...)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = next.Close() })
		f.svc = next
	}
	h.attest = func(t *testing.T, id string, nonce []byte) (*agentv1.DeviceActionAttestation, *agentv1.ResourceExecutionAttestation, error) {
		response, err := f.svc.AttestResourceExecution(t.Context(), connect.NewRequest(&agentv1.AttestResourceExecutionRequest{ActionId: id, Nonce: nonce}))
		if err != nil {
			return nil, nil, err
		}
		attestation := new(agentv1.ResourceExecutionAttestation)
		if err := f.svc.authority.Verify(t.Context(), response.Msg.GetAttestationEnvelope(), attestation, 1, publicOf(durable(t, f.svc).GetIdentityPrivateKey())); err != nil {
			t.Fatal(err)
		}
		return nil, attestation, nil
	}
	h.revision = func(t *testing.T, id string) int64 {
		_, revision := resourceRow(t, f.svc, id)
		return revision
	}
	return h
}

func deviceActionHarness(t *testing.T) *signedHarness {
	t.Helper()
	f := newDeviceActionFixture(t)
	h := &signedHarness{f: f.resourceFixture}
	h.prepare = func(t *testing.T) string {
		intent := f.actionIntent(t, 1, nil)
		f.actionPrepare(t, intent)
		return intent.GetActionId()
	}
	h.grant = func(t *testing.T, id string) []byte {
		record, _ := deviceActionRow(t, f.svc, id)
		return f.actionGrant(t, record.GetIntent())
	}
	h.foreign = func(t *testing.T, id string) []byte {
		record, _ := deviceActionRow(t, f.svc, id)
		challenge := proto.CloneOf(record.GetChallenge())
		challenge.Nonce = bytes.Repeat([]byte{9}, 32)
		intent := record.GetIntent()
		return mustSign(t, f.svc.authority, &agentv1.DeviceActionStartGrant{Challenge: challenge, ActorId: intent.GetActorId(), AuthorizationVersion: intent.GetAuthorizationVersion(), RootVersion: 1, DelegationVersion: 1, NotBefore: challenge.GetIssuedAt(), ExpiresAt: challenge.GetExpiresAt()}, f.startKey)
	}
	h.start = func(ctx context.Context, id string, grant []byte) error {
		_, err := f.svc.StartDeviceAction(ctx, connect.NewRequest(&agentv1.StartDeviceActionRequest{ActionId: id, StartGrantEnvelope: grant}))
		return err
	}
	h.state = func(t *testing.T, id string) (string, bool) {
		response, err := f.svc.GetDeviceAction(t.Context(), connect.NewRequest(&agentv1.GetDeviceActionRequest{ActionId: id}))
		if err != nil {
			t.Fatal(err)
		}
		return response.Msg.GetStatus().GetState().String(), response.Msg.GetStatus().GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_EXPIRED
	}
	h.await = func(t *testing.T, id string) {
		awaitDeviceAction(t, f.svc, id, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED)
	}
	h.effects = f.actionNative.effects.Load
	h.reopen = f.reopenActions
	h.attest = func(t *testing.T, id string, nonce []byte) (*agentv1.DeviceActionAttestation, *agentv1.ResourceExecutionAttestation, error) {
		response, err := f.svc.AttestDeviceAction(t.Context(), connect.NewRequest(&agentv1.AttestDeviceActionRequest{ActionId: id, Nonce: nonce}))
		if err != nil {
			return nil, nil, err
		}
		attestation := new(agentv1.DeviceActionAttestation)
		if err := f.svc.authority.Verify(t.Context(), response.Msg.GetAttestationEnvelope(), attestation, 1, publicOf(durable(t, f.svc).GetIdentityPrivateKey())); err != nil {
			t.Fatal(err)
		}
		return attestation, nil, nil
	}
	h.revision = func(t *testing.T, id string) int64 {
		_, revision := deviceActionRow(t, f.svc, id)
		return revision
	}
	return h
}

// TestSignedActionLifecycleCharacterization pins the security semantics the
// generic signed-action core must give every kind identically: exact replay,
// expired and revoked authority, executor restart, duplicate consumption,
// mismatched grants, the agent self-update interlock and attestation binding.
func TestSignedActionLifecycleCharacterization(t *testing.T) {
	kinds := map[string]func(*testing.T) *signedHarness{"resource": resourceHarness, "device-action": deviceActionHarness}
	cases := map[string]func(t *testing.T, h *signedHarness){
		"exact-replay-is-historical": func(t *testing.T, h *signedHarness) {
			id := h.prepare(t)
			grant := h.grant(t, id)
			if err := h.start(t.Context(), id, grant); err != nil {
				t.Fatal(err)
			}
			h.await(t, id)
			revision := h.revision(t, id)
			// Even after the grant and challenge expired, the exact bytes only read history.
			h.f.wall.Store(h.f.now.Add(6 * time.Minute).UnixNano())
			if err := h.start(t.Context(), id, grant); err != nil {
				t.Fatalf("exact replay rejected: %v", err)
			}
			if err := h.start(t.Context(), id, append(bytes.Clone(grant), ' ')); connect.CodeOf(err) != connect.CodeAlreadyExists {
				t.Fatalf("changed grant bytes: %v", err)
			}
			if h.effects() != 1 || h.revision(t, id) != revision {
				t.Fatal("replay repeated an effect or rewrote history")
			}
		},
		"expired-wall-clock": func(t *testing.T, h *signedHarness) {
			id := h.prepare(t)
			grant := h.grant(t, id)
			h.f.wall.Store(h.f.now.Add(31 * time.Second).UnixNano())
			assertSignedRejected(t, h, id, grant, true)
		},
		"expired-boottime": func(t *testing.T, h *signedHarness) {
			id := h.prepare(t)
			grant := h.grant(t, id)
			h.f.bootClock.Add(uint64(31 * time.Second))
			assertSignedRejected(t, h, id, grant, true)
		},
		"revoked-delegation": func(t *testing.T, h *signedHarness) {
			id := h.prepare(t)
			grant := h.grant(t, id)
			callTrust(t, h.f.svc, &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: mustSign(t, h.f.svc.authority, delegationDocument(h.f.fix.deploy.String(), 1, 2, 0, h.f.now), h.f.fix.rootKey)})
			assertSignedRejected(t, h, id, grant, false)
		},
		"rebooted-session": func(t *testing.T, h *signedHarness) {
			id := h.prepare(t)
			grant := h.grant(t, id)
			h.f.svc.mu.Lock()
			h.f.svc.bootID = func() (string, error) { return "6b3e9c0e-4a43-4d4f-9f37-0c3f1b0a6d11", nil }
			h.f.svc.mu.Unlock()
			assertSignedRejected(t, h, id, grant, false)
		},
		"other-executor-incarnation": func(t *testing.T, h *signedHarness) {
			id := h.prepare(t)
			grant := h.grant(t, id)
			h.reopen(t)
			assertSignedRejected(t, h, id, grant, true)
		},
		"duplicate-consume": func(t *testing.T, h *signedHarness) {
			id := h.prepare(t)
			grant := h.grant(t, id)
			var wg sync.WaitGroup
			for range 4 {
				wg.Go(func() { _ = h.start(t.Context(), id, grant) })
			}
			wg.Wait()
			h.await(t, id)
			if h.effects() != 1 {
				t.Fatalf("one grant caused %d effects", h.effects())
			}
		},
		"mismatched-grant": func(t *testing.T, h *signedHarness) {
			id := h.prepare(t)
			assertSignedRejected(t, h, id, h.foreign(t, id), false)
		},
		"agent-update-interlock": func(t *testing.T, h *signedHarness) {
			id := h.prepare(t)
			grant := h.grant(t, id)
			h.f.svc.mu.Lock()
			h.f.svc.updateHold = true
			h.f.svc.mu.Unlock()
			assertSignedRejected(t, h, id, grant, false)
		},
		"attestation-binds-nonce-and-revision": func(t *testing.T, h *signedHarness) {
			id := h.prepare(t)
			if err := h.start(t.Context(), id, h.grant(t, id)); err != nil {
				t.Fatal(err)
			}
			h.await(t, id)
			nonce := bytes.Repeat([]byte{7}, 32)
			device, resource, err := h.attest(t, id, nonce)
			if err != nil {
				t.Fatal(err)
			}
			var signed interface {
				proto.Message
				GetNonce() []byte
				GetActionRevision() uint64
			} = device
			if device == nil {
				signed = resource
			}
			if !bytes.Equal(signed.GetNonce(), nonce) || signed.GetActionRevision() != uint64(h.revision(t, id)) {
				t.Fatal("attestation lost nonce or revision binding")
			}
			if _, _, err := h.attest(t, "c5a2f0f4-1f57-4c86-9a43-ef1f5f9d5c11", nonce); connect.CodeOf(err) != connect.CodeNotFound {
				t.Fatalf("attested an unknown action: %v", err)
			}
		},
	}
	for kind, harness := range kinds {
		for name, run := range cases {
			t.Run(kind+"/"+name, func(t *testing.T) { run(t, harness(t)) })
		}
	}
}

// assertSignedRejected requires a start to fail without effect; expired also
// requires the unconsumed action to be durably EXPIRED.
func assertSignedRejected(t *testing.T, h *signedHarness, id string, grant []byte, expired bool) {
	t.Helper()
	if err := h.start(t.Context(), id, grant); err == nil {
		// Resource starts queue; let the worker settle so the report is complete.
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); <-tick.C {
			if state, _ := h.state(t, id); state != "RESOURCE_EXECUTION_STATE_QUEUED" && state != "RESOURCE_EXECUTION_STATE_RUNNING" {
				break
			}
		}
		t.Fatalf("start acknowledged a grant that must be rejected (native effects: %d)", h.effects())
	}
	if h.effects() != 0 {
		t.Fatal("rejected start reached a native effect")
	}
	if state, isExpired := h.state(t, id); expired && !isExpired {
		t.Fatalf("unconsumed action is %s, not EXPIRED", state)
	}
}
