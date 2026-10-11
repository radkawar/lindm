//go:build integration

package device

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
)

// signedServerHarness drives one signed-action kind through the device RPCs,
// so one characterization table covers resource and device-action authority.
type signedServerHarness struct {
	table     string
	principal devicePrincipal
	service   *Service
	actionID  func() string
	// prepare issues work and a fresh result nonce for the device.
	prepare func(t *testing.T)
	// proof signs a fresh device challenge for the current work.
	proof func(t *testing.T) []byte
	start func(ctx context.Context, epoch uint64, proof []byte) ([]byte, error)
	// window is the verified grant's [not_before, expires_at) length.
	window func(t *testing.T, grant []byte) time.Duration
	// result signs an attestation; running is non-terminal, otherwise succeeded.
	result func(t *testing.T, revision uint64, running bool, nonce []byte) func(context.Context) error
	nonce  func() []byte
}

func (h *signedServerHarness) ctx(t *testing.T) context.Context {
	return withDevicePrincipal(t.Context(), h.principal)
}

func (h *signedServerHarness) exec(t *testing.T, statement string, args ...any) {
	t.Helper()
	if _, err := h.service.pool.Exec(t.Context(), statement, args...); err != nil {
		t.Fatal(err)
	}
}

func (h *signedServerHarness) granted(t *testing.T) bool {
	t.Helper()
	var length int
	if err := h.service.pool.QueryRow(t.Context(), "SELECT octet_length(start_grant_envelope) FROM "+h.table+" WHERE id=$1", h.actionID()).Scan(&length); err != nil {
		t.Fatal(err)
	}
	return length != 0
}

func resourceServerHarness(t *testing.T) *signedServerHarness {
	t.Helper()
	f := newDispatchFixture(t)
	f.assign(t, nil)
	var work *devicev1.ResourceWork
	start := ed25519.PublicKey(f.service.signing.StartKey[ed25519.SeedSize:])
	return &signedServerHarness{
		table: "resource_actions", principal: f.principal, service: f.service,
		actionID: func() string { return work.GetActionId() },
		prepare:  func(t *testing.T) { work = f.work(t) },
		proof: func(t *testing.T) []byte {
			return f.sign(t, f.challenge(t, work), f.key)
		},
		start: func(ctx context.Context, epoch uint64, proof []byte) ([]byte, error) {
			response, err := f.service.AuthorizeResourceStart(ctx, connect.NewRequest(&devicev1.AuthorizeResourceStartRequest{SessionEpoch: epoch, ActionId: work.GetActionId(), ChallengeProof: proof}))
			if err != nil {
				return nil, err
			}
			return response.Msg.GetStartGrantEnvelope(), nil
		},
		window: func(t *testing.T, envelope []byte) time.Duration {
			grant := new(agentv1.ResourceExecutionStartGrant)
			if err := f.service.authority.Verify(t.Context(), envelope, grant, 1, start); err != nil {
				t.Fatal(err)
			}
			return grant.GetExpiresAt().AsTime().Sub(grant.GetNotBefore().AsTime())
		},
		result: func(t *testing.T, revision uint64, running bool, nonce []byte) func(context.Context) error {
			bound := proto.CloneOf(work)
			bound.ResultNonce = nonce
			state := agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED
			if running {
				state = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING
			}
			request := f.result(t, bound, revision, state, true)
			return func(ctx context.Context) error {
				_, err := f.service.ReportResourceResult(ctx, connect.NewRequest(request))
				return err
			}
		},
		nonce: func() []byte { return work.GetResultNonce() },
	}
}

func deviceActionServerHarness(t *testing.T) *signedServerHarness {
	t.Helper()
	f := newDeviceActionFixture(t)
	f.create(t, f.request(&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{TerminateSessions: true, Usernames: []string{"alice"}}}}))
	var work *devicev1.DeviceActionWork
	start := ed25519.PublicKey(f.svc.signing.StartKey[ed25519.SeedSize:])
	return &signedServerHarness{
		table: "device_actions", principal: f.principal, service: f.svc,
		actionID: func() string { return work.GetActionId() },
		prepare:  func(t *testing.T) { work = f.work(t) },
		proof: func(t *testing.T) []byte {
			return f.sign(t, f.challenge(t, work))
		},
		start: func(ctx context.Context, epoch uint64, proof []byte) ([]byte, error) {
			response, err := f.svc.AuthorizeDeviceActionStart(ctx, connect.NewRequest(&devicev1.AuthorizeDeviceActionStartRequest{SessionEpoch: epoch, ActionId: work.GetActionId(), ChallengeProof: proof}))
			if err != nil {
				return nil, err
			}
			return response.Msg.GetStartGrantEnvelope(), nil
		},
		window: func(t *testing.T, envelope []byte) time.Duration {
			grant := new(agentv1.DeviceActionStartGrant)
			if err := f.svc.authority.Verify(t.Context(), envelope, grant, 1, start); err != nil {
				t.Fatal(err)
			}
			return grant.GetExpiresAt().AsTime().Sub(grant.GetNotBefore().AsTime())
		},
		result: func(t *testing.T, revision uint64, running bool, nonce []byte) func(context.Context) error {
			bound := proto.CloneOf(work)
			bound.ResultNonce = nonce
			state, verification := agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, lockVerification()
			if running {
				state, verification = agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING, nil
			}
			request := f.result(t, bound, revision, state, verification)
			return func(ctx context.Context) error {
				_, err := f.svc.ReportDeviceActionResult(ctx, connect.NewRequest(request))
				return err
			}
		},
		nonce: func() []byte { return work.GetResultNonce() },
	}
}

// TestSignedActionServerCharacterization pins the server authority semantics
// the generic signed-action core gives every kind identically.
func TestSignedActionServerCharacterization(t *testing.T) {
	kinds := map[string]func(*testing.T) *signedServerHarness{"resource": resourceServerHarness, "device-action": deviceActionServerHarness}
	cases := map[string]func(t *testing.T, h *signedServerHarness){
		"start-replay-is-exact": func(t *testing.T, h *signedServerHarness) {
			h.prepare(t)
			proof := h.proof(t)
			grant, err := h.start(h.ctx(t), 1, proof)
			if err != nil {
				t.Fatal(err)
			}
			again, err := h.start(h.ctx(t), 1, proof)
			if err != nil || !bytes.Equal(again, grant) {
				t.Fatalf("exact retry did not return the stored grant: %v", err)
			}
			if _, err := h.start(h.ctx(t), 1, h.proof(t)); connect.CodeOf(err) != connect.CodeAlreadyExists {
				t.Fatalf("second challenge for a granted action: %v", err)
			}
		},
		"grant-window-at-most-30s": func(t *testing.T, h *signedServerHarness) {
			h.prepare(t)
			grant, err := h.start(h.ctx(t), 1, h.proof(t))
			if err != nil {
				t.Fatal(err)
			}
			if window := h.window(t, grant); window <= 0 || window > 30*time.Second {
				t.Fatalf("start grant window %s exceeds the 30 s bound", window)
			}
		},
		"expired-action": func(t *testing.T, h *signedServerHarness) {
			h.prepare(t)
			h.exec(t, "UPDATE "+h.table+" SET issued_at=clock_timestamp()-interval '2 minutes', expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", h.actionID())
			if _, err := h.start(h.ctx(t), 1, h.proof(t)); connect.CodeOf(err) != connect.CodePermissionDenied {
				t.Fatalf("expired action: %v", err)
			}
			if h.granted(t) {
				t.Fatal("expired action was granted")
			}
		},
		"revoked-device": func(t *testing.T, h *signedServerHarness) {
			h.prepare(t)
			proof := h.proof(t)
			h.exec(t, "UPDATE devices SET state='revoked', revoked_at=clock_timestamp(), revoked_by=(SELECT id FROM principals LIMIT 1), revoke_reason='characterization' WHERE id=$1", h.principal.DeviceID)
			if _, err := h.start(h.ctx(t), 1, proof); err == nil {
				t.Fatal("revoked device was granted")
			}
			if err := h.result(t, 1, true, h.nonce())(h.ctx(t)); err == nil {
				t.Fatal("revoked device reported a result")
			}
		},
		"other-generation": func(t *testing.T, h *signedServerHarness) {
			h.prepare(t)
			proof := h.proof(t)
			h.principal.GenerationID = uuid.New()
			if _, err := h.start(h.ctx(t), 1, proof); err == nil {
				t.Fatal("other generation was granted")
			}
			if err := h.result(t, 1, true, h.nonce())(h.ctx(t)); err == nil {
				t.Fatal("other generation reported a result")
			}
			if h.granted(t) {
				t.Fatal("binding failure left a grant")
			}
		},
		"fenced-session-epoch": func(t *testing.T, h *signedServerHarness) {
			h.prepare(t)
			if _, err := h.start(h.ctx(t), 2, h.proof(t)); err == nil || h.granted(t) {
				t.Fatalf("stale session epoch was granted: %v", err)
			}
		},
		"duplicate-and-closed-results": func(t *testing.T, h *signedServerHarness) {
			h.prepare(t)
			if _, err := h.start(h.ctx(t), 1, h.proof(t)); err != nil {
				t.Fatal(err)
			}
			running := h.result(t, 1, true, h.nonce())
			if err := running(h.ctx(t)); err != nil {
				t.Fatal(err)
			}
			// A lost response retries the exact admitted evidence after nonce consumption.
			if err := running(h.ctx(t)); err != nil {
				t.Fatalf("exact result retry: %v", err)
			}
			h.prepare(t)
			if err := h.result(t, 1, true, h.nonce())(h.ctx(t)); connect.CodeOf(err) != connect.CodeAlreadyExists {
				t.Fatalf("replayed revision: %v", err)
			}
			h.prepare(t)
			if err := h.result(t, 2, false, h.nonce())(h.ctx(t)); err != nil {
				t.Fatal(err)
			}
			// A closed action issues no further nonce; the consumed one cannot attest.
			if err := h.result(t, 3, true, h.nonce())(h.ctx(t)); err == nil {
				t.Fatal("result accepted after close")
			}
		},
		"late-result-nonce": func(t *testing.T, h *signedServerHarness) {
			h.prepare(t)
			if _, err := h.start(h.ctx(t), 1, h.proof(t)); err != nil {
				t.Fatal(err)
			}
			h.prepare(t)
			h.exec(t, "UPDATE "+h.table+" SET nonce_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", h.actionID())
			if err := h.result(t, 1, true, h.nonce())(h.ctx(t)); connect.CodeOf(err) != connect.CodePermissionDenied {
				t.Fatalf("expired result nonce: %v", err)
			}
		},
		"mismatched-attestation": func(t *testing.T, h *signedServerHarness) {
			h.prepare(t)
			if _, err := h.start(h.ctx(t), 1, h.proof(t)); err != nil {
				t.Fatal(err)
			}
			h.prepare(t)
			if err := h.result(t, 1, true, bytes.Repeat([]byte{3}, 32))(h.ctx(t)); connect.CodeOf(err) != connect.CodePermissionDenied {
				t.Fatalf("attestation over another nonce: %v", err)
			}
		},
		"ungranted-started-result": func(t *testing.T, h *signedServerHarness) {
			h.prepare(t)
			if err := h.result(t, 1, true, h.nonce())(h.ctx(t)); connect.CodeOf(err) != connect.CodePermissionDenied {
				t.Fatalf("started status without a grant: %v", err)
			}
		},
	}
	for kind, harness := range kinds {
		for name, run := range cases {
			t.Run(kind+"/"+name, func(t *testing.T) { run(t, harness(t)) })
		}
	}
}
