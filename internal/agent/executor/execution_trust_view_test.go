//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestExecutionTrustViewInitialBootstrapIsReadOnly(t *testing.T) {
	now := time.Date(2031, 8, 5, 0, 0, 0, 0, time.UTC)
	svc := openExecutor(t, now)
	if _, err := svc.GetExecutionTrust(t.Context(), connect.NewRequest(&agentv1.GetExecutionTrustRequest{})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("unprovisioned trust view: %v", err)
	}
	fix := newFixture(t, now)
	prepare(t, svc, fix, "lg1_test-grant-secret-with-32-characters-minimum", false)
	before, revision := identityRow(t, svc)
	trustBefore, trustRevision := trustRow(t, svc)
	view := readTrustView(t, svc)
	root := fix.executionRoot(t)
	rootHash := deterministicRootHash(t, root)
	if view.GetRootVersion() != root.GetVersion() || !bytes.Equal(view.GetRootSha256(), rootHash[:]) || !proto.Equal(view.GetRootExpiresAt(), root.GetExpiresAt()) {
		t.Fatal("initial trust view did not report the authenticated bootstrap root")
	}
	if view.GetDelegationVersion() != 0 || len(view.GetDelegationSha256()) != 0 || view.GetMinimumRecoveryEpoch() != 0 || view.GetAcceptedAt() != nil || view.GetDelegationExpiresAt() != nil {
		t.Fatal("initial trust view fabricated delegation acceptance")
	}
	unknown := &agentv1.GetExecutionTrustRequest{}
	unknown.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
	if _, err := svc.GetExecutionTrust(t.Context(), connect.NewRequest(unknown)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("trust view accepted an unknown field: %v", err)
	}
	if _, err := svc.GetExecutionTrust(t.Context(), nil); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("trust view accepted a nil request: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := svc.GetExecutionTrust(ctx, connect.NewRequest(&agentv1.GetExecutionTrustRequest{})); connect.CodeOf(err) != connect.CodeCanceled {
		t.Fatalf("canceled trust view: %v", err)
	}
	svc.clock = func() time.Time { return root.GetExpiresAt().AsTime().Add(time.Hour) }
	if !proto.Equal(view, readTrustView(t, svc)) {
		t.Fatal("expired bootstrap changed the historical unconfigured trust view")
	}
	after, afterRevision := identityRow(t, svc)
	trustAfter, trustAfterRevision := trustRow(t, svc)
	if !proto.Equal(before, after) || revision != afterRevision || !proto.Equal(trustBefore, trustAfter) || trustRevision != trustAfterRevision {
		t.Fatal("trust inspection changed pending enrollment or execution authority")
	}
}

func TestExecutionTrustViewReportsAcceptedRotationAfterExpiryAndRestart(t *testing.T) {
	now := time.Date(2031, 8, 6, 0, 0, 0, 0, time.UTC)
	svc, fix := enrollExecutionTrust(t, now)
	initial := readTrustView(t, svc)
	rejectAuthority(t, svc, delegationUpdate(t, svc.authority, fix, nil, 1, 0, now, testKey(t)))
	if !proto.Equal(initial, readTrustView(t, svc)) {
		t.Fatal("rejected unsigned authority changed the public trust view")
	}
	nextKey := testKey(t)
	next := successorRoot(t, fix.executionRoot(t), nextKey)
	delegation := delegationDocument(fix.deploy.String(), 2, 7, 5, now, delegate(t, testKey(t)))
	request := &agentv1.UpdateExecutionTrustRequest{
		RootTransitions:    []*agentv1.ExecutionRootTransition{rootTransition(t, svc.authority, next, fix.rootKey, nextKey)},
		DelegationEnvelope: mustSign(t, svc.authority, delegation, nextKey),
	}
	callTrust(t, svc, request)
	view := readTrustView(t, svc)
	rootHash, delegationHash := deterministicRootHash(t, next), sha256.Sum256(request.GetDelegationEnvelope())
	if view.GetRootVersion() != 2 || view.GetDelegationVersion() != 7 || view.GetMinimumRecoveryEpoch() != 5 || !bytes.Equal(view.GetRootSha256(), rootHash[:]) || !bytes.Equal(view.GetDelegationSha256(), delegationHash[:]) || !view.GetAcceptedAt().AsTime().Equal(now) || !proto.Equal(view.GetRootExpiresAt(), next.GetExpiresAt()) || !proto.Equal(view.GetDelegationExpiresAt(), delegation.GetExpiresAt()) {
		t.Fatal("trust view disagrees with protected signed acceptance")
	}
	wanted := proto.CloneOf(view)
	view.RootSha256[0] ^= 1
	view.DelegationSha256[0] ^= 1
	view.AcceptedAt.Seconds++
	view.RootExpiresAt.Seconds++
	view.DelegationExpiresAt.Seconds++
	if !proto.Equal(wanted, readTrustView(t, svc)) {
		t.Fatal("public response aliases protected trust state")
	}
	before, revision := trustRow(t, svc)
	expired := next.GetExpiresAt().AsTime().Add(time.Hour)
	svc = reopen(t, svc, expired)
	if !proto.Equal(wanted, readTrustView(t, svc)) {
		t.Fatal("expiry or restart lost the accepted trust view")
	}
	// Historical readability cannot revive the expired root's authorization.
	rejectAuthority(t, svc, &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: mustSign(t, svc.authority, delegationDocument(fix.deploy.String(), 2, 8, 5, expired), nextKey)})
	after, afterRevision := trustRow(t, svc)
	if !proto.Equal(before, after) || revision != afterRevision || !proto.Equal(wanted, readTrustView(t, svc)) {
		t.Fatal("expired-root rejection mutated historical authority")
	}
}

func TestExecutionTrustViewDoesNotObserveOrTransitionPreparedWork(t *testing.T) {
	f := newResourceFixture(t, false)
	pauseResourceConsumer(t, f.svc)
	intent := f.intent(t, 1)
	f.prepare(t, intent)
	before, revision := resourceRow(t, f.svc, intent.GetActionId())
	plans, verifies := f.native.plans.Load(), f.native.verifies.Load()
	// Accept revocation, then expire the root. Neither updates nor inspection
	// may turn retained prepared work into a native effect or fresh observation.
	callTrust(t, f.svc, &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: mustSign(t, f.svc.authority, delegationDocument(f.fix.deploy.String(), 1, 2, 9, f.now), f.fix.rootKey)})
	view := readTrustView(t, f.svc)
	f.wall.Store(f.now.Add(49 * time.Hour).UnixNano())
	f.bootClock.Add(uint64(49 * time.Hour))
	identity, identityRevision := identityRow(t, f.svc)
	trustState, trustRevision := trustRow(t, f.svc)
	if !proto.Equal(view, readTrustView(t, f.svc)) {
		t.Fatal("historical read changed revocation counters or expiry")
	}
	after, afterRevision := resourceRow(t, f.svc, intent.GetActionId())
	identityAfter, identityAfterRevision := identityRow(t, f.svc)
	trustAfter, trustAfterRevision := trustRow(t, f.svc)
	if !proto.Equal(before, after) || revision != afterRevision || !proto.Equal(identity, identityAfter) || identityRevision != identityAfterRevision || !proto.Equal(trustState, trustAfter) || trustRevision != trustAfterRevision {
		t.Fatal("trust view consumed prepared work or changed a protected journal")
	}
	if f.native.plans.Load() != plans || f.native.verifies.Load() != verifies || f.native.applies.Load() != 0 || f.native.effects.Load() != 0 {
		t.Fatal("trust synchronization or inspection touched the native provider")
	}
}

func TestExecutionTrustViewDoesNotRetireExpiredPriorCredential(t *testing.T) {
	now := time.Date(2031, 8, 7, 0, 0, 0, 0, time.UTC)
	svc, fix, pending := pendingRenewalFixture(t, now)
	pauseResourceConsumer(t, svc)
	state := durable(t, svc)
	certificate := fix.leaf(t, publicOf(state.GetPendingRenewal().GetPrivateKey()), uuid.MustParse(state.GetDeviceId()), uuid.MustParse(state.GetEnrollmentGeneration()), now.Add(-time.Minute), now.Add(30*24*time.Hour))
	if _, err := svc.CommitRenewal(t.Context(), connect.NewRequest(&agentv1.CommitRenewalRequest{IssuanceRequestId: pending.GetIssuanceRequestId(), CertificatePem: certificate})); err != nil {
		t.Fatal(err)
	}
	before, revision := identityRow(t, svc)
	prior := before.GetPriorCredential()
	if prior == nil {
		t.Fatal("fixture did not retain an overlapping credential")
	}
	svc.clock = func() time.Time { return prior.GetRetainUntil().AsTime() }
	readTrustView(t, svc)
	after, afterRevision := identityRow(t, svc)
	if !proto.Equal(before, after) || revision != afterRevision {
		t.Fatal("trust view retired an old key or otherwise mutated identity")
	}
	message := append([]byte("                                                                TLS 1.3, client CertificateVerify\x00"), bytes.Repeat([]byte{1}, 32)...)
	hash := sha256.Sum256(parseCert(t, prior.GetCertificatePem()).Raw)
	if _, err := svc.SignTLSClientMessage(t.Context(), connect.NewRequest(&agentv1.SignTLSClientMessageRequest{CertificateSha256: hash[:], Message: message})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("read-only trust view weakened the expired credential fence: %v", err)
	}
	if durable(t, svc).GetPriorCredential() != nil {
		t.Fatal("ordinary credential access no longer retires an expired key")
	}
}

func readTrustView(t *testing.T, svc *Service) *agentv1.GetExecutionTrustResponse {
	t.Helper()
	response, err := svc.GetExecutionTrust(t.Context(), connect.NewRequest(&agentv1.GetExecutionTrustRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("trust view allowed caching of protected state")
	}
	if err := protovalidate.Validate(response.Msg); err != nil {
		t.Fatalf("invalid trust view: %v", err)
	}
	return response.Msg
}

func deterministicRootHash(t *testing.T, root *agentv1.ExecutionRoot) [sha256.Size]byte {
	t.Helper()
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(encoded)
}

func identityRow(t *testing.T, svc *Service) (*agentv1.ExecutorJournalState, int64) {
	t.Helper()
	svc.mu.Lock()
	defer svc.mu.Unlock()
	state, revision, err := svc.store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return state, revision
}
