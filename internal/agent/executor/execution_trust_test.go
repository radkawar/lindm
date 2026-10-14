// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/rpcreason"
	"lindm/internal/trust"
)

func TestExecutionTrustRequiresEnrolledIdentity(t *testing.T) {
	now := time.Date(2031, 8, 1, 0, 0, 0, 0, time.UTC)
	fix := newFixture(t, now)
	svc := openExecutor(t, now)
	prepare(t, svc, fix, "lg1_test-grant-secret-with-32-characters-minimum", false)
	authority, err := trust.New()
	if err != nil {
		t.Fatal(err)
	}
	req := delegationUpdate(t, authority, fix, nil, 1, 0, now, testKey(t))
	if _, err := svc.UpdateExecutionTrust(t.Context(), connect.NewRequest(req)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("unenrolled execution trust update: %v", err)
	}
	status, err := svc.Status(t.Context(), connect.NewRequest(&agentv1.StatusRequest{}))
	if err != nil || status.Msg.GetLifecycle() != agentv1.Lifecycle_LIFECYCLE_PENDING_ENROLLMENT || status.Msg.GetHoldReason() != agentv1.HoldReason_HOLD_REASON_NONE {
		t.Fatalf("unenrolled rejection became hold or enrollment: %v", err)
	}
	recorded, revision := trustRow(t, svc)
	if recorded.GetRoot() != nil || revision != 1 {
		t.Fatal("unenrolled rejection configured execution trust")
	}
}

func TestExecutionTrustRotationsFencesAndRestart(t *testing.T) {
	now := time.Date(2031, 8, 2, 3, 4, 5, 0, time.UTC)
	svc, fix := enrollExecutionTrust(t, now)
	authority, err := trust.New()
	if err != nil {
		t.Fatal(err)
	}
	pins := durable(t, svc)
	current := fix.executionRoot(t)
	if recorded, revision := trustRow(t, svc); recorded.GetRoot() != nil || revision != 1 || recorded.GetInstallationId() != pins.GetInstallationId() {
		t.Fatal("enrolled installation did not start from an unbound execution trust row")
	}

	gapKey := testKey(t)
	gapped := proto.CloneOf(current)
	gapped.Version = 3
	gapped.Keys = []*agentv1.ExecutionKey{executionPublic(t, gapKey)}
	rejectAuthority(t, svc, &agentv1.UpdateExecutionTrustRequest{
		RootTransitions:    []*agentv1.ExecutionRootTransition{rootTransition(t, authority, gapped, fix.rootKey, gapKey)},
		DelegationEnvelope: mustSign(t, authority, delegationDocument(fix.deploy.String(), 3, 9, 0, now, delegate(t, testKey(t))), gapKey),
	})
	wrongKey := testKey(t)
	nextKey := testKey(t)
	next := successorRoot(t, current, nextKey)
	rejectAuthority(t, svc, &agentv1.UpdateExecutionTrustRequest{
		RootTransitions:    []*agentv1.ExecutionRootTransition{rootTransition(t, authority, next, wrongKey, nextKey)},
		DelegationEnvelope: mustSign(t, authority, delegationDocument(fix.deploy.String(), 2, 2, 1, now, delegate(t, testKey(t))), nextKey),
	})
	unknown := delegationUpdate(t, authority, fix, nil, 1, 0, now, testKey(t))
	unknown.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
	if _, err := svc.UpdateExecutionTrust(t.Context(), connect.NewRequest(unknown)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("unknown execution trust field: %v", err)
	}
	if recorded, revision := trustRow(t, svc); recorded.GetRoot() != nil || revision != 1 {
		t.Fatal("rejected authority configured execution trust")
	}
	assertEnrolled(t, svc)

	initialReq := delegationUpdate(t, authority, fix, nil, 1, 0, now, fix.rootKey)
	initial := callTrust(t, svc, initialReq)
	if initial.GetRootVersion() != 1 || initial.GetDelegationVersion() != 1 || initial.GetMinimumRecoveryEpoch() != 0 || !initial.GetExpiresAt().AsTime().Equal(now.Add(2*time.Hour)) {
		t.Fatalf("initial receipt = %+v", initial)
	}
	initialRow, initialRevision := trustRow(t, svc)
	if initialRow.GetRoot().GetVersion() != 1 || !bytes.Equal(initialRow.GetDelegationEnvelope(), initialReq.GetDelegationEnvelope()) || initialRevision != 2 {
		t.Fatal("initial delegation was not committed before acknowledgment")
	}

	secondKey := testKey(t)
	thirdKey := testKey(t)
	second := successorRoot(t, current, secondKey)
	third := successorRoot(t, second, thirdKey)
	delegateKey := testKey(t)
	rotatedDelegation := delegationDocument(fix.deploy.String(), 3, 4, 7, now, delegate(t, delegateKey))
	rotatedReq := &agentv1.UpdateExecutionTrustRequest{
		RootTransitions: []*agentv1.ExecutionRootTransition{
			rootTransition(t, authority, second, fix.rootKey, secondKey),
			rootTransition(t, authority, third, secondKey, thirdKey),
		},
		DelegationEnvelope: mustSign(t, authority, rotatedDelegation, thirdKey),
	}
	rotated := callTrust(t, svc, rotatedReq)
	if rotated.GetRootVersion() != 3 || rotated.GetDelegationVersion() != 4 || rotated.GetMinimumRecoveryEpoch() != 7 || !rotated.GetExpiresAt().AsTime().Equal(rotatedDelegation.GetExpiresAt().AsTime()) {
		t.Fatalf("rotation receipt = %+v", rotated)
	}
	rotatedRow, rotatedRevision := trustRow(t, svc)
	if rotatedRow.GetRoot().GetVersion() != 3 || rotatedRow.GetDelegationVersion() != 4 || rotatedRow.GetMinimumRecoveryEpoch() != 7 || !bytes.Equal(rotatedRow.GetDelegationEnvelope(), rotatedReq.GetDelegationEnvelope()) {
		t.Fatal("sequential rotation was not durable")
	}

	svc = reopen(t, svc, now.Add(30*time.Minute))
	replayed := callTrust(t, svc, rotatedReq)
	if !proto.Equal(replayed, rotated) {
		t.Fatal("exact retry changed the historical receipt")
	}
	if _, revision := trustRow(t, svc); revision != rotatedRevision {
		t.Fatal("exact retry committed another execution trust revision")
	}
	rejectAuthority(t, svc, initialReq)
	rejectAuthority(t, svc, &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: mustSign(t, authority, delegationDocument(fix.deploy.String(), 3, 5, 6, now.Add(30*time.Minute), delegate(t, testKey(t))), thirdKey)})
	wrapped := proto.CloneOf(rotatedReq)
	wrapped.RootTransitions = append(wrapped.RootTransitions, rootTransition(t, authority, successorRoot(t, third, testKey(t)), wrongKey, testKey(t)))
	rejectAuthority(t, svc, wrapped)
	fourthKey := testKey(t)
	fourth := successorRoot(t, third, fourthKey)
	fifthKey := testKey(t)
	partial := &agentv1.UpdateExecutionTrustRequest{
		RootTransitions: []*agentv1.ExecutionRootTransition{
			rootTransition(t, authority, fourth, thirdKey, fourthKey),
			rootTransition(t, authority, successorRoot(t, fourth, fifthKey), wrongKey, fifthKey),
		},
		DelegationEnvelope: mustSign(t, authority, delegationDocument(fix.deploy.String(), 5, 8, 7, now.Add(30*time.Minute), delegate(t, testKey(t))), fifthKey),
	}
	rejectAuthority(t, svc, partial)
	if row, revision := trustRow(t, svc); revision != rotatedRevision || row.GetRoot().GetVersion() != 3 || !bytes.Equal(row.GetDelegationEnvelope(), rotatedReq.GetDelegationEnvelope()) {
		t.Fatal("rejected rotation or rollback replaced committed authority")
	}
	assertEnrolled(t, svc)

	svc.clock = func() time.Time { return now.Add(-time.Minute) }
	rejectAuthority(t, svc, &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: mustSign(t, authority, delegationDocument(fix.deploy.String(), 3, 5, 7, now.Add(-time.Minute), delegate(t, testKey(t))), thirdKey)})
	if !proto.Equal(callTrust(t, svc, rotatedReq), rotated) {
		t.Fatal("clock regression blocked the historical receipt")
	}
	later := now.Add(3 * time.Hour)
	svc.clock = func() time.Time { return later }
	assertEnrolled(t, svc)
	expiredReplay := callTrust(t, svc, rotatedReq)
	if !expiredReplay.GetExpiresAt().AsTime().Equal(rotated.GetExpiresAt().AsTime()) || expiredReplay.GetDelegationVersion() != rotated.GetDelegationVersion() {
		t.Fatal("expired delegation was treated as corruption or its expiry was extended")
	}
	revocation := &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: mustSign(t, authority, delegationDocument(fix.deploy.String(), 3, 5, 7, later), thirdKey)}
	renewed := callTrust(t, svc, revocation)
	if renewed.GetRootVersion() != 3 || renewed.GetDelegationVersion() != 5 || renewed.GetMinimumRecoveryEpoch() != 7 || !bytes.Equal(trustRowMessage(t, svc).GetDelegationEnvelope(), revocation.GetDelegationEnvelope()) {
		t.Fatal("empty revocation snapshot was not committed")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	beforeCancel := trustRowMessage(t, svc)
	if _, err := svc.UpdateExecutionTrust(ctx, connect.NewRequest(delegationUpdate(t, authority, fix, nil, 6, 7, later, testKey(t)))); connect.CodeOf(err) != connect.CodeCanceled && !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled trust update: %v", err)
	}
	if !proto.Equal(beforeCancel, trustRowMessage(t, svc)) {
		t.Fatal("canceled trust update was acknowledged or partially committed")
	}
	assertPins(t, pins, durable(t, svc))
	message := append([]byte("                                                                TLS 1.3, client CertificateVerify\x00"), bytes.Repeat([]byte{1}, 32)...)
	hash := sha256.Sum256(parseCert(t, durable(t, svc).GetCertificatePem()).Raw)
	signed, err := svc.SignTLSClientMessage(t.Context(), connect.NewRequest(&agentv1.SignTLSClientMessageRequest{CertificateSha256: hash[:], Message: message}))
	if err != nil {
		t.Fatal(err)
	}
	want, err := trust.SignTLSClientMessage(ed25519.PrivateKey(durable(t, svc).GetIdentityPrivateKey()), message)
	if err != nil || !bytes.Equal(signed.Msg.GetSignature(), want) {
		t.Fatalf("execution trust rotation changed the TLS signing pin: %v", err)
	}
}

func TestDamagedExecutionTrustRemainsHeldAcrossRestartAndInspection(t *testing.T) {
	now := time.Date(2024, 8, 2, 3, 4, 5, 0, time.UTC)
	svc, fix := enrollExecutionTrust(t, now)
	authority, err := trust.New()
	if err != nil {
		t.Fatal(err)
	}
	request := delegationUpdate(t, authority, fix, nil, 1, 0, now, fix.rootKey)
	callTrust(t, svc, request)
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	status, err := Inspect(t.Context(), svc.directory)
	if err != nil || status.GetLifecycle() != agentv1.Lifecycle_LIFECYCLE_ENROLLED {
		t.Fatalf("historically valid expired trust was held: %v, %v", status, err)
	}
	svc = reopen(t, svc, now)
	recorded, revision := trustRow(t, svc)
	// Structurally valid storage damage: the signed version remains one.
	recorded.DelegationVersion++
	if _, err := svc.store.UpdateExecutionTrust(t.Context(), revision, recorded); err != nil {
		t.Fatal(err)
	}
	live, err := svc.Status(t.Context(), connect.NewRequest(&agentv1.StatusRequest{}))
	if err != nil || live.Msg.GetLifecycle() != agentv1.Lifecycle_LIFECYCLE_RECOVERY_HOLD {
		t.Errorf("live status hid damaged execution trust: %v, %v", live, err)
	}
	if _, err := svc.UpdateExecutionTrust(t.Context(), connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("damaged trust did not hold update: %v", err)
	}
	if _, err := svc.GetExecutionTrust(t.Context(), connect.NewRequest(&agentv1.GetExecutionTrustRequest{})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("damaged trust was reported as an authenticated public view: %v", err)
	}
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	status, err = Inspect(t.Context(), svc.directory)
	if err != nil || status.GetLifecycle() != agentv1.Lifecycle_LIFECYCLE_RECOVERY_HOLD || status.GetHoldReason() != agentv1.HoldReason_HOLD_REASON_INCOMPLETE_OR_CORRUPT {
		t.Errorf("offline inspection lost the trust hold: %v, %v", status, err)
	}
	svc = reopen(t, svc, now)
	live, err = svc.Status(t.Context(), connect.NewRequest(&agentv1.StatusRequest{}))
	if err != nil || live.Msg.GetLifecycle() != agentv1.Lifecycle_LIFECYCLE_RECOVERY_HOLD {
		t.Errorf("restart lost the trust hold: %v, %v", live, err)
	}
	if _, err := svc.GetConnection(t.Context(), connect.NewRequest(&agentv1.GetConnectionRequest{})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("damaged trust released connection credentials: %v", err)
	}
	if _, err := svc.GetExecutionTrust(t.Context(), connect.NewRequest(&agentv1.GetExecutionTrustRequest{})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("restart reported damaged trust as an authenticated public view: %v", err)
	}
}

func enrollExecutionTrust(t *testing.T, now time.Time) (*Service, fixture) {
	t.Helper()
	fix := newFixture(t, now)
	svc := openExecutor(t, now)
	prepare(t, svc, fix, "lg1_test-grant-secret-with-32-characters-minimum", false)
	device, generation := uuid.New(), uuid.New()
	cert := fix.leaf(t, publicOf(durable(t, svc).GetIdentityPrivateKey()), device, generation, now.Add(-time.Minute), now.Add(30*24*time.Hour))
	if _, err := svc.InstallEnrollment(t.Context(), connect.NewRequest(&agentv1.InstallEnrollmentRequest{DeviceId: device.String(), EnrollmentGeneration: generation.String(), CertificatePem: cert})); err != nil {
		t.Fatal(err)
	}
	return svc, fix
}

func (f fixture) executionRoot(t *testing.T) *agentv1.ExecutionRoot {
	t.Helper()
	root := &agentv1.ExecutionRoot{}
	if err := protojson.Unmarshal(f.root, root); err != nil {
		t.Fatal(err)
	}
	return root
}

func delegationUpdate(t *testing.T, authority *trust.Authority, fix fixture, transitions []*agentv1.ExecutionRootTransition, version, epoch uint64, now time.Time, signer ed25519.PrivateKey) *agentv1.UpdateExecutionTrustRequest {
	t.Helper()
	rootVersion := uint64(1)
	if len(transitions) > 0 {
		rootVersion = uint64(len(transitions) + 1)
	}
	return &agentv1.UpdateExecutionTrustRequest{
		RootTransitions:    transitions,
		DelegationEnvelope: mustSign(t, authority, delegationDocument(fix.deploy.String(), rootVersion, version, epoch, now, delegate(t, testKey(t))), signer),
	}
}

func delegationDocument(deployment string, rootVersion, version, epoch uint64, now time.Time, delegates ...*agentv1.ExecutionDelegate) *agentv1.ExecutionDelegation {
	return &agentv1.ExecutionDelegation{
		DeploymentId: deployment, RootVersion: rootVersion, Version: version, MinimumRecoveryEpoch: epoch,
		NotBefore: timestamppb.New(now.Add(-time.Minute)), ExpiresAt: timestamppb.New(now.Add(2 * time.Hour)),
		Delegates: delegates,
	}
}

func delegate(t *testing.T, key ed25519.PrivateKey) *agentv1.ExecutionDelegate {
	t.Helper()
	return &agentv1.ExecutionDelegate{
		Key: executionPublic(t, key), Role: agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN,
		Capabilities: []string{"systemd.service.v1"},
	}
}

func executionPublic(t *testing.T, key ed25519.PrivateKey) *agentv1.ExecutionKey {
	t.Helper()
	public := ed25519.PublicKey(key[ed25519.SeedSize:])
	id, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1.ExecutionKey{KeyId: id, PublicKey: append([]byte(nil), public...)}
}

func successorRoot(t *testing.T, current *agentv1.ExecutionRoot, key ed25519.PrivateKey) *agentv1.ExecutionRoot {
	t.Helper()
	next := proto.CloneOf(current)
	next.Version++
	next.Threshold = 1
	next.Keys = []*agentv1.ExecutionKey{executionPublic(t, key)}
	return next
}

func rootTransition(t *testing.T, authority *trust.Authority, next *agentv1.ExecutionRoot, previous, upcoming ed25519.PrivateKey) *agentv1.ExecutionRootTransition {
	t.Helper()
	return &agentv1.ExecutionRootTransition{
		PreviousQuorumEnvelope: mustSign(t, authority, next, previous),
		NextQuorumEnvelope:     mustSign(t, authority, next, upcoming),
	}
}

func mustSign(t *testing.T, authority *trust.Authority, message proto.Message, keys ...ed25519.PrivateKey) []byte {
	t.Helper()
	encoded, err := authority.Sign(t.Context(), message, keys...)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func callTrust(t *testing.T, svc *Service, req *agentv1.UpdateExecutionTrustRequest) *agentv1.UpdateExecutionTrustResponse {
	t.Helper()
	res, err := svc.UpdateExecutionTrust(t.Context(), connect.NewRequest(req))
	if err != nil {
		t.Fatal(err)
	}
	return res.Msg
}

func rejectAuthority(t *testing.T, svc *Service, req *agentv1.UpdateExecutionTrustRequest) {
	t.Helper()
	_, err := svc.UpdateExecutionTrust(t.Context(), connect.NewRequest(req))
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) || connectErr.Code() != connect.CodePermissionDenied || rpcreason.Get(connectErr) != "execution_trust_rejected" {
		t.Fatalf("cryptographic update was not an authority denial: %v", err)
	}
}

func trustRow(t *testing.T, svc *Service) (*agentv1.ExecutionTrustState, int64) {
	t.Helper()
	svc.mu.Lock()
	defer svc.mu.Unlock()
	state, revision, err := svc.store.LoadExecutionTrust(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return state, revision
}

func trustRowMessage(t *testing.T, svc *Service) *agentv1.ExecutionTrustState {
	t.Helper()
	state, _ := trustRow(t, svc)
	return state
}

func assertEnrolled(t *testing.T, svc *Service) {
	t.Helper()
	status, err := svc.Status(t.Context(), connect.NewRequest(&agentv1.StatusRequest{}))
	if err != nil || status.Msg.GetLifecycle() != agentv1.Lifecycle_LIFECYCLE_ENROLLED || status.Msg.GetHoldReason() != agentv1.HoldReason_HOLD_REASON_NONE {
		t.Fatalf("execution trust rejection entered hold: lifecycle=%v hold=%v err=%v", status.Msg.GetLifecycle(), status.Msg.GetHoldReason(), err)
	}
}

func assertPins(t *testing.T, before, after *agentv1.ExecutorJournalState) {
	t.Helper()
	if before.GetDeviceId() != after.GetDeviceId() || before.GetEnrollmentGeneration() != after.GetEnrollmentGeneration() || before.GetSessionEpoch() != after.GetSessionEpoch() || !bytes.Equal(before.GetCertificatePem(), after.GetCertificatePem()) || !bytes.Equal(before.GetIdentityPrivateKey(), after.GetIdentityPrivateKey()) || !bytes.Equal(before.GetExecutionRootJson(), after.GetExecutionRootJson()) || !bytes.Equal(before.GetBootstrapEnvelope(), after.GetBootstrapEnvelope()) {
		t.Fatal("execution trust update changed identity, session, or TLS enrollment pins")
	}
}
