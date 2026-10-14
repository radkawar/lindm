// SPDX-License-Identifier: Apache-2.0

//go:build linux

package recovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	recoveryv1 "lindm/gen/lindm/recovery/v1"
	"lindm/internal/trust"
)

// This deterministic consumer fixture exercises real DSSE verification and real
// fsync/consumption, not native media or PostgreSQL. Those are separate lanes.
type recoveryTestServer struct {
	t                                *testing.T
	r                                *runner
	start                            ed25519.PrivateKey
	root                             ed25519.PrivateKey
	checkpoint                       *agentv1.RecoveryCheckpoint
	grant                            []byte
	authorizations, effects, reports int
	brokenReceipt                    bool
	replayOriginalBoot               bool
	status                           *agentv1.DeviceActionStatus
	bootstrap                        *trust.Bootstrap
	snapshot                         *agentv1.RecoveryJournal
	acquisitions                     int
}

func (s *recoveryTestServer) check(ctx context.Context, message proto.Message, envelope, proof []byte, operation agentv1.RecoveryOperation) error {
	_, err := s.r.authority.VerifyRecoveryRequestProof(ctx, proof, envelope, s.r.credential, operation, message, s.now())
	return err
}
func (s *recoveryTestServer) AcquireRecoveryWork(ctx context.Context, request *connect.Request[recoveryv1.AcquireRecoveryWorkRequest]) (*connect.Response[recoveryv1.AcquireRecoveryWorkResponse], error) {
	if err := s.check(ctx, new(recoveryv1.AcquireRecoveryWorkRequest), request.Msg.GetCredentialEnvelope(), request.Msg.GetRequestProof(), agentv1.RecoveryOperation_RECOVERY_OPERATION_ACQUIRE_WORK); err != nil {
		return nil, err
	}
	s.acquisitions++
	return connect.NewResponse(&recoveryv1.AcquireRecoveryWorkResponse{IntentEnvelope: s.r.record.GetIntentEnvelope(), ResultNonce: bytes.Repeat([]byte{9}, 32), StartGrantEnvelope: s.grant, Checkpoint: proto.CloneOf(s.checkpoint), TrustUpdate: &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: s.r.record.GetDelegationEnvelope()}, Journal: proto.CloneOf(s.snapshot)}), nil
}
func (s *recoveryTestServer) AuthorizeRecoveryStart(ctx context.Context, request *connect.Request[recoveryv1.AuthorizeRecoveryStartRequest]) (*connect.Response[recoveryv1.AuthorizeRecoveryStartResponse], error) {
	payload := proto.CloneOf(request.Msg)
	payload.CredentialEnvelope = nil
	payload.RequestProof = nil
	if err := s.check(ctx, payload, request.Msg.GetCredentialEnvelope(), request.Msg.GetRequestProof(), agentv1.RecoveryOperation_RECOVERY_OPERATION_AUTHORIZE_START); err != nil {
		return nil, err
	}
	s.authorizations++
	intent := s.r.record.GetHandoff().GetIntent()
	binding := &agentv1.DeviceActionApprovalBinding{DeviceId: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), SpecSha256: intent.GetSpecSha256(), ExpiresAt: intent.GetExpiresAt()}
	challenge := proto.CloneOf(request.Msg.GetChallenge())
	if s.replayOriginalBoot {
		challenge.BootId = s.r.record.GetHandoff().GetOriginalBootId()
	}
	grant := &agentv1.DeviceActionStartGrant{Challenge: challenge, ActorId: intent.GetActorId(), AuthorizationVersion: intent.GetAuthorizationVersion(), RootVersion: 1, DelegationVersion: 1, NotBefore: challenge.GetIssuedAt(), ExpiresAt: challenge.GetExpiresAt(), Approvals: []*agentv1.DeviceActionHumanApproval{{ActorId: intent.GetActorId(), AuthorizationVersion: intent.GetAuthorizationVersion(), Binding: binding}, {ActorId: uuid.NewString(), AuthorizationVersion: 2, Binding: proto.CloneOf(binding)}}}
	encoded, err := s.r.authority.Sign(ctx, grant, s.start)
	if err != nil {
		return nil, err
	}
	s.grant = encoded
	return connect.NewResponse(&recoveryv1.AuthorizeRecoveryStartResponse{StartGrantEnvelope: encoded}), nil
}
func (s *recoveryTestServer) CheckpointRecoveryAction(ctx context.Context, request *connect.Request[recoveryv1.CheckpointRecoveryActionRequest]) (*connect.Response[recoveryv1.CheckpointRecoveryActionResponse], error) {
	payload := proto.CloneOf(request.Msg)
	payload.CredentialEnvelope = nil
	payload.RequestProof = nil
	if err := s.check(ctx, payload, request.Msg.GetCredentialEnvelope(), request.Msg.GetRequestProof(), agentv1.RecoveryOperation_RECOVERY_OPERATION_CHECKPOINT); err != nil {
		return nil, err
	}
	checkpoint := request.Msg.GetCheckpoint()
	if checkpoint.GetPhase() == agentv1.RecoveryPhase_RECOVERY_PHASE_EFFECT_COMMITTED {
		consumed, err := s.r.journal.Consumed()
		if err != nil || !consumed {
			s.t.Fatalf("server commit preceded local reservation: %v %v", consumed, err)
		}
		s.effects++
	}
	s.checkpoint = proto.CloneOf(checkpoint)
	digest, err := trust.DeviceActionDigest(checkpoint)
	if err != nil {
		return nil, err
	}
	receipt := &agentv1.RecoveryCheckpointReceipt{CredentialId: checkpoint.GetCredentialId(), ActionId: checkpoint.GetActionId(), Sequence: checkpoint.GetSequence(), CheckpointSha256: digest[:], StoredAt: timestamppb.New(s.now()), RootVersion: 1, DelegationVersion: 1}
	if s.brokenReceipt && checkpoint.GetPhase() == agentv1.RecoveryPhase_RECOVERY_PHASE_EFFECT_COMMITTED {
		receipt.CheckpointSha256 = bytes.Repeat([]byte{99}, 32)
	}
	encoded, err := s.r.authority.Sign(ctx, receipt, s.start)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&recoveryv1.CheckpointRecoveryActionResponse{CheckpointSha256: digest[:], Sequence: checkpoint.GetSequence(), ReceiptEnvelope: encoded}), nil
}
func (s *recoveryTestServer) ReportRecoveryResult(ctx context.Context, request *connect.Request[recoveryv1.ReportRecoveryResultRequest]) (*connect.Response[recoveryv1.ReportRecoveryResultResponse], error) {
	payload := proto.CloneOf(request.Msg)
	payload.CredentialEnvelope = nil
	payload.RequestProof = nil
	if err := s.check(ctx, payload, request.Msg.GetCredentialEnvelope(), request.Msg.GetRequestProof(), agentv1.RecoveryOperation_RECOVERY_OPERATION_REPORT_RESULT); err != nil {
		return nil, err
	}
	if err := protovalidate.Validate(request.Msg.GetStatus()); err != nil {
		return nil, err
	}
	s.reports++
	s.status = proto.CloneOf(request.Msg.GetStatus())
	return connect.NewResponse(&recoveryv1.ReportRecoveryResultResponse{Closed: true}), nil
}

type recoveryTestProvider struct {
	plan    *agentv1.DeviceActionPlan
	server  *recoveryTestServer
	effects int
}

func (p *recoveryTestProvider) Observe(context.Context, *agentv1.DeviceActionSpec) (*agentv1.DeviceActionObservation, error) {
	return proto.CloneOf(p.plan.GetBefore()), nil
}
func (p *recoveryTestProvider) Plan(context.Context, *agentv1.DeviceActionSpec, *agentv1.DeviceActionObservation) (*agentv1.DeviceActionPlan, error) {
	return proto.CloneOf(p.plan), nil
}
func (p *recoveryTestProvider) Apply(ctx context.Context, plan *agentv1.DeviceActionPlan, _ []byte, gate func(context.Context) error) (*agentv1.DeviceActionVerification, error) {
	if err := gate(ctx); err != nil {
		return nil, err
	}
	if p.server.effects != 1 {
		return nil, errors.New("native effect preceded server checkpoint")
	}
	p.effects++
	return &agentv1.DeviceActionVerification{Verified: true, After: proto.CloneOf(plan.GetBefore()), Evidence: "deterministic native consumer boundary fixture"}, nil
}
func (p *recoveryTestProvider) Verify(_ context.Context, _ *agentv1.DeviceActionPlan, result *agentv1.DeviceActionVerification) (*agentv1.DeviceActionVerification, error) {
	return proto.CloneOf(result), nil
}

func newRecoveryRunnerFixture(t *testing.T) (*runner, *recoveryTestServer, *recoveryTestProvider) {
	t.Helper()
	return newRecoveryRunnerFixtureAt(t, time.Now())
}

func newRecoveryRunnerFixtureAt(t *testing.T, at time.Time) (*runner, *recoveryTestServer, *recoveryTestProvider) {
	t.Helper()
	authority, key, credential, now := recoveryProofFixtureAt(t, at)
	makeKey := func() ed25519.PrivateKey {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	rootKey, startKey, planKey, caKey := makeKey(), makeKey(), makeKey(), makeKey()
	executionKey := func(k ed25519.PrivateKey) *agentv1.ExecutionKey {
		public, ok := k.Public().(ed25519.PublicKey)
		if !ok {
			t.Fatal("fixture key is not Ed25519")
		}
		id, err := trust.KeyID(public)
		if err != nil {
			t.Fatal(err)
		}
		return &agentv1.ExecutionKey{KeyId: id, PublicKey: public}
	}
	root := &agentv1.ExecutionRoot{DeploymentId: credential.GetHandoff().GetIntent().GetDeploymentId(), Version: 1, Threshold: 1, NotBefore: timestamppb.New(now.Add(-time.Hour)), ExpiresAt: timestamppb.New(now.Add(time.Hour)), Keys: []*agentv1.ExecutionKey{executionKey(rootKey)}}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	release, err := metadata.Root(now.Add(time.Hour)).ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	// Already-trusted constructor material: bootstrap authentication itself is
	// covered by trust's tests, rather than mocked as a network observation.
	bootstrap := &trust.Bootstrap{Root: root, Bundle: &agentv1.BootstrapBundle{DeploymentId: root.GetDeploymentId(), TransportCaPem: ca, DeviceCaPem: ca, ReleaseRootJson: release}}
	verifier, err := authority.NewExecutionVerifier(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	delegation := &agentv1.ExecutionDelegation{DeploymentId: root.GetDeploymentId(), RootVersion: 1, Version: 1, NotBefore: timestamppb.New(now.Add(-time.Minute)), ExpiresAt: timestamppb.New(now.Add(30 * time.Minute)), Delegates: []*agentv1.ExecutionDelegate{{Key: executionKey(planKey), Role: agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, Capabilities: []string{"device.sanitize.v1"}}, {Key: executionKey(startKey), Role: agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, Capabilities: []string{"device.sanitize.v1"}}}}
	delegationEnvelope, err := authority.Sign(t.Context(), delegation, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	delegation, err = verifier.VerifyDelegation(t.Context(), root, delegationEnvelope, 0, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := journal.Close(); err != nil {
			t.Error(err)
		}
	})
	validator, err := protovalidate.New()
	if err != nil {
		t.Fatal(err)
	}
	plan := proto.CloneOf(credential.GetHandoff().GetChallenge().GetNativePlan())
	plan.Before.RecoveryEnvironment = true
	plan.Before.OffTargetJournal = true
	r := &runner{journal: journal, key: key, bootID: uuid.NewString(), incarnation: uuid.NewString(), clock: &Clock{ready: true, serverTime: now, monotonic: func() (time.Duration, error) { return 0, nil }}, boottime: func() (time.Duration, error) { return time.Second, nil }, authority: authority, verifier: verifier, validator: validator, credential: credential, delegation: delegation, record: &agentv1.RecoveryJournal{FormatVersion: 1, Handoff: credential.GetHandoff(), CredentialEnvelope: []byte("retained signed credential fixture"), IntentEnvelope: []byte("retained intent fixture"), AcceptedRoot: root, DelegationEnvelope: delegationEnvelope, CredentialRoot: root, CredentialDelegationEnvelope: delegationEnvelope, State: agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED, Failure: agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_NONE, AcceptedAt: timestamppb.New(now)}}
	intentEnvelope, err := authority.Sign(t.Context(), credential.GetHandoff().GetIntent(), planKey)
	if err != nil {
		t.Fatal(err)
	}
	intentDigest := sha256.Sum256(intentEnvelope)
	credential.Handoff.IntentSha256 = intentDigest[:]
	credential.Handoff.Challenge.IntentSha256 = intentDigest[:]
	credentialEnvelope, err := authority.Sign(t.Context(), credential, startKey)
	if err != nil {
		t.Fatal(err)
	}
	r.record.IntentEnvelope = intentEnvelope
	r.record.CredentialEnvelope = credentialEnvelope
	r.record.TrustAcceptedAt = timestamppb.New(now)
	rootDigest, err := trust.ExecutionRootDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	r.clock.floor = recoveryTrustFloor{rootVersion: 1, delegationVersion: 1, rootSHA256: rootDigest, delegationSHA256: sha256.Sum256(delegationEnvelope)}
	server := &recoveryTestServer{t: t, r: r, start: startKey, root: rootKey, bootstrap: bootstrap}
	provider := &recoveryTestProvider{plan: plan, server: server}
	r.client = server
	r.provider = provider
	return r, server, provider
}

func TestRecoveryRunCommitsBothCheckpointsBeforeEffect(t *testing.T) {
	r, server, provider := newRecoveryRunnerFixture(t)
	if err := r.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if server.authorizations != 1 || server.effects != 1 || provider.effects != 1 || server.reports != 1 || server.status.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED {
		t.Fatalf("incomplete execution: grants=%d commits=%d native=%d reports=%d status=%v", server.authorizations, server.effects, provider.effects, server.reports, server.status)
	}
	if !proto.Equal(server.status.GetBefore(), r.record.GetChallenge().GetNativePlan().GetBefore()) {
		t.Fatal("successful report lost the recovery-boot preflight observation")
	}
	if r.record.GetStartedAt() == nil || r.record.GetCompletedAt() == nil {
		t.Fatal("terminal timing was not durable")
	}
}
func TestRecoveryRunRejectsMismatchedSignedReceipt(t *testing.T) {
	r, server, provider := newRecoveryRunnerFixture(t)
	server.brokenReceipt = true
	if err := r.run(t.Context()); err == nil {
		t.Fatal("bad signed checkpoint receipt accepted")
	}
	if provider.effects != 0 {
		t.Fatal("effect ran without exact server receipt")
	}
	consumed, err := r.journal.Consumed()
	if err != nil || !consumed {
		t.Fatalf("ambiguous checkpoint did not consume: %v %v", consumed, err)
	}
	if r.record.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN {
		t.Fatal("ambiguous acknowledgment not retained unknown")
	}
}
func TestRecoveryRunNeverReplaysOriginalBootGrant(t *testing.T) {
	r, server, provider := newRecoveryRunnerFixture(t)
	server.replayOriginalBoot = true
	if err := r.run(t.Context()); err == nil {
		t.Fatal("original boot grant accepted")
	}
	if provider.effects != 0 || server.effects != 0 {
		t.Fatal("crossboot grant consumed")
	}
}
func TestRecoveryRunPriorReservationReportsUnknownWithoutReexecution(t *testing.T) {
	r, server, provider := newRecoveryRunnerFixture(t)
	if err := r.journal.Consume(); err != nil {
		t.Fatal(err)
	}
	if err := r.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if provider.effects != 0 || server.authorizations != 0 || server.status.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN {
		t.Fatal("prior effect reservation was replayed")
	}
	if !proto.Equal(server.status.GetBefore(), r.record.GetHandoff().GetChallenge().GetNativePlan().GetBefore()) {
		t.Fatal("unknown report lost the retained handoff observation")
	}
}

func TestRecoveryRunRejectsChangedMediaBeforeStart(t *testing.T) {
	r, server, provider := newRecoveryRunnerFixture(t)
	provider.plan.Before.Target.Serial = "replacement-disk"
	if err := r.run(t.Context()); err == nil {
		t.Fatal("changed native media accepted")
	}
	if server.authorizations != 0 || server.effects != 0 || provider.effects != 0 {
		t.Fatal("changed media obtained authority or effect")
	}
	if server.status.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_FAILED || server.status.GetFailure() != agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_PRECONDITION {
		t.Fatal("changed media was not reported as precondition failure")
	}
	if !proto.Equal(server.status.GetBefore(), r.record.GetHandoff().GetChallenge().GetNativePlan().GetBefore()) {
		t.Fatal("rejected media replaced the approved handoff observation")
	}
}

func (s *recoveryTestServer) now() time.Time {
	s.t.Helper()
	now, _, err := s.r.now()
	if err != nil {
		s.t.Fatal(err)
	}
	return now
}

func (s *recoveryTestServer) GetRecoveryTime(ctx context.Context, request *connect.Request[recoveryv1.GetRecoveryTimeRequest]) (*connect.Response[recoveryv1.GetRecoveryTimeResponse], error) {
	digest, err := trust.DeviceActionDigest(request.Msg)
	if err != nil {
		return nil, err
	}
	now := s.now()
	statement := &agentv1.RecoveryTimeStatement{DeploymentId: s.r.record.GetAcceptedRoot().GetDeploymentId(), RequestSha256: digest[:], ServerTime: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(30 * time.Second)), RootVersion: 1, DelegationVersion: 1}
	envelope, err := s.r.authority.Sign(ctx, statement, s.start)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&recoveryv1.GetRecoveryTimeResponse{ServerTime: statement.GetServerTime(), TimeEnvelope: envelope, TrustUpdate: &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: s.r.record.GetDelegationEnvelope()}}), nil
}
