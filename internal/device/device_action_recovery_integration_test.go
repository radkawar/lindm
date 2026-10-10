//go:build integration

package device

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	recoveryv1 "lindm/gen/lindm/recovery/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/trust"
)

type actionRecoveryFixture struct {
	*deviceActionFixture
	key               ed25519.PrivateKey
	credential        *agentv1.DeviceActionRecoveryCredential
	envelope          []byte
	work              *devicev1.DeviceActionWork
	journal           *agentv1.RecoveryJournal
	boot, incarnation string
}

func newActionRecoveryFixture(t *testing.T) *actionRecoveryFixture {
	t.Helper()
	f := newDeviceActionFixture(t)
	target := &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, Wwn: "isolated-original-root-wwn", Serial: "isolated-original-root", SizeBytes: 1 << 30}
	f.observeStorageTargets(t, target)
	client, imageDigest := recoveryArtifactFixture(t, []byte("signed recovery admission fixture"))
	f.svc.recoveryArtifacts = client
	f.observeRecoveryReadiness(t, recoveryObservationFixture(time.Now()))
	media, err := trust.DeviceActionDigest(target)
	if err != nil {
		t.Fatal(err)
	}
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Sanitize{Sanitize: &agentv1.SanitizeAction{Target: target, Method: agentv1.SanitizeMethod_SANITIZE_METHOD_OVERWRITE, Recovery: &agentv1.RecoveryBootSpec{ImageSha256: imageDigest, MediaSha256: media[:], BootMode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI}}}}
	request := f.request(spec)
	f.approval(t, request)
	f.create(t, request)
	work := f.work(t)
	original := f.challenge(t, work)
	original.NativePlan.Before.Target = target
	original.NativePlan.Before.RecoveryEnvironment = false
	original.NativePlan.Before.OffTargetJournal = false
	original.NativePlanSha256, err = actionDigest(original.NativePlan)
	if err != nil {
		t.Fatal(err)
	}
	planDigest, err := trust.RecoveryPlanDigest(original.NativePlan)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519Key(t)
	handoff := &agentv1.DeviceActionRecoveryHandoff{Intent: f.intent(t, work), IntentSha256: original.GetIntentSha256(), Challenge: original, NativePlanSha256: planDigest[:], RecoveryImageSha256: spec.GetSanitize().GetRecovery().GetImageSha256(), MediaSha256: media[:], RecoveryPublicKey: ed25519.PublicKey(key[ed25519.SeedSize:]), OriginalBootId: original.GetBootId(), ExpiresAt: request.GetExpiresAt(), Custody: agentv1.RecoveryCustody_RECOVERY_CUSTODY_OFF_TARGET}
	registered, err := f.svc.RegisterDeviceActionRecovery(f.deviceCtx(), connect.NewRequest(&devicev1.RegisterDeviceActionRecoveryRequest{SessionEpoch: 1, ActionId: work.GetActionId(), HandoffProof: f.sign(t, handoff), CertificatePem: f.certificate}))
	if err != nil {
		t.Fatal(err)
	}
	credential := new(agentv1.DeviceActionRecoveryCredential)
	if err := f.svc.authority.Verify(t.Context(), registered.Msg.GetCredentialEnvelope(), credential, 1, ed25519.PublicKey(f.svc.signing.StartKey[ed25519.SeedSize:])); err != nil {
		t.Fatal(err)
	}
	snapshot, err := f.svc.execution.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	now := timestamppb.Now()
	journal := &agentv1.RecoveryJournal{FormatVersion: 1, CredentialEnvelope: registered.Msg.GetCredentialEnvelope(), IntentEnvelope: work.GetIntentEnvelope(), AcceptedRoot: snapshot.Root, DelegationEnvelope: snapshot.DelegationEnvelope, Handoff: handoff, State: agentv1.DeviceActionState_DEVICE_ACTION_STATE_QUEUED, Failure: agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_NONE, AcceptedAt: now, CredentialRoot: snapshot.Root, CredentialDelegationEnvelope: snapshot.DelegationEnvelope, TrustAcceptedAt: now}
	return &actionRecoveryFixture{deviceActionFixture: f, key: key, credential: credential, envelope: registered.Msg.GetCredentialEnvelope(), work: work, journal: journal, boot: uuid.NewString(), incarnation: uuid.NewString()}
}
func (f *actionRecoveryFixture) proof(t *testing.T, operation agentv1.RecoveryOperation, payload proto.Message) []byte {
	t.Helper()
	digest, err := trust.DeviceActionDigest(payload)
	if err != nil {
		t.Fatal(err)
	}
	credentialDigest := sha256.Sum256(f.envelope)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Millisecond)
	proof := &agentv1.RecoveryRequestProof{CredentialId: f.credential.GetCredentialId(), CredentialSha256: credentialDigest[:], RequestId: uuid.NewString(), BootId: f.boot, ExecutorIncarnation: f.incarnation, Nonce: nonce, Operation: operation, PayloadSha256: digest[:], IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(30 * time.Second))}
	envelope, err := f.svc.authority.Sign(t.Context(), proof, f.key)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}
func (f *actionRecoveryFixture) acquire(t *testing.T) *recoveryv1.AcquireRecoveryWorkResponse {
	t.Helper()
	request := &recoveryv1.AcquireRecoveryWorkRequest{CredentialEnvelope: f.envelope}
	request.RequestProof = f.proof(t, agentv1.RecoveryOperation_RECOVERY_OPERATION_ACQUIRE_WORK, recoveryAcquirePayload(request))
	response, err := f.svc.AcquireRecoveryWork(t.Context(), connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg
}
func (f *actionRecoveryFixture) checkpointRequest(t *testing.T, phase agentv1.RecoveryPhase) *recoveryv1.CheckpointRecoveryActionRequest {
	t.Helper()
	previous := f.journal.GetCheckpoint()
	var previousSHA []byte
	var err error
	if previous != nil {
		previousSHA, err = actionDigest(previous)
		if err != nil {
			t.Fatal(err)
		}
	}
	checkpoint := &agentv1.RecoveryCheckpoint{CredentialId: f.credential.GetCredentialId(), ActionId: f.work.GetActionId(), BootId: f.boot, ExecutorIncarnation: f.incarnation, Sequence: previous.GetSequence() + 1, Phase: phase, PreviousSha256: previousSHA, At: timestamppb.Now()}
	if len(f.journal.GetStartGrantEnvelope()) > 0 {
		digest := sha256.Sum256(f.journal.GetStartGrantEnvelope())
		checkpoint.GrantSha256 = digest[:]
	}
	f.journal.Checkpoint = checkpoint
	f.journal.CheckpointReceiptEnvelope = nil
	request := &recoveryv1.CheckpointRecoveryActionRequest{CredentialEnvelope: f.envelope, Checkpoint: checkpoint, Journal: proto.CloneOf(f.journal)}
	request.RequestProof = f.proof(t, agentv1.RecoveryOperation_RECOVERY_OPERATION_CHECKPOINT, recoveryCheckpointPayload(request))
	return request
}
func (f *actionRecoveryFixture) checkpoint(t *testing.T, phase agentv1.RecoveryPhase) *recoveryv1.CheckpointRecoveryActionResponse {
	t.Helper()
	request := f.checkpointRequest(t, phase)
	response, err := f.svc.CheckpointRecoveryAction(t.Context(), connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	f.journal.CheckpointReceiptEnvelope = response.Msg.GetReceiptEnvelope()
	return response.Msg
}
func (f *actionRecoveryFixture) startRequest(t *testing.T) *recoveryv1.AuthorizeRecoveryStartRequest {
	t.Helper()
	challenge := proto.CloneOf(f.credential.GetHandoff().GetChallenge())
	challenge.BootId = f.boot
	challenge.ExecutorIncarnation = f.incarnation
	challenge.IssuedAt = timestamppb.Now()
	challenge.ExpiresAt = timestamppb.New(challenge.GetIssuedAt().AsTime().Add(30 * time.Second))
	challenge.NativePlan.Before.RecoveryEnvironment = true
	challenge.NativePlan.Before.OffTargetJournal = true
	challenge.NativePlan.Before.ObservedAt = challenge.IssuedAt
	var err error
	challenge.NativePlanSha256, err = actionDigest(challenge.NativePlan)
	if err != nil {
		t.Fatal(err)
	}
	request := &recoveryv1.AuthorizeRecoveryStartRequest{CredentialEnvelope: f.envelope, Challenge: challenge, RecoveryImageSha256: f.credential.GetHandoff().GetRecoveryImageSha256()}
	request.RequestProof = f.proof(t, agentv1.RecoveryOperation_RECOVERY_OPERATION_AUTHORIZE_START, recoveryStartPayload(request))
	return request
}
func (f *actionRecoveryFixture) start(t *testing.T) *recoveryv1.AuthorizeRecoveryStartRequest {
	t.Helper()
	request := f.startRequest(t)
	response, err := f.svc.AuthorizeRecoveryStart(t.Context(), connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	f.journal.Challenge = request.GetChallenge()
	f.journal.StartGrantEnvelope = response.Msg.GetStartGrantEnvelope()
	f.journal.StartedAt = timestamppb.Now()
	f.journal.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING
	return request
}
func (f *actionRecoveryFixture) resultRequest(t *testing.T, state agentv1.DeviceActionState) *recoveryv1.ReportRecoveryResultRequest {
	t.Helper()
	work := f.acquire(t)
	digest := sha256.Sum256(f.work.GetIntentEnvelope())
	failure := agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_NONE
	if state == agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN {
		failure = agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_INTERRUPTED
	}
	status := &agentv1.DeviceActionStatus{ActionId: f.work.GetActionId(), IntentSha256: digest[:], State: state, Failure: failure, AcceptedAt: f.journal.GetAcceptedAt(), StartedAt: f.journal.GetStartedAt(), CompletedAt: timestamppb.Now(), Before: f.credential.GetHandoff().GetChallenge().GetNativePlan().GetBefore(), Verification: f.journal.GetVerification()}
	if f.journal.GetCompletedAt() != nil {
		status.CompletedAt = f.journal.GetCompletedAt()
	}
	if f.journal.GetChallenge() != nil {
		status.Before = f.journal.GetChallenge().GetNativePlan().GetBefore()
	}
	request := &recoveryv1.ReportRecoveryResultRequest{CredentialEnvelope: f.envelope, ResultNonce: work.GetResultNonce(), Status: status}
	request.RequestProof = f.proof(t, agentv1.RecoveryOperation_RECOVERY_OPERATION_REPORT_RESULT, recoveryResultPayload(request))
	return request
}
func TestDeviceActionRecoveryWorkCarriesUnchangedCurrentTrust(t *testing.T) {
	f := newActionRecoveryFixture(t)
	work := f.acquire(t)
	update := work.GetTrustUpdate()
	if update == nil || len(update.GetRootTransitions()) != 0 || !bytes.Equal(update.GetDelegationEnvelope(), f.journal.GetDelegationEnvelope()) {
		t.Fatal("recovery work omitted unchanged current signed authority")
	}
}

func TestDeviceActionRecoveryDurableCheckpointReplayAndTerminal(t *testing.T) {
	f := newActionRecoveryFixture(t)
	f.checkpoint(t, agentv1.RecoveryPhase_RECOVERY_PHASE_BOOTED)
	start := f.start(t)
	replay, err := f.svc.AuthorizeRecoveryStart(t.Context(), connect.NewRequest(start))
	if err != nil || !bytes.Equal(replay.Msg.GetStartGrantEnvelope(), f.journal.GetStartGrantEnvelope()) {
		t.Fatalf("exact recovery start replay: %v", err)
	}
	changed := f.startRequest(t)
	if _, err := f.svc.AuthorizeRecoveryStart(t.Context(), connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("fresh destructive grant minted: %v", err)
	}
	effect := f.checkpoint(t, agentv1.RecoveryPhase_RECOVERY_PHASE_EFFECT_COMMITTED)
	id, _ := uuid.Parse(f.work.GetActionId())
	row, err := devicedb.New(f.svc.pool).GetDeviceActionRecovery(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if !row.EffectCommittedAt.Valid || !bytes.Equal(row.CheckpointReceiptEnvelope, effect.GetReceiptEnvelope()) || len(row.JournalDocument) == 0 {
		t.Fatal("receipt preceded durable effect gate or snapshot")
	}
	if !proto.Equal(f.acquire(t).GetJournal(), f.journal) {
		t.Fatal("TPM snapshot reconstruction changed journal")
	}
	if _, err := f.svc.AuthorizeRecoveryStart(t.Context(), connect.NewRequest(start)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("grant reissued after consumption: %v", err)
	}
	f.journal.Verification = &agentv1.DeviceActionVerification{Verified: true, After: &agentv1.DeviceActionObservation{ObservedAt: timestamppb.Now(), Supported: true, Target: f.credential.GetHandoff().GetIntent().GetSpec().GetSanitize().GetTarget(), RecoveryEnvironment: true, OffTargetJournal: true}}
	if _, err := f.svc.ReportRecoveryResult(t.Context(), connect.NewRequest(f.resultRequest(t, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED))); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("success without terminal verification: %v", err)
	}
	f.journal.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED
	f.journal.CompletedAt = timestamppb.Now()
	f.checkpoint(t, agentv1.RecoveryPhase_RECOVERY_PHASE_TERMINAL)
	result := f.resultRequest(t, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED)
	response, err := f.svc.ReportRecoveryResult(t.Context(), connect.NewRequest(result))
	if err != nil || !response.Msg.GetClosed() {
		t.Fatalf("recovery terminal report: %v", err)
	}
	again, err := f.svc.ReportRecoveryResult(t.Context(), connect.NewRequest(result))
	if err != nil || !again.Msg.GetClosed() {
		t.Fatalf("terminal receipt replay: %v", err)
	}
}
func TestDeviceActionRecoveryExpiryUnknownAndSessionFence(t *testing.T) {
	f := newActionRecoveryFixture(t)
	f.checkpoint(t, agentv1.RecoveryPhase_RECOVERY_PHASE_BOOTED)
	f.start(t)
	f.checkpoint(t, agentv1.RecoveryPhase_RECOVERY_PHASE_EFFECT_COMMITTED)
	if _, err := f.svc.pool.Exec(t.Context(), "UPDATE device_action_recovery SET expires_at=clock_timestamp()-interval '1 second' WHERE credential_id=$1", f.credential.GetCredentialId()); err != nil {
		t.Fatal(err)
	}
	f.boot = uuid.NewString()
	f.incarnation = uuid.NewString()
	request := f.resultRequest(t, agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN)
	response, err := f.svc.ReportRecoveryResult(t.Context(), connect.NewRequest(request))
	if err != nil || response.Msg.GetClosed() {
		t.Fatalf("expired consumed historical report: %v", err)
	}
	current, err := f.svc.GetDeviceAction(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceActionRequest{ActionId: f.work.GetActionId()}))
	if err != nil || current.Msg.GetAction().GetStatus().GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN {
		t.Fatalf("unknown lost: %v", err)
	}
	if _, err := f.svc.AuthorizeRecoveryStart(t.Context(), connect.NewRequest(f.startRequest(t))); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("expired authority renewed: %v", err)
	}
	if _, err := f.svc.pool.Exec(t.Context(), "UPDATE enrollment_generations SET session_epoch=session_epoch+1 WHERE id=$1", f.generation); err != nil {
		t.Fatal(err)
	}
	acquire := &recoveryv1.AcquireRecoveryWorkRequest{CredentialEnvelope: f.envelope}
	acquire.RequestProof = f.proof(t, agentv1.RecoveryOperation_RECOVERY_OPERATION_ACQUIRE_WORK, recoveryAcquirePayload(acquire))
	if _, err := f.svc.AcquireRecoveryWork(t.Context(), connect.NewRequest(acquire)); err == nil {
		t.Fatal("recovery session fence ignored")
	}
}
func TestDeviceActionRecoveryScopeProofRevocationAndMissingResult(t *testing.T) {
	f := newActionRecoveryFixture(t)
	f.checkpoint(t, agentv1.RecoveryPhase_RECOVERY_PHASE_BOOTED)
	acquire := &recoveryv1.AcquireRecoveryWorkRequest{CredentialEnvelope: f.envelope}
	acquire.RequestProof = f.proof(t, agentv1.RecoveryOperation_RECOVERY_OPERATION_ACQUIRE_WORK, recoveryAcquirePayload(acquire))
	first, err := f.svc.AcquireRecoveryWork(t.Context(), connect.NewRequest(acquire))
	if err != nil {
		t.Fatal(err)
	}
	replay, err := f.svc.AcquireRecoveryWork(t.Context(), connect.NewRequest(acquire))
	if err != nil || !proto.Equal(first.Msg, replay.Msg) {
		t.Fatalf("recovery work receipt replay: %v", err)
	}
	reused := proto.CloneOf(acquire)
	proof := new(agentv1.RecoveryRequestProof)
	if err := f.svc.authority.Verify(t.Context(), acquire.GetRequestProof(), proof, 1, ed25519.PublicKey(f.key[ed25519.SeedSize:])); err != nil {
		t.Fatal(err)
	}
	proof.RequestId = uuid.NewString()
	reused.RequestProof, err = f.svc.authority.Sign(t.Context(), proof, f.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.AcquireRecoveryWork(t.Context(), connect.NewRequest(reused)); err == nil {
		t.Fatal("recovery nonce reused under another request identity")
	}
	request := f.startRequest(t)
	request.RecoveryImageSha256[0] ^= 1
	if _, err := f.svc.AuthorizeRecoveryStart(t.Context(), connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("changed signed request accepted: %v", err)
	}
	request = f.startRequest(t)
	request.Challenge.NativePlan.Before.Target.Serial = "substituted-media"
	request.Challenge.NativePlanSha256, _ = actionDigest(request.Challenge.NativePlan)
	request.RequestProof = f.proof(t, agentv1.RecoveryOperation_RECOVERY_OPERATION_AUTHORIZE_START, recoveryStartPayload(request))
	if _, err := f.svc.AuthorizeRecoveryStart(t.Context(), connect.NewRequest(request)); err == nil {
		t.Fatal("changed recovery media accepted")
	}
	if _, err := f.svc.pool.Exec(t.Context(), "UPDATE approval_requests SET created_at=clock_timestamp()-interval '10 minutes', expires_at=clock_timestamp()-interval '1 second' WHERE id=(SELECT approval_id FROM device_actions WHERE id=$1)", f.work.GetActionId()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.AuthorizeRecoveryStart(t.Context(), connect.NewRequest(f.startRequest(t))); err == nil {
		t.Fatal("stale two-human approval accepted after boot")
	}
	if _, err := f.svc.pool.Exec(t.Context(), "UPDATE device_actions SET issued_at=clock_timestamp()-interval '2 minutes', expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", f.work.GetActionId()); err != nil {
		t.Fatal(err)
	}
	if !f.deviceActionFixture.work(t).GetRecoveryHandoff() {
		t.Fatal("missing handoff result was expired away")
	}
	if _, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(f.request(lockActionSpec()))); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("replacement issued after possible boot: %v", err)
	}
}
