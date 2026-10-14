// SPDX-License-Identifier: Apache-2.0

//go:build integration

package device

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/pem"
	"testing"
	"time"

	"lindm/internal/device/dispatch"

	"lindm/internal/device/assistance"
	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/config"
	"lindm/internal/executionauthority"
	"lindm/internal/identity"
	"lindm/internal/trust"
)

type deviceActionFixture struct {
	*enrolledFixture
	certificate []byte
	rootKeys    []ed25519.PrivateKey
}

// All authorization and custody state belongs to a fresh real PostgreSQL schema.
// Native effects are never invoked by this server contract fixture.
func newDeviceActionFixture(t *testing.T) *deviceActionFixture {
	t.Helper()
	return newDeviceActionFixtureCapabilities(t, []string{"systemd.service.v1", "device.escrow-rotate.v1", "device.tpm2-bind.v1", "device.lock-sessions.v1", "device.release-lock.v1", "device.quarantine.v1", "device.release-quarantine.v1", "device.crypto-erase.v1", "device.sanitize.v1", "device.restart.v1", "device.shutdown.v1", "device.refresh-inventory.v1", "device.local-admin-rotate.v1", "device.patch-now.v1"})
}

func newDeviceActionFixtureCapabilities(t *testing.T, capabilities []string) *deviceActionFixture {
	t.Helper()
	f := &deviceActionFixture{enrolledFixture: newEnrolled(t, 0)}
	started := time.Now()
	s := f.svc
	now := time.Now().UTC()
	public := func(key ed25519.PrivateKey) *agentv1.ExecutionKey {
		p := ed25519.PublicKey(key[ed25519.SeedSize:])
		id, err := trust.KeyID(p)
		if err != nil {
			t.Fatal(err)
		}
		return &agentv1.ExecutionKey{KeyId: id, PublicKey: p}
	}
	sign := func(message proto.Message, keys ...ed25519.PrivateKey) []byte {
		data, err := s.Authority.Sign(t.Context(), message, keys...)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	roots := []ed25519.PrivateKey{ed25519Key(t), ed25519Key(t)}
	f.rootKeys = roots
	root := &agentv1.ExecutionRoot{DeploymentId: s.DeploymentID.String(), Version: 1, Threshold: 2, NotBefore: timestamppb.New(now.Add(-time.Hour)), ExpiresAt: timestamppb.New(now.Add(24 * time.Hour)), Keys: []*agentv1.ExecutionKey{public(roots[0]), public(roots[1])}}
	rootJSON, err := protojson.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	rootDigest := sha256.Sum256(rootJSON)
	transport, _ := testCA(t, now.Add(48*time.Hour))
	bundle := &agentv1.BootstrapBundle{BundleId: uuid.NewString(), DeploymentId: s.DeploymentID.String(), EnrollmentOrigin: "https://admin.example", DeviceOrigin: "https://device.example", TransportCaPem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: transport.Raw}), ConsoleCaPem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: transport.Raw}), DeviceCaPem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.CA.Raw}), ReleaseRootJson: dispatchReleaseRoot(t, now), ExecutionRootVersion: 1, ExecutionRootSha256: rootDigest[:], NotBefore: timestamppb.New(now.Add(-time.Hour)), ExpiresAt: timestamppb.New(now.Add(12 * time.Hour))}
	store, err := executionauthority.New(t.Context(), s.Pool, executionauthority.Config{RootJSON: rootJSON, BootstrapEnvelope: sign(bundle, roots...), TLSPublicKey: ed25519Key(t).Public()})
	if err != nil {
		t.Fatal(err)
	}
	authorityReady := time.Now()
	plan, start := ed25519Key(t), ed25519Key(t)
	delegation := &agentv1.ExecutionDelegation{DeploymentId: s.DeploymentID.String(), RootVersion: 1, Version: 1, NotBefore: timestamppb.New(now.Add(-time.Hour)), ExpiresAt: timestamppb.New(now.Add(6 * time.Hour)), Delegates: []*agentv1.ExecutionDelegate{{Key: public(plan), Role: agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, Capabilities: capabilities}, {Key: public(start), Role: agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, Capabilities: capabilities}}}
	actor, _ := identity.PrincipalFromContext(f.ownerCtx)
	tx, err := s.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(t.Context(), tx, &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: sign(delegation, roots...)}, actor.ID, "isolated device action authority"); err != nil {
		_ = tx.Rollback(t.Context())
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	custody := newFixtureCustody(t)
	f.svc, err = New(s.Pool, core.Config{DeploymentID: s.DeploymentID.String(), CACertificate: s.CA, CAKey: s.CAKey, Identity: s.Identity, ExecutionAuthority: store, ExecutionSigning: &config.ExecutionSigning{PlanKey: plan, StartKey: start}, Escrow: custody}, assistance.NewRuntime())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Pool.QueryRow(t.Context(), "SELECT pem FROM device_certificates WHERE id=$1", f.principal.CertificateID).Scan(&f.certificate); err != nil {
		t.Fatal(err)
	}
	report := hostObservation(f.generation, 1, "device-action-fixture")
	details := nativeDetailsFixture()
	report.Observation.Details = details
	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	details.Sessions.Sessions = &inventoryv1.ObservedUint64{Status: success, Value: 1}
	details.Storage = &inventoryv1.StorageDetails{Status: success, Devices: []*inventoryv1.BlockDevice{fixtureStorageDevice("fixture-disk", fixtureStorageTarget(uuid.NewString()))}}
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(report)); err != nil {
		t.Fatal(err)
	}
	t.Logf("action fixture: authority=%s delegation_custody_service=%s", authorityReady.Sub(started), time.Since(authorityReady))
	return f
}
func (f *deviceActionFixture) request(spec *agentv1.DeviceActionSpec) *adminv1.CreateDeviceActionRequest {
	return &adminv1.CreateDeviceActionRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, EnrollmentGeneration: f.generation, Spec: spec, ExpiresAt: timestamppb.New(time.Now().Add(5 * time.Minute)), Reason: "isolated action contract"}
}
func (f *deviceActionFixture) create(t *testing.T, request *adminv1.CreateDeviceActionRequest) *adminv1.DeviceAction {
	t.Helper()
	response, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg.GetAction()
}
func (f *deviceActionFixture) work(t *testing.T) *devicev1.DeviceActionWork {
	t.Helper()
	response, err := f.svc.GetDeviceActionWork(f.deviceCtx(), connect.NewRequest(&devicev1.GetDeviceActionWorkRequest{SessionEpoch: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if response.Msg.GetWork() == nil {
		t.Fatal("missing imperative work")
	}
	return response.Msg.GetWork()
}
func (f *deviceActionFixture) sign(t *testing.T, message proto.Message) []byte {
	t.Helper()
	encoded, err := f.svc.Authority.Sign(t.Context(), message, f.key)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
func (f *deviceActionFixture) intent(t *testing.T, work *devicev1.DeviceActionWork) *agentv1.DeviceActionIntent {
	t.Helper()
	intent := new(agentv1.DeviceActionIntent)
	if err := f.svc.Authority.Verify(t.Context(), work.GetIntentEnvelope(), intent, 1, ed25519.PublicKey(f.svc.Signing.PlanKey[ed25519.SeedSize:])); err != nil {
		t.Fatal(err)
	}
	return intent
}
func (f *deviceActionFixture) challenge(t *testing.T, work *devicev1.DeviceActionWork) *agentv1.DeviceActionChallenge {
	t.Helper()
	intent := f.intent(t, work)
	now := time.Now().UTC().Add(-time.Second)
	digest := sha256.Sum256(work.GetIntentEnvelope())
	plan := &agentv1.DeviceActionPlan{ActionId: intent.GetActionId(), Spec: intent.GetSpec(), Before: &agentv1.DeviceActionObservation{ObservedAt: timestamppb.New(now), Supported: true, RecoveryEnvironment: true, OffTargetJournal: true}}
	if rotate := intent.GetSpec().GetEscrowRotate(); rotate != nil {
		plan.Before.Target = rotate.GetTarget()
		plan.Before.Encrypted = true
		plan.RecoveryBinding = &agentv1.RecoveryKeyBinding{DeviceId: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), ActionId: intent.GetActionId(), LuksUuid: rotate.GetTarget().GetLuksUuid(), NewKeyslot: 1}
	}
	if rotate := intent.GetSpec().GetLocalAdminPasswordRotate(); rotate != nil {
		plan.Before.LocalAdmin = &agentv1.LocalAdminAccountObservation{AccountName: rotate.GetAccountName(), AccountUid: 1001, PasswordUsable: true}
		plan.LocalAdminBinding = &agentv1.LocalAdminPasswordBinding{DeviceId: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), ActionId: intent.GetActionId(), AccountName: rotate.GetAccountName(), AccountUid: 1001}
	}
	if core.LiveRootAction(intent.GetSpec()) {
		plan.Before.Encrypted = true
		plan.Before.RecoveryEnvironment = false
		plan.Before.OffTargetJournal = false
		for i, target := range intent.GetSpec().GetCryptoErase().GetTargets() {
			plan.CryptoEraseTargets = append(plan.CryptoEraseTargets, &agentv1.CryptoEraseTargetPlan{Target: target, MetadataSha256: make([]byte, 32), LuksHeaderBytes: 16 << 20, RootBacking: i == 0, RootMappingSha256: make([]byte, 32)})
		}
		plan.Before.CryptoEraseTargets = plan.CryptoEraseTargets
	}
	planDigest, err := core.ActionDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1.DeviceActionChallenge{DeploymentId: intent.GetDeploymentId(), DeviceId: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), ActionId: intent.GetActionId(), ActionSequence: intent.GetActionSequence(), RecoveryEpoch: intent.GetRecoveryEpoch(), IntentSha256: digest[:], SpecSha256: intent.GetSpecSha256(), NativePlanSha256: planDigest, NativePlan: plan, Nonce: make([]byte, 32), BootId: uuid.NewString(), ExecutorIncarnation: uuid.NewString(), IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(30 * time.Second))}
}
func (f *deviceActionFixture) startRequest(t *testing.T, work *devicev1.DeviceActionWork) (*devicev1.AuthorizeDeviceActionStartRequest, *agentv1.DeviceActionChallenge) {
	t.Helper()
	challenge := f.challenge(t, work)
	return &devicev1.AuthorizeDeviceActionStartRequest{SessionEpoch: 1, ActionId: work.GetActionId(), ChallengeProof: f.sign(t, challenge)}, challenge
}
func (f *deviceActionFixture) approval(t *testing.T, request *adminv1.CreateDeviceActionRequest) context.Context {
	t.Helper()
	created, err := f.svc.CreateApproval(f.ownerCtx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_CreateDeviceAction{CreateDeviceAction: request}}))
	if err != nil {
		t.Fatal(err)
	}
	reviewer := approvalReviewer(t, f.svc, t.Context())
	if _, err := f.svc.ApproveApproval(reviewer, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: created.Msg.GetApproval().GetId(), Reason: "independent action review"})); err != nil {
		t.Fatal(err)
	}
	request.ApprovalId = created.Msg.GetApproval().GetId()
	return reviewer
}
func (f *deviceActionFixture) result(t *testing.T, work *devicev1.DeviceActionWork, revision uint64, state agentv1.DeviceActionState, verification *agentv1.DeviceActionVerification) *devicev1.ReportDeviceActionResultRequest {
	t.Helper()
	now := time.Now().UTC().Add(-time.Second)
	intent := f.intent(t, work)
	digest := sha256.Sum256(work.GetIntentEnvelope())
	stamp := timestamppb.New(now)
	status := &agentv1.DeviceActionStatus{ActionId: work.GetActionId(), IntentSha256: digest[:], State: state, Failure: agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_NONE, AcceptedAt: stamp, StartedAt: stamp, Before: &agentv1.DeviceActionObservation{ObservedAt: stamp, Supported: true}, Verification: verification}
	if dispatch.ActionTerminal(state) || state == agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN {
		status.CompletedAt = stamp
	}
	if state == agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN {
		status.Failure = agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_INTERRUPTED
	}
	attestation := &agentv1.DeviceActionAttestation{DeploymentId: intent.GetDeploymentId(), DeviceId: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), SessionEpoch: 1, ActionRevision: revision, Nonce: work.GetResultNonce(), IssuedAt: stamp, ExpiresAt: timestamppb.New(now.Add(30 * time.Second)), Status: status}
	return &devicev1.ReportDeviceActionResultRequest{SessionEpoch: 1, ActionId: work.GetActionId(), AttestationEnvelope: f.sign(t, attestation), CertificatePem: f.certificate}
}
