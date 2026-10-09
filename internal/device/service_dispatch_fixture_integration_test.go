//go:build integration

package device

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/config"
	"lindm/internal/executionauthority"
	"lindm/internal/identity"
	"lindm/internal/testdb"
	"lindm/internal/trust"
)

type dispatchFixture struct {
	service             *Service
	pool                *pgxpool.Pool
	actor               identity.Principal
	adminCtx, deviceCtx context.Context
	principal           devicePrincipal
	directory           *dispatchDirectory
	key                 ed25519.PrivateKey
	certificate         []byte
	revision            *adminv1.ServiceProfileRevision
}

func newDispatchFixture(t *testing.T) *dispatchFixture {
	t.Helper()
	pool, _ := testdb.Open(t)
	identityService, actor, directory := dispatchIdentity(t, pool)
	f := &dispatchFixture{pool: pool, actor: actor, directory: directory, adminCtx: identity.WithPrincipal(t.Context(), actor), key: ed25519Key(t)}
	now := time.Now().UTC()
	deployment := uuid.NewString()
	ca, caKey := testCA(t, now.Add(48*time.Hour))
	authority, err := trust.New()
	if err != nil {
		t.Fatal(err)
	}
	sign := func(message proto.Message, keys ...ed25519.PrivateKey) []byte {
		t.Helper()
		encoded, err := authority.Sign(t.Context(), message, keys...)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	public := func(key ed25519.PrivateKey) *agentv1.ExecutionKey {
		t.Helper()
		pub := key.Public().(ed25519.PublicKey)
		id, err := trust.KeyID(pub)
		if err != nil {
			t.Fatal(err)
		}
		return &agentv1.ExecutionKey{KeyId: id, PublicKey: pub}
	}
	roots := []ed25519.PrivateKey{ed25519Key(t), ed25519Key(t)}
	root := &agentv1.ExecutionRoot{DeploymentId: deployment, Version: 1, Threshold: 2, NotBefore: timestamppb.New(now.Add(-time.Hour)), ExpiresAt: timestamppb.New(now.Add(24 * time.Hour)), Keys: []*agentv1.ExecutionKey{public(roots[0]), public(roots[1])}}
	rootJSON, err := protojson.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	rootDigest := sha256.Sum256(rootJSON)
	transportCA, _ := testCA(t, now.Add(48*time.Hour))
	bundle := &agentv1.BootstrapBundle{BundleId: uuid.NewString(), DeploymentId: deployment, EnrollmentOrigin: "https://admin.example", DeviceOrigin: "https://device.example", TransportCaPem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: transportCA.Raw}), DeviceCaPem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), ReleaseRootJson: dispatchReleaseRoot(t, now), ExecutionRootVersion: 1, ExecutionRootSha256: rootDigest[:], NotBefore: timestamppb.New(now.Add(-time.Hour)), ExpiresAt: timestamppb.New(now.Add(12 * time.Hour))}
	store, err := executionauthority.New(t.Context(), pool, executionauthority.Config{RootJSON: rootJSON, BootstrapEnvelope: sign(bundle, roots...), TLSPublicKey: ed25519Key(t).Public()})
	if err != nil {
		t.Fatal(err)
	}
	plan, start := ed25519Key(t), ed25519Key(t)
	delegation := &agentv1.ExecutionDelegation{DeploymentId: deployment, RootVersion: 1, Version: 1, MinimumRecoveryEpoch: 0, NotBefore: timestamppb.New(now.Add(-time.Hour)), ExpiresAt: timestamppb.New(now.Add(6 * time.Hour)), Delegates: []*agentv1.ExecutionDelegate{{Key: public(plan), Role: agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, Capabilities: []string{"systemd.service.v1"}}, {Key: public(start), Role: agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, Capabilities: []string{"systemd.service.v1"}}}}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(t.Context(), tx, &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: sign(delegation, roots...)}, actor.ID, "admit isolated dispatch authority"); err != nil {
		_ = tx.Rollback(t.Context())
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.service, err = New(pool, Config{DeploymentID: deployment, CACertificate: ca, CAKey: caKey, Identity: identityService, ExecutionAuthority: store, ExecutionSigning: &config.ExecutionSigning{PlanKey: plan, StartKey: start}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, enrolled := enrollDevice(t, t.Context(), f.service, f.adminCtx, f.key)
	f.certificate = enrolled.Msg.GetCertificatePem()
	f.principal, err = f.service.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), parseCertPEM(t, f.certificate))
	if err != nil {
		t.Fatal(err)
	}
	acquireTestSession(t, t.Context(), f.service, f.principal, f.key, 0)
	f.deviceCtx = withDevicePrincipal(t.Context(), f.principal)
	firstID, secondID := uuid.NewString(), uuid.NewString()
	published, err := f.service.PublishServiceProfileRevision(f.adminCtx, connect.NewRequest(&adminv1.PublishServiceProfileRevisionRequest{RequestId: uuid.NewString(), ProfileId: uuid.NewString(), Reason: "test dispatch revision", Spec: &policyv1.ServiceProfileSpec{Name: "Dispatch integration", Resources: []*policyv1.ServiceProfileResource{{ResourceId: secondID, Desired: &agentv1.ServiceDesiredState{Unit: "aaa-dependent.service", Runtime: agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, Enablement: agentv1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED}, DependsOn: []string{firstID}}, {ResourceId: firstID, Desired: &agentv1.ServiceDesiredState{Unit: "zzz-first.service", Runtime: agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, Enablement: agentv1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED}}}}}))
	if err != nil {
		t.Fatal(err)
	}
	f.revision = published.Msg.GetRevision()
	return f
}

func dispatchReleaseRoot(t *testing.T, now time.Time) []byte {
	t.Helper()
	key := ed25519Key(t)
	root := metadata.Root(now.Add(24 * time.Hour))
	public, err := metadata.KeyFromPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		if err := root.Signed.AddKey(public, role); err != nil {
			t.Fatal(err)
		}
	}
	signer, err := signature.LoadSignerVerifier(key, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.Sign(signer); err != nil {
		t.Fatal(err)
	}
	encoded, err := root.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func (f *dispatchFixture) assignmentRequest(expected *string) *adminv1.SetServiceAssignmentRequest {
	return &adminv1.SetServiceAssignmentRequest{RequestId: uuid.NewString(), DeviceId: f.principal.DeviceID.String(), ExpectedAssignmentId: expected, Target: &adminv1.ServiceAssignmentTarget{ProfileId: f.revision.GetProfileId(), RevisionId: f.revision.GetRevisionId()}, Reason: "assign integration desired state"}
}
func (f *dispatchFixture) assign(t *testing.T, expected *string) *adminv1.ServiceAssignment {
	t.Helper()
	result, err := f.service.SetServiceAssignment(f.adminCtx, connect.NewRequest(f.assignmentRequest(expected)))
	if err != nil {
		t.Fatal(err)
	}
	return result.Msg.GetAssignment()
}
func (f *dispatchFixture) work(t *testing.T) *devicev1.ServiceWork {
	t.Helper()
	response, err := f.service.GetServiceWork(f.deviceCtx, connect.NewRequest(&devicev1.GetServiceWorkRequest{SessionEpoch: 1}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg.GetWork()
}
func (f *dispatchFixture) intent(t *testing.T, work *devicev1.ServiceWork) *agentv1.ServiceExecutionIntent {
	t.Helper()
	if work == nil {
		t.Fatal("missing service work")
	}
	message := new(agentv1.ServiceExecutionIntent)
	if err := f.service.authority.Verify(t.Context(), work.GetIntentEnvelope(), message, 1, f.service.signing.PlanKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	return message
}
func (f *dispatchFixture) challenge(t *testing.T, work *devicev1.ServiceWork) *agentv1.ServiceExecutionChallenge {
	t.Helper()
	intent := f.intent(t, work)
	digest := sha256.Sum256(work.GetIntentEnvelope())
	now := time.Now().UTC().Add(-time.Second)
	return &agentv1.ServiceExecutionChallenge{DeploymentId: intent.GetDeploymentId(), DeviceId: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), ActionId: intent.GetActionId(), DesiredRevision: intent.GetDesiredRevision(), ResourceSequence: intent.GetResourceSequence(), RecoveryEpoch: intent.GetRecoveryEpoch(), IntentSha256: digest[:], NativePlanSha256: make([]byte, 32), Nonce: make([]byte, 32), BootId: uuid.NewString(), ExecutorIncarnation: uuid.NewString(), IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(30 * time.Second))}
}
func (f *dispatchFixture) sign(t *testing.T, message proto.Message, key ed25519.PrivateKey) []byte {
	t.Helper()
	encoded, err := f.service.authority.Sign(t.Context(), message, key)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
func (f *dispatchFixture) start(t *testing.T, work *devicev1.ServiceWork) (*devicev1.AuthorizeServiceStartRequest, []byte) {
	t.Helper()
	request := &devicev1.AuthorizeServiceStartRequest{SessionEpoch: 1, ActionId: work.GetActionId(), ChallengeProof: f.sign(t, f.challenge(t, work), f.key)}
	response, err := f.service.AuthorizeServiceStart(f.deviceCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	return request, response.Msg.GetStartGrantEnvelope()
}
func (f *dispatchFixture) result(t *testing.T, work *devicev1.ServiceWork, revision uint64, state agentv1.ServiceExecutionState, started bool) *devicev1.ReportServiceResultRequest {
	t.Helper()
	intent := f.intent(t, work)
	now := time.Now().UTC().Add(-time.Second)
	stamp := timestamppb.New(now)
	digest := sha256.Sum256(work.GetIntentEnvelope())
	observation := &agentv1.ServiceObservation{Unit: intent.GetDesired().GetUnit(), BootId: uuid.NewString(), ObservedAt: stamp, LoadState: "loaded", ActiveState: "active", DefinitionSha256: make([]byte, 32), FingerprintSha256: make([]byte, 32)}
	status := &agentv1.ServiceExecutionStatus{ActionId: intent.GetActionId(), IntentSha256: digest[:], State: state, Failure: agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_NONE, AcceptedAt: stamp, Before: observation}
	if started {
		status.StartedAt = stamp
	}
	if state >= agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED {
		status.CompletedAt = stamp
	}
	if state == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED {
		status.Verification = &agentv1.ServiceVerification{Observation: observation, RuntimeMatches: true, EnablementMatches: true, DefinitionMatches: true, Converged: true}
	}
	if state > agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED {
		status.Failure = agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_NATIVE
	}
	attestation := &agentv1.ServiceExecutionAttestation{DeploymentId: intent.GetDeploymentId(), DeviceId: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), SessionEpoch: 1, ActionRevision: revision, Nonce: work.GetResultNonce(), IssuedAt: stamp, ExpiresAt: timestamppb.New(now.Add(30 * time.Second)), Status: status}
	return &devicev1.ReportServiceResultRequest{SessionEpoch: 1, ActionId: work.GetActionId(), AttestationEnvelope: f.sign(t, attestation, f.key), CertificatePem: f.certificate}
}
