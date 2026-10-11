package loadlab

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"testing/synctest"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	devicev1connect "lindm/gen/lindm/device/v1/devicev1connect"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/pki"
	"lindm/internal/rpcreason"
	"lindm/internal/trust"
)

func TestDispatchRetainsStartedActionAfterReportFailure(t *testing.T) {
	for _, test := range []struct {
		name string
		lost bool
		wait time.Duration
	}{
		{"admission-rejected", false, 20 * time.Second},
		{"lost-closed-reply", true, 20 * time.Second},
		{"expired-unadmitted-proof", false, 70 * time.Second},
		{"expired-closed-receipt", true, 70 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newReplayFixture(t)
				f.reportFailure = replayRPCError(connect.CodeResourceExhausted, "admission_rejected")
				f.loseReport = test.lost
				if err := f.r.dispatch(t.Context(), f.d); connect.CodeOf(err) != connect.CodeResourceExhausted {
					t.Fatalf("report failure was hidden: %v", err)
				}
				pending := f.d.pending
				proof := bytes.Clone(pending.proof)
				status := proto.CloneOf(pending.status)
				report := proto.CloneOf(pending.report)
				if f.r.completed.Load() != 0 || f.r.completedDevices.Load() != 0 || len(f.d.completed) != 0 {
					t.Fatal("unacknowledged report counted as completion")
				}
				time.Sleep(test.wait)
				if err := f.r.dispatch(t.Context(), f.d); err != nil {
					t.Fatal(err)
				}
				if !f.closed || f.authorizations != 1 || f.grants != 1 || f.reports != 2 || f.d.pending != nil {
					t.Fatalf("report retry restarted or failed to close: starts=%d grants=%d reports=%d closed=%t", f.authorizations, f.grants, f.reports, f.closed)
				}
				if !bytes.Equal(proof, pending.proof) || !proto.Equal(status, f.lastAttestation.GetStatus()) || !proto.Equal(status, pending.status) {
					t.Fatal("report retry changed challenge, plan, execution timestamps or terminal evidence")
				}
				exact := bytes.Equal(report.GetAttestationEnvelope(), f.receipt.GetAttestationEnvelope())
				if exact != (test.lost || test.wait < 30*time.Second) {
					t.Fatal("report did not preserve exact receipt or refresh expired unadmitted evidence")
				}
				if f.r.completed.Load() != 1 || f.r.completedDevices.Load() != 1 || len(f.d.completed) != 1 {
					t.Fatal("closed completion was not counted exactly once")
				}
				if err := f.r.dispatch(t.Context(), f.d); err != nil || f.r.completed.Load() != 1 || f.reports != 2 {
					t.Fatalf("closed work was replayed as a new effect: %v", err)
				}
				metrics := f.r.metrics.snapshot(false)["ReportResourceResult"]
				if metrics.Calls != 2 || metrics.Errors != 1 || metrics.Reasons["admission_rejected"] != 1 {
					t.Fatalf("transient failure vanished from capacity evidence: %+v", metrics)
				}
			})
		})
	}
}

func TestDispatchRetriesPreparedChallengeAndStoredGrant(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "rejected-start", true: "lost-start-reply"}[lost], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newReplayFixture(t)
				f.startFailure = replayRPCError(connect.CodeUnavailable, "unavailable")
				f.loseStart = lost
				if err := f.r.dispatch(t.Context(), f.d); connect.CodeOf(err) != connect.CodeUnavailable {
					t.Fatalf("start error was hidden: %v", err)
				}
				pending := f.d.pending
				proof := bytes.Clone(pending.proof)
				accepted := proto.CloneOf(pending.status.GetAcceptedAt())
				time.Sleep(20 * time.Second)
				if err := f.r.dispatch(t.Context(), f.d); err != nil {
					t.Fatal(err)
				}
				wantCalls := 2
				if lost {
					wantCalls = 1 // GetResourceWork carries the already-authorized grant.
				}
				if f.authorizations != wantCalls || f.grants != 1 || !f.closed || !bytes.Equal(proof, f.challengeProof) || !proto.Equal(accepted, f.lastAttestation.GetStatus().GetAcceptedAt()) {
					t.Fatal("retry replaced the prepared challenge or admitted a second start")
				}
			})
		})
	}
}

func TestDispatchExpiresPreparedChallengeWithoutExecution(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "rejected-start", true: "lost-start-reply"}[lost], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newReplayFixture(t)
				f.startFailure = replayRPCError(connect.CodeUnavailable, "unavailable")
				f.loseStart = lost
				if err := f.r.dispatch(t.Context(), f.d); connect.CodeOf(err) != connect.CodeUnavailable {
					t.Fatal(err)
				}
				time.Sleep(30 * time.Second)
				if err := f.r.dispatch(t.Context(), f.d); err != nil {
					t.Fatal(err)
				}
				status := f.lastAttestation.GetStatus()
				if f.authorizations != 1 || !f.closed || status.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED || status.GetStartedAt() != nil || f.r.completed.Load() != 0 || len(f.d.completed) != 0 {
					t.Fatal("lapsed challenge generated a new start or counted as success")
				}
			})
		})
	}
}

func TestDispatchRejectsChangedStartGrant(t *testing.T) {
	f := newReplayFixture(t)
	f.changeGrant = true
	if err := f.r.dispatch(t.Context(), f.d); err == nil {
		t.Fatal("grant for a different challenge was accepted")
	}
	if f.reports != 0 || f.d.pending.status.GetStartedAt() != nil || f.r.completed.Load() != 0 {
		t.Fatal("unverified grant produced execution evidence")
	}
}

func TestDispatchPreservesNonretryableReportError(t *testing.T) {
	f := newReplayFixture(t)
	f.reportFailure = replayRPCError(connect.CodePermissionDenied, "service_result_rejected")
	if err := f.r.dispatch(t.Context(), f.d); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("real rejection was reinterpreted: %v", err)
	}
	metrics := f.r.metrics.snapshot(false)["ReportResourceResult"]
	if metrics.NonRetryableErrors != 1 || metrics.Reasons["service_result_rejected"] != 1 || f.r.completed.Load() != 0 || f.d.pending == nil {
		t.Fatal("real rejection or pending history was lost")
	}
}

func TestDispatchRequiresClosedReport(t *testing.T) {
	f := newReplayFixture(t)
	f.leaveOpen = true
	if err := f.r.dispatch(t.Context(), f.d); err == nil {
		t.Fatal("unclosed terminal report was accepted as completion")
	}
	if f.r.completed.Load() != 0 || len(f.d.completed) != 0 || f.d.pending == nil {
		t.Fatal("unclosed report discarded pending history or counted completion")
	}
}

func TestDispatchRejectsChangedIntentOnReportRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newReplayFixture(t)
		f.reportFailure = replayRPCError(connect.CodeResourceExhausted, "admission_rejected")
		if err := f.r.dispatch(t.Context(), f.d); connect.CodeOf(err) != connect.CodeResourceExhausted {
			t.Fatal(err)
		}
		f.intent.DesiredRevision = uuid.NewString()
		f.intent.Ownership.AssignmentId = f.intent.GetDesiredRevision()
		f.work.IntentEnvelope = f.sign(f.intent, f.planKey)
		time.Sleep(30 * time.Second)
		if err := f.r.dispatch(t.Context(), f.d); err == nil {
			t.Fatal("changed intent was attached to retained execution history")
		}
		if f.authorizations != 1 || f.reports != 1 || f.r.completed.Load() != 0 {
			t.Fatal("changed intent authorized another start or report")
		}
	})
}

func TestDispatchBoundsCompletedHistoryAcrossPeriodicActions(t *testing.T) {
	f := newReplayFixture(t)
	old := proto.CloneOf(f.work)
	for sequence := uint64(1); sequence <= 8; sequence++ {
		f.intent.ActionId = uuid.NewString()
		f.intent.ResourceSequence = sequence
		f.work = &devicev1.ResourceWork{ActionId: f.intent.GetActionId(), IntentEnvelope: f.sign(f.intent, f.planKey)}
		f.closed, f.receipt = false, nil
		f.challengeProof = nil
		if err := f.r.dispatch(t.Context(), f.d); err != nil {
			t.Fatal(err)
		}
		if len(f.d.completed) != 1 || f.r.completed.Load() != sequence || f.r.completedDevices.Load() != 1 || f.d.pending != nil {
			t.Fatal("periodic history grew beyond the single assigned resource or changed counters")
		}
	}
	f.work, f.closed = old, false
	if err := f.r.dispatch(t.Context(), f.d); err == nil || f.authorizations != 8 {
		t.Fatal("discarded action ID bypassed the retained service sequence fence")
	}
}

// This is a unit Connect transport, not a running server, OIDC or native-package
// integration. Real authority signatures/verifiers and the measurement interceptor
// run against a narrowly modeled service receipt/nonce endpoint.
type replayFixture struct {
	devicev1connect.UnimplementedDeviceServiceHandler
	t               *testing.T
	r               *runner
	d               *simulatedDevice
	intent          *agentv1.ResourceExecutionIntent
	work            *devicev1.ResourceWork
	planKey         ed25519.PrivateKey
	startKey        ed25519.PrivateKey
	deviceCA        *x509.Certificate
	challengeProof  []byte
	receipt         *devicev1.ReportResourceResultRequest
	lastAttestation *agentv1.ResourceExecutionAttestation
	startFailure    error
	reportFailure   error
	loseStart       bool
	loseReport      bool
	changeGrant     bool
	leaveOpen       bool
	closed          bool
	authorizations  int
	grants          int
	reports         int
}

type replayHTTPClient struct{ handler http.Handler }

func (c replayHTTPClient) Do(req *http.Request) (*http.Response, error) {
	defer func() { _ = req.Body.Close() }()
	response := httptest.NewRecorder()
	c.handler.ServeHTTP(response, req)
	return response.Result(), nil
}

func newReplayFixture(t *testing.T) *replayFixture {
	t.Helper()
	authority, err := trust.New()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	rootKey := replayKey(t)
	root := &agentv1.ExecutionRoot{DeploymentId: uuid.NewString(), Version: 1, Threshold: 1, Keys: []*agentv1.ExecutionKey{replayExecutionKey(t, rootKey)}, NotBefore: timestamppb.New(now.Add(-time.Hour)), ExpiresAt: timestamppb.New(now.Add(24 * time.Hour))}
	f := &replayFixture{t: t, r: &runner{authority: authority, metrics: &measurements{}}, planKey: replayKey(t), startKey: replayKey(t)}
	f.d = &simulatedDevice{id: uuid.NewString(), generation: uuid.NewString(), boot: uuid.NewString(), incarnation: uuid.NewString(), epoch: 1, key: replayKey(t), root: root, completed: make(map[string]bool)}
	rootJSON, err := protojson.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(rootJSON)
	transport, _ := replayCA(t, replayKey(t), now, x509.ExtKeyUsageServerAuth)
	deviceCAKey := replayKey(t)
	deviceCA, certificate := replayCA(t, deviceCAKey, now, x509.ExtKeyUsageClientAuth)
	f.deviceCA = certificate
	bundle := &agentv1.BootstrapBundle{BundleId: uuid.NewString(), DeploymentId: root.GetDeploymentId(), EnrollmentOrigin: "https://enrollment.example", DeviceOrigin: "https://device.example", TransportCaPem: transport, DeviceCaPem: deviceCA, ExecutionRootVersion: 1, ExecutionRootSha256: digest[:], ReleaseRootJson: replayReleaseRoot(t, now), NotBefore: timestamppb.New(now.Add(-time.Minute)), ExpiresAt: timestamppb.New(now.Add(time.Hour))}
	bootstrap, err := authority.VerifyBootstrap(t.Context(), rootJSON, f.sign(bundle, rootKey), now)
	if err != nil {
		t.Fatal(err)
	}
	f.r.verifier, err = authority.NewExecutionVerifier(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	delegation := &agentv1.ExecutionDelegation{DeploymentId: root.GetDeploymentId(), RootVersion: 1, Version: 1, MinimumRecoveryEpoch: 1, NotBefore: timestamppb.New(now.Add(-time.Minute)), ExpiresAt: timestamppb.New(now.Add(time.Hour)), Delegates: []*agentv1.ExecutionDelegate{{Key: replayExecutionKey(t, f.planKey), Role: agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, Capabilities: []string{"systemd.service.v1"}}, {Key: replayExecutionKey(t, f.startKey), Role: agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, Capabilities: []string{"systemd.service.v1"}}}}
	f.d.delegation, err = f.r.verifier.VerifyDelegation(t.Context(), root, f.sign(delegation, rootKey), 0, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := pki.DeviceIdentityURL(uuid.MustParse(root.GetDeploymentId()), uuid.MustParse(f.d.id), uuid.MustParse(f.d.generation))
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: f.d.id}, BasicConstraintsValid: true, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{identity}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, certificate, f.d.key.Public(), deviceCAKey)
	if err != nil {
		t.Fatal(err)
	}
	f.d.certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	f.intent = &agentv1.ResourceExecutionIntent{DeploymentId: root.GetDeploymentId(), DeviceId: f.d.id, EnrollmentGeneration: f.d.generation, ActionId: uuid.NewString(), DesiredRevision: uuid.NewString(), ActorId: uuid.NewString(), ResourceSequence: 1, RecoveryEpoch: 1, RootVersion: 1, DelegationVersion: 1, AuthorizationVersion: 1, NotBefore: timestamppb.New(now.Add(-time.Minute)), ExpiresAt: timestamppb.New(now.Add(5 * time.Minute)),
		Desired:   &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: "capacity-synthetic.service"}, State: &resourcev1.ResourceDesiredState_SystemdService{SystemdService: &resourcev1.SystemdServiceDesired{Unit: "capacity-synthetic.service", Runtime: resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, Enablement: resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED}}},
		Operation: resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE,
	}
	resourceID := uuid.NewString()
	f.intent.Ownership = &agentv1.ResourceOwnershipBinding{AssignmentId: f.intent.GetDesiredRevision(), ResourceId: resourceID, Policy: &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN}, Sources: []*agentv1.ResourceOwnershipSource{{ProfileId: uuid.NewString(), ProfileRevision: uuid.NewString(), ResourceId: resourceID}}}
	f.work = &devicev1.ResourceWork{ActionId: f.intent.GetActionId(), IntentEnvelope: f.sign(f.intent, f.planKey)}
	_, handler := devicev1connect.NewDeviceServiceHandler(f)
	f.d.client = devicev1connect.NewDeviceServiceClient(replayHTTPClient{handler}, "https://device.example", connect.WithInterceptors(f.r.metrics))
	return f
}

func (f *replayFixture) GetResourceWork(_ context.Context, _ *connect.Request[devicev1.GetResourceWorkRequest]) (*connect.Response[devicev1.GetResourceWorkResponse], error) {
	if f.closed {
		return connect.NewResponse(&devicev1.GetResourceWorkResponse{}), nil
	}
	f.work.ResultNonce = make([]byte, 32)
	if _, err := rand.Read(f.work.ResultNonce); err != nil {
		return nil, err
	}
	f.work.ResultNonceExpiresAt = timestamppb.New(time.Now().Add(time.Minute))
	return connect.NewResponse(&devicev1.GetResourceWorkResponse{Work: f.work}), nil
}

func (f *replayFixture) AuthorizeResourceStart(ctx context.Context, req *connect.Request[devicev1.AuthorizeResourceStartRequest]) (*connect.Response[devicev1.AuthorizeResourceStartResponse], error) {
	f.authorizations++
	challenge := new(agentv1.ResourceExecutionChallenge)
	if err := f.r.authority.Verify(ctx, req.Msg.GetChallengeProof(), challenge, 1, ed25519.PublicKey(f.d.key[ed25519.SeedSize:])); err != nil {
		return nil, err
	}
	if len(f.challengeProof) != 0 && !bytes.Equal(f.challengeProof, req.Msg.GetChallengeProof()) {
		return nil, replayRPCError(connect.CodeAlreadyExists, "service_start_conflict")
	}
	f.challengeProof = bytes.Clone(req.Msg.GetChallengeProof())
	if f.authorizations == 1 && f.startFailure != nil && !f.loseStart {
		return nil, f.startFailure
	}
	if len(f.work.GetStartGrantEnvelope()) == 0 {
		if f.changeGrant {
			challenge.Nonce[0] ^= 1
		}
		grant := &agentv1.ResourceExecutionStartGrant{Challenge: challenge, ActorId: f.intent.GetActorId(), AuthorizationVersion: 1, RootVersion: 1, DelegationVersion: 1, NotBefore: challenge.GetIssuedAt(), ExpiresAt: challenge.GetExpiresAt()}
		f.work.StartGrantEnvelope = f.sign(grant, f.startKey)
		f.grants++
	}
	if f.authorizations == 1 && f.startFailure != nil {
		return nil, f.startFailure
	}
	return connect.NewResponse(&devicev1.AuthorizeResourceStartResponse{StartGrantEnvelope: f.work.GetStartGrantEnvelope()}), nil
}

func (f *replayFixture) ReportResourceResult(ctx context.Context, req *connect.Request[devicev1.ReportResourceResultRequest]) (*connect.Response[devicev1.ReportResourceResultResponse], error) {
	f.reports++
	if f.receipt != nil && proto.Equal(f.receipt, req.Msg) {
		return connect.NewResponse(&devicev1.ReportResourceResultResponse{Closed: f.closed}), nil
	}
	if f.reports == 1 && f.reportFailure != nil && !f.loseReport {
		return nil, f.reportFailure
	}
	if !time.Now().Before(f.work.GetResultNonceExpiresAt().AsTime()) {
		return nil, replayRPCError(connect.CodePermissionDenied, "service_result_nonce_rejected")
	}
	binding := &trust.ResourceAttestationBinding{DeploymentID: uuid.MustParse(f.intent.GetDeploymentId()), DeviceID: uuid.MustParse(f.d.id), EnrollmentGeneration: uuid.MustParse(f.d.generation), SessionEpoch: f.d.epoch, ActionID: uuid.MustParse(f.work.GetActionId()), IntentSHA256: sha256.Sum256(f.work.GetIntentEnvelope())}
	copy(binding.Nonce[:], f.work.GetResultNonce())
	attestation, err := f.r.authority.VerifyResourceAttestation(ctx, req.Msg.GetAttestationEnvelope(), req.Msg.GetCertificatePem(), f.deviceCA, binding, time.Now(), trust.MaxDeviceClockSkew)
	if err != nil {
		return nil, err
	}
	f.lastAttestation = attestation
	f.receipt = proto.CloneOf(req.Msg)
	f.closed = !f.leaveOpen && attestation.GetStatus().GetState() >= agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED
	if f.reports == 1 && f.reportFailure != nil {
		return nil, f.reportFailure
	}
	return connect.NewResponse(&devicev1.ReportResourceResultResponse{Closed: f.closed}), nil
}

func (f *replayFixture) sign(message proto.Message, key ed25519.PrivateKey) []byte {
	f.t.Helper()
	envelope, err := f.r.authority.Sign(f.t.Context(), message, key)
	if err != nil {
		f.t.Fatal(err)
	}
	return envelope
}

func replayRPCError(code connect.Code, reason string) error {
	return rpcreason.Error(code, reason)
}

func replayKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func replayExecutionKey(t *testing.T, key ed25519.PrivateKey) *agentv1.ExecutionKey {
	t.Helper()
	public := ed25519.PublicKey(key[ed25519.SeedSize:])
	id, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1.ExecutionKey{KeyId: id, PublicKey: public}
}

func replayCA(t *testing.T, key ed25519.PrivateKey, now time.Time, usage x509.ExtKeyUsage) ([]byte, *x509.Certificate) {
	t.Helper()
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "load replay unit fixture"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), certificate
}

func replayReleaseRoot(t *testing.T, now time.Time) []byte {
	t.Helper()
	key := replayKey(t)
	root := metadata.Root(now.Add(time.Hour))
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
