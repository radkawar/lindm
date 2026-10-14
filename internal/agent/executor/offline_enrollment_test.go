// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
	"lindm/internal/pki"
	"lindm/internal/trust"
)

func offlineAuthorizationFixture(t *testing.T, fix fixture, authority *trust.Authority) (*agentv1.OfflineEnrollmentAuthorizationFile, ed25519.PrivateKey) {
	t.Helper()
	plan, start := testKey(t), testKey(t)
	delegation := &agentv1.ExecutionDelegation{DeploymentId: fix.deploy.String(), RootVersion: 1, Version: 1, NotBefore: timestamppb.New(fix.now.Add(-time.Minute)), ExpiresAt: timestamppb.New(fix.now.Add(time.Hour)), Delegates: []*agentv1.ExecutionDelegate{
		{Key: executionPublic(t, plan), Role: agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, Capabilities: []string{trust.OfflineEnrollmentCapability}},
		{Key: executionPublic(t, start), Role: agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, Capabilities: []string{trust.OfflineEnrollmentCapability}},
	}}
	value := &agentv1.OfflineEnrollmentAuthorization{DeploymentId: fix.deploy.String(), AuthorizationId: uuid.NewString(), TokenId: uuid.NewString(), RootVersion: 1, DelegationVersion: 1, NotBefore: timestamppb.New(fix.now), ExpiresAt: timestamppb.New(fix.now.Add(30 * time.Minute))}
	return &agentv1.OfflineEnrollmentAuthorizationFile{AuthorizationEnvelope: mustSign(t, authority, value, plan), DelegationEnvelope: mustSign(t, authority, delegation, fix.rootKey)}, start
}

func TestOfflineEnrollmentSignedPairDurabilityAndRejection(t *testing.T) {
	now := time.Date(2032, 1, 2, 3, 4, 5, 0, time.UTC)
	fix := newFixture(t, now)
	authority, err := trust.New()
	if err != nil {
		t.Fatal(err)
	}
	authorization, start := offlineAuthorizationFixture(t, fix, authority)
	svc := openExecutor(t, now)
	prepared, err := svc.PrepareBootstrap(t.Context(), connect.NewRequest(&agentv1.PrepareBootstrapRequest{ExecutionRootJson: fix.root, BootstrapEnvelope: fix.bundle, OfflineAuthorization: authorization}))
	if err != nil {
		t.Fatal(err)
	}
	state := durable(t, svc)
	if state.GetPendingGrant() != "" || prepared.Msg.GetPendingGrant() != "" {
		t.Fatal("offline exchange retained a bearer token")
	}
	proof := new(agentv1.OfflineEnrollmentRequestProof)
	if err := authority.Verify(t.Context(), prepared.Msg.GetOfflineRequest().GetRequestProof(), proof, 1, publicOf(state.GetIdentityPrivateKey())); err != nil {
		t.Fatal(err)
	}
	if proof.GetInstallationId() != state.GetInstallationId() || proof.GetTransactionId() != state.GetEnrollmentTransactionId() {
		t.Fatal("request did not bind protected transaction")
	}
	svc = reopen(t, svc, now.Add(time.Minute))
	resumed, err := svc.PrepareBootstrap(t.Context(), connect.NewRequest(&agentv1.PrepareBootstrapRequest{Resume: true}))
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(prepared.Msg.GetOfflineRequest(), resumed.Msg.GetOfflineRequest()) {
		t.Fatal("restart changed the signed offline request")
	}
	certificate := fix.leaf(t, publicOf(state.GetIdentityPrivateKey()), uuid.New(), uuid.New(), now.Add(-time.Minute), now.Add(30*24*time.Hour))
	cert := parseCert(t, certificate)
	// The certificate's URI is the authoritative generation, not its common name.
	deploymentID, deviceID, generationID, err := pki.ParseDeviceIdentity(cert.URIs[0].String())
	if err != nil {
		t.Fatal(err)
	}
	if deploymentID != fix.deploy {
		t.Fatal("fixture deployment mismatch")
	}
	value := &agentv1.OfflineEnrollmentResponse{Request: proof, DeviceId: deviceID.String(), EnrollmentGeneration: generationID.String(), CertificatePem: certificate, RootVersion: 1, DelegationVersion: 1, NotBefore: timestamppb.New(now.Add(time.Minute)), ExpiresAt: timestamppb.New(now.Add(20 * time.Minute))}
	response := func(value *agentv1.OfflineEnrollmentResponse, key ed25519.PrivateKey) *agentv1.ImportOfflineEnrollmentRequest {
		return &agentv1.ImportOfflineEnrollmentRequest{Response: &agentv1.OfflineEnrollmentResponseFile{ResponseEnvelope: mustSign(t, authority, value, key), DelegationEnvelope: authorization.GetDelegationEnvelope()}}
	}
	for name, change := range map[string]func(*agentv1.OfflineEnrollmentResponse){
		"transaction":  func(v *agentv1.OfflineEnrollmentResponse) { v.Request.TransactionId = uuid.NewString() },
		"installation": func(v *agentv1.OfflineEnrollmentResponse) { v.Request.InstallationId = uuid.NewString() },
		"deployment":   func(v *agentv1.OfflineEnrollmentResponse) { v.Request.DeploymentId = uuid.NewString() },
		"csr":          func(v *agentv1.OfflineEnrollmentResponse) { v.Request.CsrSha256 = bytes.Repeat([]byte{9}, 32) },
		"authorization": func(v *agentv1.OfflineEnrollmentResponse) {
			v.Request.AuthorizationSha256 = bytes.Repeat([]byte{9}, 32)
		},
		"certificate_key": func(v *agentv1.OfflineEnrollmentResponse) {
			v.CertificatePem = fix.leaf(t, publicOf(testKey(t)), deviceID, generationID, now, now.Add(30*24*time.Hour))
		},
		"expired": func(v *agentv1.OfflineEnrollmentResponse) {
			v.NotBefore = timestamppb.New(now)
			v.ExpiresAt = timestamppb.New(now.Add(time.Second))
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := proto.CloneOf(value)
			change(changed)
			if _, err := svc.ImportOfflineEnrollment(t.Context(), connect.NewRequest(response(changed, start))); err == nil {
				t.Fatal("mismatched signed response accepted")
			}
		})
	}
	if _, err := svc.ImportOfflineEnrollment(t.Context(), connect.NewRequest(response(value, testKey(t)))); err == nil {
		t.Fatal("untrusted signer accepted")
	}
	if _, err := svc.ImportOfflineEnrollment(t.Context(), connect.NewRequest(response(value, fix.rootKey))); err == nil {
		t.Fatal("root key bypassed delegated signer")
	}
	unsigned := &agentv1.InstallEnrollmentRequest{DeviceId: deviceID.String(), EnrollmentGeneration: generationID.String(), CertificatePem: certificate}
	if _, err := svc.InstallEnrollment(t.Context(), connect.NewRequest(unsigned)); err == nil {
		t.Fatal("unsigned install bypassed offline response proof")
	}
	if _, err := svc.ImportOfflineEnrollment(t.Context(), connect.NewRequest(response(value, start))); err != nil {
		t.Fatal(err)
	}
	svc = reopen(t, svc, now.Add(2*time.Minute))
	if !bytes.Equal(durable(t, svc).GetCertificatePem(), certificate) {
		t.Fatal("offline identity was not durable")
	}
	if _, err := svc.ImportOfflineEnrollment(t.Context(), connect.NewRequest(response(value, start))); err == nil {
		t.Fatal("replayed offline response accepted")
	}
	session(t, svc)
	claim := durable(t, svc).GetPendingSession()
	if claim.GetInstallationId() != state.GetInstallationId() {
		t.Fatal("session proof omitted protected installation identity")
	}
}

func TestProvisioningResumeProofKeepsProtectedAttempt(t *testing.T) {
	now := time.Date(2032, 1, 2, 3, 4, 5, 0, time.UTC)
	fix := newFixture(t, now)
	svc := openExecutor(t, now)
	prepared, err := svc.PrepareBootstrap(t.Context(), connect.NewRequest(&agentv1.PrepareBootstrapRequest{ExecutionRootJson: fix.root, BootstrapEnvelope: fix.bundle, PendingGrant: "boot-delivered-test-token-with-32-characters", ProvisioningToken: true}))
	if err != nil {
		t.Fatal(err)
	}
	state := durable(t, svc)
	svc = reopen(t, svc, now.Add(time.Minute))
	resumed, err := svc.PrepareBootstrap(t.Context(), connect.NewRequest(&agentv1.PrepareBootstrapRequest{Resume: true}))
	if err != nil {
		t.Fatal(err)
	}
	if !resumed.Msg.GetProvisioningToken() || !bytes.Equal(prepared.Msg.GetProvisioningRetrievalProof(), resumed.Msg.GetProvisioningRetrievalProof()) || resumed.Msg.GetEnrollmentTransactionId() != prepared.Msg.GetEnrollmentTransactionId() {
		t.Fatal("pending approval resume changed the immutable attempt")
	}
	claim := new(enrollmentv1.ProvisioningRetrieval)
	if err := svc.authority.Verify(t.Context(), resumed.Msg.GetProvisioningRetrievalProof(), claim, 1, publicOf(state.GetIdentityPrivateKey())); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(state.GetEnrollmentCsrPem())
	if claim.GetInstallationId() != state.GetInstallationId() || claim.GetTransactionId() != state.GetEnrollmentTransactionId() || claim.GetDeploymentId() != fix.deploy.String() || !bytes.Equal(claim.GetCsrSha256(), digest[:]) {
		t.Fatal("resume proof is not bound to protected state")
	}
}

func TestOfflineAuthorizationRejectsUntrustedExpiredAndWrongCapability(t *testing.T) {
	now := time.Date(2032, 1, 2, 3, 4, 5, 0, time.UTC)
	fix := newFixture(t, now)
	authority, err := trust.New()
	if err != nil {
		t.Fatal(err)
	}
	original, start := offlineAuthorizationFixture(t, fix, authority)
	for _, scenario := range []string{"tampered", "wrong_capability", "wrong_quorum", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			file := proto.CloneOf(original)
			clock := now
			switch scenario {
			case "tampered":
				file.AuthorizationEnvelope[len(file.AuthorizationEnvelope)-2] ^= 1
			case "expired":
				clock = now.Add(31 * time.Minute)
			default:
				delegation := new(agentv1.ExecutionDelegation)
				if err := authority.Verify(t.Context(), file.GetDelegationEnvelope(), delegation, 1, publicOf(fix.rootKey)); err != nil {
					t.Fatal(err)
				}
				signer := fix.rootKey
				if scenario == "wrong_quorum" {
					signer = start
				} else {
					for _, delegate := range delegation.Delegates {
						delegate.Capabilities = []string{"systemd.service.v1"}
					}
				}
				file.DelegationEnvelope = mustSign(t, authority, delegation, signer)
			}
			service := openExecutor(t, clock)
			if _, err := service.PrepareBootstrap(t.Context(), connect.NewRequest(&agentv1.PrepareBootstrapRequest{ExecutionRootJson: fix.root, BootstrapEnvelope: fix.bundle, OfflineAuthorization: file})); err == nil {
				t.Fatal("rejected offline authority initialized a device")
			}
			status, err := service.Status(t.Context(), connect.NewRequest(&agentv1.StatusRequest{}))
			if err != nil {
				t.Fatal(err)
			}
			if status.Msg.GetLifecycle() != agentv1.Lifecycle_LIFECYCLE_UNPROVISIONED {
				t.Fatal("invalid authority persisted provisioning state")
			}
		})
	}
}
