// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/pki"
)

type serviceAttestationFixture struct {
	authority      *Authority
	ca             *x509.Certificate
	caKey, key     ed25519.PrivateKey
	certificatePEM []byte
	binding        ResourceAttestationBinding
	attestation    *agentv1.ResourceExecutionAttestation
	now            time.Time
}

func newResourceAttestationFixture(t *testing.T) serviceAttestationFixture {
	t.Helper()
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	f := serviceAttestationFixture{
		authority: a, caKey: testKey(t), key: testKey(t),
		now: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
		binding: ResourceAttestationBinding{
			DeploymentID: uuid.New(), DeviceID: uuid.New(), EnrollmentGeneration: uuid.New(),
			SessionEpoch: 7, ActionID: uuid.New(),
			IntentSHA256: sha256.Sum256([]byte("retained signed service intent")),
		},
	}
	if _, err := rand.Read(f.binding.Nonce[:]); err != nil {
		t.Fatal(err)
	}
	f.ca = decodeCertificate(t, testCA(t, f.caKey, f.now, x509.ExtKeyUsageClientAuth))
	f.certificatePEM = f.certificate(t, f.key.Public(), nil)
	beforeNative := &resourcev1.SystemdServiceObservation{
		Unit: "example.service", BootId: uuid.NewString(), ObservedAt: timestamppb.New(f.now.Add(-30 * time.Minute)),
		LoadState: "loaded", ActiveState: "inactive", SubState: "dead", UnitFileState: "disabled", ServiceType: "simple",
		DefinitionSha256: bytes.Repeat([]byte{1}, 32), FingerprintSha256: bytes.Repeat([]byte{2}, 32),
	}
	before := attestationObservation(beforeNative)
	afterNative := proto.CloneOf(beforeNative)
	afterNative.ObservedAt = timestamppb.New(f.now.Add(-29 * time.Minute))
	afterNative.ActiveState, afterNative.SubState = "active", "running"
	afterNative.FingerprintSha256 = bytes.Repeat([]byte{3}, 32)
	after := attestationObservation(afterNative)
	f.attestation = &agentv1.ResourceExecutionAttestation{
		DeploymentId: f.binding.DeploymentID.String(), DeviceId: f.binding.DeviceID.String(), EnrollmentGeneration: f.binding.EnrollmentGeneration.String(),
		SessionEpoch: f.binding.SessionEpoch, ActionRevision: 4, Nonce: bytes.Clone(f.binding.Nonce[:]),
		IssuedAt: timestamppb.New(f.now), ExpiresAt: timestamppb.New(f.now.Add(30 * time.Second)),
		Status: &agentv1.ResourceExecutionStatus{
			ActionId: f.binding.ActionID.String(), IntentSha256: bytes.Clone(f.binding.IntentSHA256[:]),
			State: agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED, Failure: agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NONE,
			AcceptedAt: timestamppb.New(f.now.Add(-30 * time.Minute)), StartedAt: timestamppb.New(f.now.Add(-30 * time.Minute)), CompletedAt: timestamppb.New(f.now.Add(-29 * time.Minute)),
			Before: before, Verification: &resourcev1.ResourceVerification{
				Ref: proto.CloneOf(after.GetRef()), DesiredSha256: bytes.Repeat([]byte{4}, 32), PlanSha256: bytes.Repeat([]byte{5}, 32),
				After: after, Disposition: resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED,
				Checks: &resourcev1.ResourceVerification_SystemdService{SystemdService: &resourcev1.SystemdServiceChecks{Observation: afterNative, RuntimeMatches: true, EnablementMatches: true, DefinitionMatches: true, Converged: true, JobCompleted: true}},
			},
		},
	}
	return f
}

func attestationObservation(native *resourcev1.SystemdServiceObservation) *resourcev1.ResourceObservation {
	return &resourcev1.ResourceObservation{
		Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: native.GetUnit()},
		Metadata: &resourcev1.ObservationMetadata{
			BootId: native.GetBootId(), ExecutorIncarnation: "a2bca405-36e9-4a43-b5b5-d0b82a05e551", ObservedAt: proto.CloneOf(native.GetObservedAt()),
			Backend:        &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_SYSTEMD, NativeVersion: "255", ProviderVersion: "1", Product: &resourcev1.PlatformProduct{OsId: "ubuntu", Product: "Ubuntu", Version: "24.04", Architecture: "x86_64"}},
			NativeRevision: bytes.Clone(native.GetFingerprintSha256()), ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK,
		},
		Observed: &resourcev1.ResourceObservation_SystemdService{SystemdService: native},
	}
}

func (f serviceAttestationFixture) certificate(t *testing.T, public crypto.PublicKey, change func(*x509.Certificate)) []byte {
	t.Helper()
	identity, err := pki.DeviceIdentityURL(f.binding.DeploymentID, f.binding.DeviceID, f.binding.EnrollmentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: f.binding.DeviceID.String()}, URIs: []*url.URL{identity},
		NotBefore: f.now.Add(-time.Minute), NotAfter: f.now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true,
	}
	if change != nil {
		change(leaf)
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, f.ca, public, f.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// Sign without schema validation so malformed payloads reach the verifier, not
// just the production signer's input checks. This helper also signs wrong domains.
func signResourceAttestationUnchecked(t *testing.T, message *agentv1.ResourceExecutionAttestation, domain string, key ed25519.PrivateKey) []byte {
	t.Helper()
	public := ed25519.PublicKey(key[ed25519.SeedSize:])
	id, err := KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := dsse.NewEnvelopeSigner(&edSigner{edVerifier: edVerifier{public: public, id: id}, private: key})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signer.SignPayload(t.Context(), domain, payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestResourceAttestationBindsConsumerContextAndValidity(t *testing.T) {
	f := newResourceAttestationFixture(t)
	for _, tc := range []struct {
		name   string
		change func(*agentv1.ResourceExecutionAttestation, *ResourceAttestationBinding)
		at     time.Time
		valid  bool
	}{
		{name: "issued boundary", at: f.now, valid: true},
		{name: "just before expiry", at: f.now.Add(30*time.Second - time.Nanosecond), valid: true},
		{name: "expiry boundary", at: f.now.Add(30 * time.Second)},
		{name: "expired", at: f.now.Add(time.Minute)},
		{name: "future proof", at: f.now.Add(-time.Nanosecond)},
		{name: "wrong deployment", at: f.now, change: func(a *agentv1.ResourceExecutionAttestation, _ *ResourceAttestationBinding) {
			a.DeploymentId = uuid.NewString()
		}},
		{name: "wrong device", at: f.now, change: func(a *agentv1.ResourceExecutionAttestation, _ *ResourceAttestationBinding) {
			a.DeviceId = uuid.NewString()
		}},
		{name: "wrong generation", at: f.now, change: func(a *agentv1.ResourceExecutionAttestation, _ *ResourceAttestationBinding) {
			a.EnrollmentGeneration = uuid.NewString()
		}},
		{name: "wrong action", at: f.now, change: func(a *agentv1.ResourceExecutionAttestation, _ *ResourceAttestationBinding) {
			a.Status.ActionId = uuid.NewString()
		}},
		{name: "wrong intent digest", at: f.now, change: func(a *agentv1.ResourceExecutionAttestation, _ *ResourceAttestationBinding) {
			a.Status.IntentSha256[0] ^= 1
		}},
		{name: "nonce replay", at: f.now, change: func(_ *agentv1.ResourceExecutionAttestation, b *ResourceAttestationBinding) { b.Nonce[0] ^= 1 }},
		{name: "session replay", at: f.now, change: func(_ *agentv1.ResourceExecutionAttestation, b *ResourceAttestationBinding) { b.SessionEpoch++ }},
		{name: "zero expected deployment", at: f.now, change: func(_ *agentv1.ResourceExecutionAttestation, b *ResourceAttestationBinding) {
			b.DeploymentID = uuid.Nil
		}},
		{name: "zero expected device", at: f.now, change: func(_ *agentv1.ResourceExecutionAttestation, b *ResourceAttestationBinding) { b.DeviceID = uuid.Nil }},
		{name: "zero expected generation", at: f.now, change: func(_ *agentv1.ResourceExecutionAttestation, b *ResourceAttestationBinding) {
			b.EnrollmentGeneration = uuid.Nil
		}},
		{name: "zero expected action", at: f.now, change: func(_ *agentv1.ResourceExecutionAttestation, b *ResourceAttestationBinding) { b.ActionID = uuid.Nil }},
		{name: "zero expected session", at: f.now, change: func(_ *agentv1.ResourceExecutionAttestation, b *ResourceAttestationBinding) { b.SessionEpoch = 0 }},
		{name: "all zero nonce and digest are bindings", at: f.now, valid: true, change: func(a *agentv1.ResourceExecutionAttestation, b *ResourceAttestationBinding) {
			b.Nonce, b.IntentSHA256 = [32]byte{}, [32]byte{}
			a.Nonce, a.Status.IntentSha256 = make([]byte, 32), make([]byte, 32)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate, expected := proto.CloneOf(f.attestation), f.binding
			if tc.change != nil {
				tc.change(candidate, &expected)
			}
			envelope := executionSign(t, f.authority, candidate, f.key)
			got, err := f.authority.VerifyResourceAttestation(t.Context(), envelope, f.certificatePEM, f.ca, &expected, tc.at, 0)
			if tc.valid {
				if err != nil || !proto.Equal(got, candidate) {
					t.Fatalf("valid attestation changed or rejected: %v", err)
				}
			} else if err == nil || got != nil {
				t.Fatal("unbound or stale attestation accepted")
			}
		})
	}
	envelope := executionSign(t, f.authority, f.attestation, f.key)
	if got, err := f.authority.VerifyResourceAttestation(t.Context(), envelope, f.certificatePEM, f.ca, nil, f.now, 0); err == nil || got != nil {
		t.Fatal("missing consumer context accepted")
	}
}

func TestResourceAttestationRequiresPinnedCurrentDeviceLeaf(t *testing.T) {
	f := newResourceAttestationFixture(t)
	envelope := executionSign(t, f.authority, f.attestation, f.key)
	otherCA := decodeCertificate(t, testCA(t, testKey(t), f.now, x509.ExtKeyUsageClientAuth))
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*x509.Certificate)
		public crypto.PublicKey
		ca     *x509.Certificate
		pem    []byte
		valid  bool
	}{
		{name: "current leaf", ca: f.ca, pem: f.certificatePEM, valid: true},
		{name: "whitespace around single leaf", ca: f.ca, pem: append(append([]byte(" \n"), f.certificatePEM...), '\n'), valid: true},
		{name: "not before boundary", ca: f.ca, valid: true, change: func(c *x509.Certificate) { c.NotBefore = f.now }},
		{name: "proof ends at certificate expiry", ca: f.ca, valid: true, change: func(c *x509.Certificate) { c.NotAfter = f.now.Add(30 * time.Second) }},
		{name: "nil pinned CA", pem: f.certificatePEM},
		{name: "wrong pinned CA", ca: otherCA, pem: f.certificatePEM},
		{name: "another leaf key", ca: f.ca, public: testKey(t).Public()},
		{name: "non Ed25519 leaf", ca: f.ca, public: ecdsaKey.Public()},
		{name: "expired leaf boundary", ca: f.ca, change: func(c *x509.Certificate) { c.NotAfter = f.now }},
		{name: "future leaf", ca: f.ca, change: func(c *x509.Certificate) { c.NotBefore = f.now.Add(time.Second) }},
		{name: "proof outlives leaf", ca: f.ca, change: func(c *x509.Certificate) { c.NotAfter = f.now.Add(29 * time.Second) }},
		{name: "wrong deployment identity", ca: f.ca, change: func(c *x509.Certificate) {
			c.URIs[0], _ = pki.DeviceIdentityURL(uuid.New(), f.binding.DeviceID, f.binding.EnrollmentGeneration)
		}},
		{name: "wrong device identity", ca: f.ca, change: func(c *x509.Certificate) {
			device := uuid.New()
			c.Subject.CommonName = device.String()
			c.URIs[0], _ = pki.DeviceIdentityURL(f.binding.DeploymentID, device, f.binding.EnrollmentGeneration)
		}},
		{name: "wrong generation identity", ca: f.ca, change: func(c *x509.Certificate) {
			c.URIs[0], _ = pki.DeviceIdentityURL(f.binding.DeploymentID, f.binding.DeviceID, uuid.New())
		}},
		{name: "wrong subject", ca: f.ca, change: func(c *x509.Certificate) { c.Subject.CommonName = "relay" }},
		{name: "CA instead of device", ca: f.ca, change: func(c *x509.Certificate) { c.IsCA = true }},
		{name: "extra key authority", ca: f.ca, change: func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageCertSign }},
		{name: "server rather than device usage", ca: f.ca, change: func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }},
		{name: "extra TLS name", ca: f.ca, change: func(c *x509.Certificate) { c.DNSNames = []string{"relay.example"} }},
		{name: "missing certificate", ca: f.ca, pem: []byte{}},
		{name: "oversized certificate", ca: f.ca, pem: bytes.Repeat([]byte{' '}, 16385)},
		{name: "not PEM", ca: f.ca, pem: []byte("device certificate")},
		{name: "invalid DER", ca: f.ca, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}})},
		{name: "wrong PEM type", ca: f.ca, pem: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: decodeCertificate(t, f.certificatePEM).Raw})},
		{name: "PEM headers", ca: f.ca, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"X-Relay": "ignored"}, Bytes: decodeCertificate(t, f.certificatePEM).Raw})},
		{name: "bundled CA", ca: f.ca, pem: append(bytes.Clone(f.certificatePEM), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.Raw})...)},
		{name: "two leaves", ca: f.ca, pem: append(bytes.Clone(f.certificatePEM), f.certificatePEM...)},
		{name: "leading junk", ca: f.ca, pem: append([]byte("relay-selected metadata\n"), f.certificatePEM...)},
		{name: "malformed first PEM block", ca: f.ca, pem: append([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n"), f.certificatePEM...)},
		{name: "trailing junk", ca: f.ca, pem: append(bytes.Clone(f.certificatePEM), []byte("relay-selected metadata")...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certificatePEM := tc.pem
			if certificatePEM == nil {
				public := tc.public
				if public == nil {
					public = f.key.Public()
				}
				certificatePEM = f.certificate(t, public, tc.change)
			}
			got, err := f.authority.VerifyResourceAttestation(t.Context(), envelope, certificatePEM, tc.ca, &f.binding, f.now, 0)
			if tc.valid {
				if err != nil || !proto.Equal(got, f.attestation) {
					t.Fatalf("valid device certificate rejected: %v", err)
				}
			} else if err == nil || got != nil {
				t.Fatal("untrusted device certificate accepted")
			}
		})
	}
}

func TestResourceAttestationRejectsForgeriesAndWrongDomains(t *testing.T) {
	f := newResourceAttestationFixture(t)
	valid := executionSign(t, f.authority, f.attestation, f.key)
	var parsed dsse.Envelope
	if err := json.Unmarshal(valid, &parsed); err != nil {
		t.Fatal(err)
	}
	changed := proto.CloneOf(f.attestation)
	changed.Status.State, changed.Status.Failure = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NATIVE
	payload, err := proto.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Payload = base64.StdEncoding.EncodeToString(payload)
	tampered, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	claimedKeyID := parsed.Signatures[0].KeyID
	if err := json.Unmarshal(signResourceAttestationUnchecked(t, f.attestation, ResourceAttestationType, testKey(t)), &parsed); err != nil {
		t.Fatal(err)
	}
	parsed.Signatures[0].KeyID = claimedKeyID
	routed, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Signatures = nil
	unsigned, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		envelope []byte
	}{
		{name: "missing proof"},
		{name: "oversized proof", envelope: bytes.Repeat([]byte{' '}, 65537)},
		{name: "relay signed status", envelope: signResourceAttestationUnchecked(t, f.attestation, ResourceAttestationType, testKey(t))},
		{name: "CA signed status", envelope: signResourceAttestationUnchecked(t, f.attestation, ResourceAttestationType, f.caKey)},
		{name: "challenge domain", envelope: signResourceAttestationUnchecked(t, f.attestation, ResourceChallengeType, f.key)},
		{name: "start domain", envelope: signResourceAttestationUnchecked(t, f.attestation, ResourceStartType, f.key)},
		{name: "unrecognized domain", envelope: signResourceAttestationUnchecked(t, f.attestation, "application/vnd.relay.status", f.key)},
		{name: "forged device key routing label", envelope: routed},
		{name: "status changed without signature", envelope: tampered},
		{name: "unsigned status", envelope: unsigned},
		{name: "unknown envelope field", envelope: append(append([]byte(`{"relayTrusted":true,`), valid[1:]...), '\n')},
		{name: "trailing envelope", envelope: append(bytes.Clone(valid), valid...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := f.authority.VerifyResourceAttestation(t.Context(), tc.envelope, f.certificatePEM, f.ca, &f.binding, f.now, 0); err == nil || got != nil {
				t.Fatal("forged or cross-domain proof accepted")
			}
		})
	}
}

func TestResourceAttestationRejectsSignedMalformedPayloads(t *testing.T) {
	f := newResourceAttestationFixture(t)
	for _, tc := range []struct {
		name   string
		change func(*agentv1.ResourceExecutionAttestation)
	}{
		{name: "missing issuance", change: func(a *agentv1.ResourceExecutionAttestation) { a.IssuedAt = nil }},
		{name: "missing expiry", change: func(a *agentv1.ResourceExecutionAttestation) { a.ExpiresAt = nil }},
		{name: "invalid timestamp", change: func(a *agentv1.ResourceExecutionAttestation) { a.IssuedAt.Nanos = 1000000000 }},
		{name: "empty interval", change: func(a *agentv1.ResourceExecutionAttestation) { a.ExpiresAt = proto.CloneOf(a.IssuedAt) }},
		{name: "reversed interval", change: func(a *agentv1.ResourceExecutionAttestation) { a.ExpiresAt = timestamppb.New(f.now.Add(-time.Second)) }},
		{name: "interval exceeds thirty seconds", change: func(a *agentv1.ResourceExecutionAttestation) {
			a.ExpiresAt = timestamppb.New(f.now.Add(30*time.Second + time.Nanosecond))
		}},
		{name: "missing status", change: func(a *agentv1.ResourceExecutionAttestation) { a.Status = nil }},
		{name: "zero revision", change: func(a *agentv1.ResourceExecutionAttestation) { a.ActionRevision = 0 }},
		{name: "zero session", change: func(a *agentv1.ResourceExecutionAttestation) { a.SessionEpoch = 0 }},
		{name: "short nonce", change: func(a *agentv1.ResourceExecutionAttestation) { a.Nonce = a.Nonce[:31] }},
		{name: "long nonce", change: func(a *agentv1.ResourceExecutionAttestation) { a.Nonce = append(a.Nonce, 0) }},
		{name: "short digest", change: func(a *agentv1.ResourceExecutionAttestation) { a.Status.IntentSha256 = a.Status.IntentSha256[:31] }},
		{name: "zero action", change: func(a *agentv1.ResourceExecutionAttestation) { a.Status.ActionId = uuid.Nil.String() }},
		{name: "unknown attestation field", change: func(a *agentv1.ResourceExecutionAttestation) { a.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01}) }},
		{name: "unknown nested status field", change: func(a *agentv1.ResourceExecutionAttestation) {
			a.Status.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
		}},
		{name: "unknown nested observation field", change: func(a *agentv1.ResourceExecutionAttestation) {
			a.Status.Before.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
		}},
		{name: "unknown state", change: func(a *agentv1.ResourceExecutionAttestation) { a.Status.State = 99 }},
		{name: "unknown failure", change: func(a *agentv1.ResourceExecutionAttestation) { a.Status.Failure = 99 }},
		{name: "success without completion", change: func(a *agentv1.ResourceExecutionAttestation) { a.Status.CompletedAt = nil }},
		{name: "success without verification", change: func(a *agentv1.ResourceExecutionAttestation) { a.Status.Verification = nil }},
		{name: "success without convergence", change: func(a *agentv1.ResourceExecutionAttestation) {
			a.Status.Verification.Disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED
		}},
		{name: "success carrying failure", change: func(a *agentv1.ResourceExecutionAttestation) {
			a.Status.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NATIVE
		}},
		{name: "false convergence", change: func(a *agentv1.ResourceExecutionAttestation) {
			a.Status.Verification.GetSystemdService().DefinitionMatches = false
		}},
		{name: "pending already completed", change: func(a *agentv1.ResourceExecutionAttestation) {
			a.Status.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED
			a.Status.StartedAt = nil
		}},
		{name: "queued already started", change: func(a *agentv1.ResourceExecutionAttestation) {
			a.Status.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED
			a.Status.CompletedAt = nil
		}},
		{name: "running not started", change: func(a *agentv1.ResourceExecutionAttestation) {
			a.Status.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING
			a.Status.StartedAt, a.Status.CompletedAt = nil, nil
		}},
		{name: "pending carrying failure", change: func(a *agentv1.ResourceExecutionAttestation) {
			a.Status.State, a.Status.Failure = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NATIVE
			a.Status.StartedAt, a.Status.CompletedAt = nil, nil
		}},
		{name: "failure without cause", change: func(a *agentv1.ResourceExecutionAttestation) {
			a.Status.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED
		}},
		{name: "failure without completion", change: func(a *agentv1.ResourceExecutionAttestation) {
			a.Status.State, a.Status.Failure = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NATIVE
			a.Status.CompletedAt = nil
		}},
		{name: "missing historical observation", change: func(a *agentv1.ResourceExecutionAttestation) { a.Status.Before = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := proto.CloneOf(f.attestation)
			tc.change(candidate)
			envelope := signResourceAttestationUnchecked(t, candidate, ResourceAttestationType, f.key)
			if got, err := f.authority.VerifyResourceAttestation(t.Context(), envelope, f.certificatePEM, f.ca, &f.binding, f.now, 0); err == nil || got != nil {
				t.Fatal("signed malformed evidence accepted")
			}
		})
	}
}

func TestResourceAttestationPreservesEveryDurableState(t *testing.T) {
	f := newResourceAttestationFixture(t)
	for _, tc := range []struct {
		state   agentv1.ResourceExecutionState
		failure agentv1.ResourceExecutionFailure
	}{
		{agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NONE},
		{agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NONE},
		{agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NONE},
		{agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NONE},
		{agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NATIVE},
		{agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_OUTCOME_UNKNOWN, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_INTERRUPTED},
		{agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_EXPIRED},
		{agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUPERSEDED, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_SUPERSEDED},
	} {
		t.Run(tc.state.String(), func(t *testing.T) {
			candidate := proto.CloneOf(f.attestation)
			candidate.Status.State, candidate.Status.Failure = tc.state, tc.failure
			if tc.state != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED {
				candidate.Status.Verification = nil
			}
			if tc.state <= agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING {
				candidate.Status.CompletedAt = nil
			}
			if tc.state != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING {
				// Even success can be a no-op; not every terminal action started
				// native effects. Authentication must preserve that distinction.
				candidate.Status.StartedAt = nil
				// A successful no-effect status is an explicit read-only finding.
				candidate.Status.ReadOnly = tc.state == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED
			}
			envelope := executionSign(t, f.authority, candidate, f.key)
			got, err := f.authority.VerifyResourceAttestation(t.Context(), envelope, f.certificatePEM, f.ca, &f.binding, f.now, 0)
			if err != nil || !proto.Equal(got, candidate) {
				t.Fatalf("durable status changed or rejected: %v", err)
			}
		})
	}
}

func TestResourceAttestationRenewalAuthenticatesUnchangedHistoricalEvidence(t *testing.T) {
	f := newResourceAttestationFixture(t)
	oldKey := testKey(t)
	oldCertificate := f.certificate(t, oldKey.Public(), func(c *x509.Certificate) {
		c.SerialNumber = big.NewInt(1)
		c.NotBefore, c.NotAfter = f.now.Add(-45*time.Minute), f.now.Add(-15*time.Minute)
	})
	historical := proto.CloneOf(f.attestation)
	historical.IssuedAt = timestamppb.New(f.now.Add(-28 * time.Minute))
	historical.ExpiresAt = timestamppb.New(f.now.Add(-28*time.Minute + 30*time.Second))
	oldEnvelope := executionSign(t, f.authority, historical, oldKey)
	if got, err := f.authority.VerifyResourceAttestation(t.Context(), oldEnvelope, oldCertificate, f.ca, &f.binding, historical.GetIssuedAt().AsTime(), 0); err != nil || !proto.Equal(got.Status, f.attestation.Status) {
		t.Fatalf("original proof invalid during old leaf lifetime: %v", err)
	}
	// The renewed key/certificate were not valid at the recorded observation.
	// Only the freshly signed snapshot must satisfy current identity validity.
	freshEnvelope := executionSign(t, f.authority, f.attestation, f.key)
	got, err := f.authority.VerifyResourceAttestation(t.Context(), freshEnvelope, f.certificatePEM, f.ca, &f.binding, f.now, 0)
	if err != nil || !proto.Equal(got, f.attestation) || !proto.Equal(got.Status, historical.Status) || got.GetActionRevision() != historical.GetActionRevision() {
		t.Fatalf("renewal lost historical evidence: %v", err)
	}
	freshWithOldKey := executionSign(t, f.authority, f.attestation, oldKey)
	for _, tc := range []struct {
		name                  string
		envelope, certificate []byte
	}{
		{name: "replayed old proof", envelope: oldEnvelope, certificate: oldCertificate},
		{name: "fresh proof expired leaf", envelope: freshWithOldKey, certificate: oldCertificate},
		{name: "old key relabeled with renewed certificate", envelope: freshWithOldKey, certificate: f.certificatePEM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if result, err := f.authority.VerifyResourceAttestation(t.Context(), tc.envelope, tc.certificate, f.ca, &f.binding, f.now, 0); err == nil || result != nil {
				t.Fatal("expired identity or substituted renewal key accepted")
			}
		})
	}

	// A wall-clock rollback must not turn retained timestamps into a new native
	// observation, or make otherwise authentic history unverifiable.
	rolledBack := proto.CloneOf(f.attestation)
	for _, timestamp := range []*timestamppb.Timestamp{
		rolledBack.Status.AcceptedAt, rolledBack.Status.StartedAt, rolledBack.Status.CompletedAt,
		rolledBack.Status.Before.Metadata.ObservedAt, rolledBack.Status.Before.GetSystemdService().ObservedAt,
		rolledBack.Status.Verification.After.Metadata.ObservedAt, rolledBack.Status.Verification.After.GetSystemdService().ObservedAt,
		rolledBack.Status.Verification.GetSystemdService().Observation.ObservedAt,
	} {
		timestamp.Seconds += int64((2 * time.Hour) / time.Second)
	}
	envelope := executionSign(t, f.authority, rolledBack, f.key)
	got, err = f.authority.VerifyResourceAttestation(t.Context(), envelope, f.certificatePEM, f.ca, &f.binding, f.now, 0)
	if err != nil || !proto.Equal(got, rolledBack) {
		t.Fatalf("historic timestamps after clock rollback changed or rejected: %v", err)
	}
}

func TestResourceAttestationExplicitDeviceClockTolerance(t *testing.T) {
	f := newResourceAttestationFixture(t)
	for _, tc := range []struct {
		name      string
		offset    time.Duration
		tolerance time.Duration
		accepted  bool
	}{
		{"ahead ninety seconds", 90 * time.Second, MaxDeviceClockSkew, true},
		{"behind ninety seconds", -90 * time.Second, MaxDeviceClockSkew, true},
		{"ahead at inclusive boundary", MaxDeviceClockSkew, MaxDeviceClockSkew, true},
		{"ahead beyond boundary", MaxDeviceClockSkew + time.Nanosecond, MaxDeviceClockSkew, false},
		{"expired at exclusive boundary", -MaxDeviceClockSkew - 30*time.Second, MaxDeviceClockSkew, false},
		{"ahead three minutes", 3 * time.Minute, MaxDeviceClockSkew, false},
		{"behind three minutes", -3 * time.Minute, MaxDeviceClockSkew, false},
		{"explicit strict mode", time.Second, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := proto.CloneOf(f.attestation)
			candidate.IssuedAt = timestamppb.New(f.now.Add(tc.offset))
			candidate.ExpiresAt = timestamppb.New(f.now.Add(tc.offset + 30*time.Second))
			envelope := executionSign(t, f.authority, candidate, f.key)
			got, err := f.authority.VerifyResourceAttestation(t.Context(), envelope, f.certificatePEM, f.ca, &f.binding, f.now, tc.tolerance)
			if tc.accepted {
				if err != nil || !proto.Equal(got, candidate) {
					t.Fatalf("bounded clock tolerance rejected evidence: %v", err)
				}
			} else if got != nil || !errors.Is(err, ErrDeviceClockSkew) {
				t.Fatalf("outside tolerance = %v, want device_clock_skew", err)
			}
		})
	}
	envelope := executionSign(t, f.authority, f.attestation, f.key)
	if _, err := f.authority.VerifyResourceAttestation(t.Context(), envelope, f.certificatePEM, f.ca, &f.binding, f.now, -time.Second); err == nil {
		t.Fatal("negative clock tolerance accepted")
	}
	certificate := f.certificate(t, f.key.Public(), func(cert *x509.Certificate) {
		cert.NotAfter = f.now.Add(15 * time.Second)
	})
	if _, err := f.authority.VerifyResourceAttestation(t.Context(), envelope, certificate, f.ca, &f.binding, f.now, MaxDeviceClockSkew); err == nil {
		t.Fatal("clock tolerance extended signing certificate validity")
	}
}
