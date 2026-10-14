// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestEnvelopeAuthorityDomainAndQuorum(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	first, second := testKey(t), testKey(t)
	message := &agentv1.IssuanceRetrieval{DeploymentId: uuid.NewString(), DeviceId: uuid.NewString(), EnrollmentGeneration: uuid.NewString(), IssuanceRequestId: uuid.NewString()}
	encoded, err := a.Sign(t.Context(), message, first, second)
	if err != nil {
		t.Fatal(err)
	}
	public := []ed25519.PublicKey{ed25519.PublicKey(first[ed25519.SeedSize:]), ed25519.PublicKey(second[ed25519.SeedSize:])}
	var decoded agentv1.IssuanceRetrieval
	if err := a.Verify(t.Context(), encoded, &decoded, 2, public...); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(message, &decoded) {
		t.Fatal("verified authority changed its bound identity")
	}
	if err := a.Verify(t.Context(), encoded, new(agentv1.RenewalIntent), 2, public...); err == nil {
		t.Fatal("accepted retrieval signature as renewal authority")
	}
	var envelope dsse.Envelope
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Signatures[1] = envelope.Signatures[0]
	duplicate, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(t.Context(), duplicate, &decoded, 2, public...); err == nil {
		t.Fatal("duplicate signature satisfied quorum")
	}
	if !proto.Equal(message, &decoded) {
		t.Fatal("failed verification mutated the destination")
	}
	if err := a.Verify(t.Context(), encoded, &decoded, 2, public[0], public[0]); err == nil {
		t.Fatal("duplicate public key satisfied quorum")
	}
	envelope.PayloadType = RenewalType
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(t.Context(), tampered, new(agentv1.RenewalIntent), 1, public...); err == nil {
		t.Fatal("accepted a changed DSSE payload type")
	}
}

func TestBootstrapTrustBindings(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	key := testKey(t)
	public := ed25519.PublicKey(key[ed25519.SeedSize:])
	id, err := KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	root := &agentv1.ExecutionRoot{DeploymentId: uuid.NewString(), Version: 1, Threshold: 1, NotBefore: timestamppb.New(now.Add(-time.Hour)), ExpiresAt: timestamppb.New(now.Add(24 * time.Hour)), Keys: []*agentv1.ExecutionKey{{KeyId: id, PublicKey: public}}}
	rootJSON, err := protojson.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(rootJSON)
	transport := testCA(t, testKey(t), now, x509.ExtKeyUsageServerAuth)
	device := testCA(t, testKey(t), now, x509.ExtKeyUsageClientAuth)
	consoleKey := testKey(t)
	console := testCA(t, consoleKey, now, x509.ExtKeyUsageServerAuth)
	bundle := &agentv1.BootstrapBundle{BundleId: uuid.NewString(), DeploymentId: root.GetDeploymentId(), EnrollmentOrigin: "https://enroll.example", DeviceOrigin: "https://devices.example", TransportCaPem: transport, ConsoleCaPem: console, DeviceCaPem: device, ExecutionRootVersion: 1, ExecutionRootSha256: digest[:], ReleaseRootJson: testReleaseRoot(t, testKey(t), now.Add(time.Hour)), NotBefore: timestamppb.New(now.Add(-time.Minute)), ExpiresAt: timestamppb.New(now.Add(time.Hour))}
	for _, test := range []struct {
		name   string
		change func(*agentv1.BootstrapBundle)
		at     time.Time
		valid  bool
	}{
		{name: "valid independent trust", at: now, valid: true},
		{name: "explicit shared server issuer", at: now, valid: true, change: func(b *agentv1.BootstrapBundle) { b.ConsoleCaPem = transport }},
		{name: "invalid console CA", at: now, change: func(b *agentv1.BootstrapBundle) { b.ConsoleCaPem = bytes.Repeat([]byte("invalid"), 12) }},
		{name: "wrong console CA usage", at: now, change: func(b *agentv1.BootstrapBundle) { b.ConsoleCaPem = device }},
		{name: "console reuses device CA key", at: now, change: func(b *agentv1.BootstrapBundle) {
			b.DeviceCaPem = testCA(t, consoleKey, now, x509.ExtKeyUsageClientAuth)
		}},
		{name: "console reuses execution key", at: now, change: func(b *agentv1.BootstrapBundle) { b.ConsoleCaPem = testCA(t, key, now, x509.ExtKeyUsageServerAuth) }},
		{name: "release reuses console key", at: now, change: func(b *agentv1.BootstrapBundle) {
			b.ReleaseRootJson = testReleaseRoot(t, consoleKey, now.Add(time.Hour))
		}},
		{name: "expired at exact boundary", at: now.Add(time.Hour)},
		{name: "wrong deployment", at: now, change: func(b *agentv1.BootstrapBundle) { b.DeploymentId = uuid.NewString() }},
		{name: "wrong root version", at: now, change: func(b *agentv1.BootstrapBundle) { b.ExecutionRootVersion = 2 }},
		{name: "wrong root digest", at: now, change: func(b *agentv1.BootstrapBundle) { b.ExecutionRootSha256 = make([]byte, 32) }},
		{name: "bundle outlives root", at: now, change: func(b *agentv1.BootstrapBundle) { b.ExpiresAt = timestamppb.New(now.Add(48 * time.Hour)) }},
		{name: "wrong device CA usage", at: now, change: func(b *agentv1.BootstrapBundle) { b.DeviceCaPem = transport }},
		{name: "release reuses execution key", at: now, change: func(b *agentv1.BootstrapBundle) { b.ReleaseRootJson = testReleaseRoot(t, key, now.Add(time.Hour)) }},
		{name: "expired release root", at: now, change: func(b *agentv1.BootstrapBundle) { b.ReleaseRootJson = testReleaseRoot(t, testKey(t), now) }},
		{name: "unsigned release root", at: now, change: func(b *agentv1.BootstrapBundle) {
			r, err := metadata.Root().FromBytes(b.ReleaseRootJson)
			if err != nil {
				t.Fatal(err)
			}
			r.Signatures = nil
			b.ReleaseRootJson, err = r.ToBytes(false)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{name: "null release root role", at: now, change: func(b *agentv1.BootstrapBundle) {
			r, err := metadata.Root().FromBytes(b.ReleaseRootJson)
			if err != nil {
				t.Fatal(err)
			}
			r.Signed.Roles["root"] = nil
			b.ReleaseRootJson, err = r.ToBytes(false)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{name: "null release key", at: now, change: func(b *agentv1.BootstrapBundle) {
			r, err := metadata.Root().FromBytes(b.ReleaseRootJson)
			if err != nil {
				t.Fatal(err)
			}
			for id := range r.Signed.Keys {
				r.Signed.Keys[id] = nil
			}
			b.ReleaseRootJson, err = r.ToBytes(false)
			if err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := proto.CloneOf(bundle)
			if test.change != nil {
				test.change(candidate)
			}
			envelope, err := a.Sign(t.Context(), candidate, key)
			if err != nil {
				t.Fatal(err)
			}
			got, err := a.VerifyBootstrap(t.Context(), rootJSON, envelope, test.at)
			if !test.valid {
				if err == nil {
					t.Fatal("accepted invalid bootstrap authority")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Bundle.GetDeviceOrigin() != bundle.GetDeviceOrigin() || !bytes.Equal(got.DeviceCA.Raw, decodeCertificate(t, device).Raw) {
				t.Fatal("bootstrap changed its pinned device authority")
			}
		})
	}
}

func TestBootstrapMissingConsoleCAFailsClosed(t *testing.T) {
	f := newExecutionFixture(t, 1)
	bundle := proto.CloneOf(f.bootstrap.Bundle)
	bundle.ConsoleCaPem = nil
	if _, err := f.authority.Sign(t.Context(), bundle, f.keys...); err == nil {
		t.Fatal("signed bootstrap without required console trust")
	}
	// Authenticate the old-shaped payload with the real fixture root signer,
	// bypassing only producer schema validation, not DSSE verification.
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	public, ok := f.keys[0].Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("execution fixture signer is not Ed25519")
	}
	id, err := KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := dsse.NewEnvelopeSigner(&edSigner{edVerifier: edVerifier{public: public, id: id}, private: f.keys[0]})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signer.SignPayload(t.Context(), BootstrapType, payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.authority.VerifyBootstrap(t.Context(), f.rootJSON, encoded, f.now); err == nil {
		t.Fatal("accepted authenticated bootstrap missing console CA")
	}
}

func TestBootstrapConsoleSignedDeviceHostnameCertificateIsRejected(t *testing.T) {
	f := newExecutionFixture(t, 1)
	consoleCA := decodeCertificate(t, f.bootstrap.Bundle.GetConsoleCaPem())
	key := testKey(t)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), DNSNames: []string{"devices.example"},
		NotBefore: f.now.Add(-time.Minute), NotAfter: f.now.Add(time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, consoleCA, key.Public(), f.reserved[3])
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	options := x509.VerifyOptions{Roots: f.bootstrap.ConsoleRoots, DNSName: "devices.example", CurrentTime: f.now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if _, err := certificate.Verify(options); err != nil {
		t.Fatalf("console-signed adversarial fixture is not a valid same-DNS certificate: %v", err)
	}
	options.Roots = f.bootstrap.TransportRoots
	if _, err := certificate.Verify(options); err == nil {
		t.Fatal("device roots accepted console-signed device-hostname certificate")
	}
}

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testCA(t *testing.T, key ed25519.PrivateKey, now time.Time, usage x509.ExtKeyUsage) []byte {
	t.Helper()
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated trust fixture"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func decodeCertificate(t *testing.T, encoded []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(encoded)
	if block == nil {
		t.Fatal("missing fixture certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func testReleaseRoot(t *testing.T, key ed25519.PrivateKey, expires time.Time) []byte {
	t.Helper()
	root := metadata.Root(expires)
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
