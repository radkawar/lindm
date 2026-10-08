//go:build linux

package executor

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/pki"
	"lindm/internal/trust"
)

type fixture struct {
	root    []byte
	bundle  []byte
	ca      *x509.Certificate
	caKey   ed25519.PrivateKey
	rootKey ed25519.PrivateKey
	now     time.Time
	deploy  uuid.UUID
}

func newFixture(t *testing.T, now time.Time) fixture {
	t.Helper()
	authority, err := trust.New()
	if err != nil {
		t.Fatal(err)
	}
	key := testKey(t)
	public := ed25519.PublicKey(key[ed25519.SeedSize:])
	id, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	deployment := uuid.New()
	root := &agentv1.ExecutionRoot{DeploymentId: deployment.String(), Version: 1, Threshold: 1, NotBefore: timestamppb.New(now.Add(-time.Hour)), ExpiresAt: timestamppb.New(now.Add(48 * time.Hour)), Keys: []*agentv1.ExecutionKey{{KeyId: id, PublicKey: public}}}
	rootJSON, err := protojson.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(rootJSON)
	caKey := testKey(t)
	devicePEM := testCA(t, caKey, now, x509.ExtKeyUsageClientAuth)
	bundle := &agentv1.BootstrapBundle{
		BundleId: uuid.NewString(), DeploymentId: deployment.String(), EnrollmentOrigin: "https://enroll.example", DeviceOrigin: "https://devices.example",
		TransportCaPem: testCA(t, testKey(t), now, x509.ExtKeyUsageServerAuth), DeviceCaPem: devicePEM, ExecutionRootVersion: 1, ExecutionRootSha256: digest[:],
		ReleaseRootJson: testReleaseRoot(t, testKey(t), now.Add(24*time.Hour)), NotBefore: timestamppb.New(now.Add(-time.Minute)), ExpiresAt: timestamppb.New(now.Add(2 * time.Hour)),
	}
	envelope, err := authority.Sign(t.Context(), bundle, key)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(devicePEM)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{root: rootJSON, bundle: envelope, ca: ca, caKey: caKey, rootKey: key, now: now, deploy: deployment}
}

func (f fixture) leaf(t *testing.T, pub ed25519.PublicKey, device, generation uuid.UUID, notBefore, notAfter time.Time) []byte {
	t.Helper()
	identity, err := pki.DeviceIdentityURL(f.deploy, device, generation)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: device.String()},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true, URIs: []*url.URL{identity},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, f.ca, pub, f.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func protectedDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
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
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture-ca"}, NotBefore: now.Add(-40 * 24 * time.Hour), NotAfter: now.Add(40 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
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
