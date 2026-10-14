// SPDX-License-Identifier: Apache-2.0

// Package testfixture supplies real quorum-signed bootstrap material for agent
// boundary tests. It does not replace authority verification or TLS verification.
package testfixture

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
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

type Bootstrap struct {
	RootJSON, Envelope []byte
	Verified           *trust.Bootstrap
	TransportCA        *x509.Certificate
	ConsoleCA          *x509.Certificate
	DeviceCA           *x509.Certificate
	now                time.Time
	transportKey       crypto.Signer
	consoleKey         crypto.Signer
	deviceKey          crypto.Signer
}

func NewBootstrap(t testing.TB, now time.Time, enrollmentOrigin, deviceOrigin string) *Bootstrap {
	t.Helper()
	fixture := &Bootstrap{now: now, transportKey: edKey(t), deviceKey: edKey(t)}
	consoleKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fixture.consoleKey = consoleKey
	transportPEM, transportCA := ca(t, now, fixture.transportKey, "device-transport-ca", x509.ExtKeyUsageServerAuth)
	consolePEM, consoleCA := ca(t, now, fixture.consoleKey, "console-ca", x509.ExtKeyUsageServerAuth)
	devicePEM, deviceCA := ca(t, now, fixture.deviceKey, "device-client-ca", x509.ExtKeyUsageClientAuth)
	fixture.TransportCA, fixture.ConsoleCA, fixture.DeviceCA = transportCA, consoleCA, deviceCA
	keys := []ed25519.PrivateKey{edKey(t), edKey(t)}
	root := &agentv1.ExecutionRoot{DeploymentId: uuid.NewString(), Version: 1, Threshold: 2, NotBefore: timestamppb.New(now.Add(-time.Hour)), ExpiresAt: timestamppb.New(now.Add(48 * time.Hour))}
	for _, key := range keys {
		public, ok := key.Public().(ed25519.PublicKey)
		if !ok {
			t.Fatal("execution fixture signer is not Ed25519")
		}
		id, err := trust.KeyID(public)
		if err != nil {
			t.Fatal(err)
		}
		root.Keys = append(root.Keys, &agentv1.ExecutionKey{KeyId: id, PublicKey: public})
	}
	fixture.RootJSON, err = protojson.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(fixture.RootJSON)
	bundle := &agentv1.BootstrapBundle{
		BundleId: uuid.NewString(), DeploymentId: root.GetDeploymentId(), EnrollmentOrigin: enrollmentOrigin, DeviceOrigin: deviceOrigin,
		TransportCaPem: transportPEM, ConsoleCaPem: consolePEM, DeviceCaPem: devicePEM,
		ExecutionRootVersion: root.GetVersion(), ExecutionRootSha256: digest[:], ReleaseRootJson: releaseRoot(t, now),
		NotBefore: timestamppb.New(now.Add(-time.Minute)), ExpiresAt: timestamppb.New(now.Add(2 * time.Hour)),
	}
	authority, err := trust.New()
	if err != nil {
		t.Fatal(err)
	}
	fixture.Envelope, err = authority.Sign(t.Context(), bundle, keys...)
	if err != nil {
		t.Fatal(err)
	}
	fixture.Verified, err = authority.VerifyBootstrap(t.Context(), fixture.RootJSON, fixture.Envelope, now)
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (f *Bootstrap) Connection() *agentv1.GetConnectionResponse {
	bundle := f.Verified.Bundle
	return &agentv1.GetConnectionResponse{
		DeploymentId: bundle.GetDeploymentId(), EnrollmentOrigin: bundle.GetEnrollmentOrigin(), DeviceOrigin: bundle.GetDeviceOrigin(),
		TransportCaPem: bytes.Clone(bundle.GetTransportCaPem()), ConsoleCaPem: bytes.Clone(bundle.GetConsoleCaPem()),
	}
}

func (f *Bootstrap) Prepare() *agentv1.PrepareBootstrapResponse {
	bundle := f.Verified.Bundle
	return &agentv1.PrepareBootstrapResponse{
		DeploymentId: bundle.GetDeploymentId(), EnrollmentOrigin: bundle.GetEnrollmentOrigin(), DeviceOrigin: bundle.GetDeviceOrigin(),
		TransportCaPem: bytes.Clone(bundle.GetTransportCaPem()), ConsoleCaPem: bytes.Clone(bundle.GetConsoleCaPem()),
	}
}

// ServerCertificate signs the same DNS name with exactly one origin's CA.
func (f *Bootstrap) ServerCertificate(t testing.TB, console bool, hostname string) tls.Certificate {
	t.Helper()
	issuer, signer := f.TransportCA, f.transportKey
	if console {
		issuer, signer = f.ConsoleCA, f.consoleKey
	}
	key := edKey(t)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{hostname}, NotBefore: f.now.Add(-time.Minute), NotAfter: f.now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, leaf, issuer, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func (f *Bootstrap) DeviceCertificate(t testing.TB, csrPEM []byte, device, generation uuid.UUID) []byte {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("missing device CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	deployment, err := uuid.Parse(f.Verified.Root.GetDeploymentId())
	if err != nil {
		t.Fatal(err)
	}
	identity, err := pki.DeviceIdentityURL(deployment, device, generation)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: device.String()}, URIs: []*url.URL{identity}, NotBefore: f.now.Add(-time.Minute), NotAfter: f.now.Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, leaf, f.DeviceCA, csr.PublicKey, f.deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func edKey(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func ca(t testing.TB, now time.Time, key crypto.Signer, name string, usage x509.ExtKeyUsage) ([]byte, *x509.Certificate) {
	t.Helper()
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(40 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), parsed
}

func releaseRoot(t testing.TB, now time.Time) []byte {
	t.Helper()
	root := metadata.Root(now.Add(24 * time.Hour))
	var rootKey ed25519.PrivateKey
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		key := edKey(t)
		public, err := metadata.KeyFromPublicKey(key.Public())
		if err != nil {
			t.Fatal(err)
		}
		if err := root.Signed.AddKey(public, role); err != nil {
			t.Fatal(err)
		}
		if role == "root" {
			rootKey = key
		}
	}
	signer, err := signature.LoadSignerVerifier(rootKey, crypto.Hash(0))
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
