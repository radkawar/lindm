package config

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/trust"
)

func TestExecutionBootstrapBindsDeploymentAndTransport(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*testing.T, *executionConfigFixture)
	}{
		{name: "other deployment", change: func(_ *testing.T, f *executionConfigFixture) {
			f.document.Proto.DeploymentId = uuid.NewString()
		}},
		{name: "other administrative origin", change: func(_ *testing.T, f *executionConfigFixture) {
			f.document.Proto.PublicUrl = "https://localhost:8444"
		}},
		{name: "other device origin", change: func(_ *testing.T, f *executionConfigFixture) {
			f.document.Proto.DevicePublicUrl = proto.String("https://localhost:8445")
		}},
		{name: "other device CA", change: func(t *testing.T, f *executionConfigFixture) {
			writeCertificate(t, f.document.base, "device", true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
		}},
		{name: "transport pin cannot verify server", change: func(t *testing.T, f *executionConfigFixture) {
			writeCertificate(t, f.document.base, "other-transport", true, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil)
			f.bundle.TransportCaPem = executionConfigFile(t, f.document.base, "other-transport.crt")
			f.publish(t)
		}},
		{name: "device hostname absent from server certificate", change: func(t *testing.T, f *executionConfigFixture) {
			f.document.Proto.DevicePublicUrl = proto.String("https://devices.example")
			f.bundle.DeviceOrigin = f.document.Proto.GetDevicePublicUrl()
			f.publish(t)
		}},
		{name: "TLS leaf holds execution root key", change: func(t *testing.T, f *executionConfigFixture) {
			writeExecutionServerCertificate(t, f.document.base, f.transport, f.rootKey)
		}},
		{name: "unsigned substituted root", change: func(t *testing.T, f *executionConfigFixture) {
			_, other, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := f.authority.Sign(t.Context(), f.bundle, other)
			if err != nil {
				t.Fatal(err)
			}
			writeFixtureFile(t, f.document.base, "bootstrap.dsse.json", envelope)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newExecutionConfigFixture(t)
			resources, err := f.document.Resolve()
			if err != nil {
				t.Fatalf("valid public bootstrap rejected: %v", err)
			}
			resources.HTTPClient.CloseIdleConnections()
			test.change(t, f)
			resources, err = f.document.Resolve()
			if err == nil {
				resources.HTTPClient.CloseIdleConnections()
				t.Fatalf("accepted %s", test.name)
			}
		})
	}
}

type executionConfigFixture struct {
	document   *Document
	authority  *trust.Authority
	root       *agentv1.ExecutionRoot
	bundle     *agentv1.BootstrapBundle
	rootKey    ed25519.PrivateKey
	releaseKey ed25519.PrivateKey
	transport  tls.Certificate
}

func newExecutionConfigFixture(t *testing.T) *executionConfigFixture {
	t.Helper()
	dir := databaseFixture(t)
	writeCertificate(t, dir, "root", true, nil, nil)
	writeCertificate(t, dir, "client", false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	writeCertificate(t, dir, "transport", true, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil)
	writeCertificate(t, dir, "device", true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	transport, err := keyPair(dir, "transport.crt", "transport.key")
	if err != nil {
		t.Fatal(err)
	}
	_, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeExecutionServerCertificate(t, dir, transport, serverKey)
	writeFixtureFile(t, dir, "oidc-secret", []byte("isolated-test-credential"))
	deployment := uuid.NewString()
	document := &Document{base: dir, Proto: &configv1.ServerConfig{
		DeploymentId: deployment, PublicUrl: "https://localhost:7444", DevicePublicUrl: proto.String("https://localhost:7445"),
		Database:           &configv1.DatabaseConfig{UrlFile: "database-url", MaxConnections: 2},
		Tls:                &configv1.TLSConfig{CertificateFile: "server.crt", PrivateKeyFile: "server.key"},
		DeviceCa:           &configv1.DeviceCAConfig{CertificateFile: "device.crt", PrivateKeyFile: "device.key"},
		Authentication:     &configv1.AuthenticationConfig{Primary: &configv1.AuthenticationConfig_Keycloak{Keycloak: &configv1.KeycloakDirectory{ClientSecretFile: "oidc-secret", DirectoryClientSecretFile: "oidc-secret"}}},
		ExecutionBootstrap: &configv1.ExecutionBootstrapConfig{RootFile: "execution-root.json", BootstrapFile: "bootstrap.dsse.json"},
	}}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	root := &agentv1.ExecutionRoot{
		DeploymentId: deployment, Version: 1, Threshold: 1,
		NotBefore: timestamppb.New(now.Add(-time.Minute)), ExpiresAt: timestamppb.New(now.Add(30 * time.Minute)),
		Keys: []*agentv1.ExecutionKey{{KeyId: keyID, PublicKey: public}},
	}
	releasePublic, releasePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	releaseKey, err := metadata.KeyFromPublicKey(releasePublic)
	if err != nil {
		t.Fatal(err)
	}
	release := metadata.Root(now.Add(30 * time.Minute))
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		if err := release.Signed.AddKey(releaseKey, role); err != nil {
			t.Fatal(err)
		}
	}
	signer, err := signature.LoadSignerVerifier(releasePrivate, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := release.Sign(signer); err != nil {
		t.Fatal(err)
	}
	releaseJSON, err := release.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := trust.New()
	if err != nil {
		t.Fatal(err)
	}
	f := &executionConfigFixture{
		document: document, authority: authority, root: root, rootKey: private, releaseKey: releasePrivate, transport: transport,
		bundle: &agentv1.BootstrapBundle{
			BundleId: uuid.NewString(), DeploymentId: deployment, EnrollmentOrigin: document.Proto.GetPublicUrl(), DeviceOrigin: document.Proto.GetDevicePublicUrl(),
			TransportCaPem: executionConfigFile(t, dir, "transport.crt"), DeviceCaPem: executionConfigFile(t, dir, "device.crt"),
			ExecutionRootVersion: 1, ReleaseRootJson: releaseJSON, NotBefore: root.GetNotBefore(), ExpiresAt: root.GetExpiresAt(),
		},
	}
	f.publish(t)
	return f
}

func (f *executionConfigFixture) publish(t *testing.T) {
	t.Helper()
	rootJSON, err := protojson.Marshal(f.root)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(rootJSON)
	f.bundle.ExecutionRootSha256 = digest[:]
	envelope, err := f.authority.Sign(t.Context(), f.bundle, f.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, f.document.base, "execution-root.json", rootJSON)
	writeFixtureFile(t, f.document.base, "bootstrap.dsse.json", envelope)
}

func executionConfigFile(t *testing.T, dir, name string) []byte {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return contents
}

func writeExecutionServerCertificate(t *testing.T, dir string, issuer tls.Certificate, key ed25519.PrivateKey) {
	t.Helper()
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, issuer.Leaf, key.Public(), issuer.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, dir, "server.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded}))
	writeFixtureFile(t, dir, "server.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
}
