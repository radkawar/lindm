// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/trust"
)

func TestExecutionSigningLoadsBeforeDelegation(t *testing.T) {
	f := newExecutionConfigFixture(t)
	plan, start := executionSigningKey(t), executionSigningKey(t)
	configureExecutionSigning(t, f, plan, start)
	resources := resolveExecutionSigning(t, f)
	again := resolveExecutionSigning(t, f)
	signing := resources.ExecutionSigning
	if signing == nil || again.ExecutionSigning == nil {
		t.Fatal("configured execution signing did not load")
	}
	if signing.PlanKeyID == "" || signing.StartKeyID == "" || signing.PlanKeyID == signing.StartKeyID ||
		signing.PlanKeyID != again.ExecutionSigning.PlanKeyID || signing.StartKeyID != again.ExecutionSigning.StartKeyID {
		t.Fatal("execution signing key identifiers were missing or unstable")
	}
	assertSigningKey(t, signing.PlanKey, signing.PlanKeyID, plan)
	assertSigningKey(t, signing.StartKey, signing.StartKeyID, start)
	rendered := fmt.Sprintf("%v\n%#v\n%s", signing, signing, signing)
	if bytes.Contains([]byte(rendered), plan) || bytes.Contains([]byte(rendered), start) {
		t.Fatal("execution signing printed private key material")
	}
	encoded, err := json.Marshal(signing)
	if err == nil || bytes.Contains(encoded, plan) || bytes.Contains(encoded, start) {
		t.Fatal("execution signing serialized private key material")
	}
}

func TestExecutionSigningAbsence(t *testing.T) {
	f := newExecutionConfigFixture(t)
	resources := resolveExecutionSigning(t, f)
	if resources.ExecutionSigning != nil {
		t.Fatal("absent execution signing created an issuer")
	}
	f.document.Proto.ExecutionBootstrap = nil
	resources = resolveExecutionSigning(t, f)
	if resources.ExecutionBootstrap != nil || resources.ExecutionSigning != nil {
		t.Fatal("absent bootstrap and signing created execution resources")
	}
	f.document.Proto.ExecutionSigning = &configv1.ExecutionSigningConfig{PlanKeyFile: "plan.key", StartKeyFile: "start.key"}
	if _, err := f.document.Resolve(); err == nil {
		t.Fatal("accepted execution signing without a bootstrap")
	}
}

func TestExecutionSigningSchema(t *testing.T) {
	base := executionSigningSchemaConfig()
	if err := validateExecutionSigningSchema(t, base); err != nil {
		t.Fatalf("valid signing schema rejected: %v", err)
	}
	absent := proto.CloneOf(base)
	absent.ExecutionSigning = nil
	if err := validateExecutionSigningSchema(t, absent); err != nil {
		t.Fatalf("absent signing schema rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		change func(*configv1.ServerConfig)
	}{
		{name: "signing without bootstrap", change: func(cfg *configv1.ServerConfig) { cfg.ExecutionBootstrap = nil }},
		{name: "same key file", change: func(cfg *configv1.ServerConfig) {
			cfg.ExecutionSigning.StartKeyFile = cfg.ExecutionSigning.GetPlanKeyFile()
		}},
		{name: "empty plan file", change: func(cfg *configv1.ServerConfig) { cfg.ExecutionSigning.PlanKeyFile = "" }},
		{name: "empty start file", change: func(cfg *configv1.ServerConfig) { cfg.ExecutionSigning.StartKeyFile = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := proto.CloneOf(base)
			test.change(cfg)
			if err := validateExecutionSigningSchema(t, cfg); err == nil {
				t.Fatalf("accepted %s", test.name)
			}
		})
	}
}

func TestExecutionSigningRejectsRoleAlias(t *testing.T) {
	shared := executionSigningKey(t)
	for _, test := range []struct {
		name   string
		change func(*testing.T, *executionConfigFixture)
	}{
		{name: "same key in distinct files", change: func(t *testing.T, f *executionConfigFixture) {
			configureExecutionSigning(t, f, shared, shared)
		}},
		{name: "symlink aliases one key file", change: func(t *testing.T, f *executionConfigFixture) {
			writeExecutionSigningKey(t, f.document.base, "start.key", shared)
			if err := os.Symlink("start.key", filepath.Join(f.document.base, "plan.key")); err != nil {
				t.Fatal(err)
			}
			f.document.Proto.ExecutionSigning = &configv1.ExecutionSigningConfig{PlanKeyFile: "plan.key", StartKeyFile: "start.key"}
		}},
		{name: "same resolved file", change: func(t *testing.T, f *executionConfigFixture) {
			writeExecutionSigningKey(t, f.document.base, "plan.key", shared)
			f.document.Proto.ExecutionSigning = &configv1.ExecutionSigningConfig{PlanKeyFile: "plan.key", StartKeyFile: "./plan.key"}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newExecutionConfigFixture(t)
			test.change(t, f)
			rejectExecutionSigning(t, f)
		})
	}
}

func TestExecutionSigningRejectsReservedKeys(t *testing.T) {
	for _, test := range []struct {
		name  string
		start bool
		key   func(*testing.T, *executionConfigFixture) ed25519.PrivateKey
	}{
		{name: "execution root", key: func(_ *testing.T, f *executionConfigFixture) ed25519.PrivateKey { return f.rootKey }},
		{name: "non-signing execution root", key: func(t *testing.T, f *executionConfigFixture) ed25519.PrivateKey {
			key := executionSigningKey(t)
			public := ed25519.PublicKey(key[ed25519.SeedSize:])
			id, err := trust.KeyID(public)
			if err != nil {
				t.Fatal(err)
			}
			f.root.Keys = append(f.root.Keys, &agentv1.ExecutionKey{KeyId: id, PublicKey: public})
			f.publish(t)
			return key
		}},
		{name: "transport CA", key: func(t *testing.T, f *executionConfigFixture) ed25519.PrivateKey {
			return executionFixturePrivateKey(t, f.document.base, "transport.key")
		}},
		{name: "additional transport CA", key: func(t *testing.T, f *executionConfigFixture) ed25519.PrivateKey {
			writeCertificate(t, f.document.base, "transport-extra", true, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil)
			f.bundle.TransportCaPem = append(bytes.Clone(f.bundle.TransportCaPem), executionConfigFile(t, f.document.base, "transport-extra.crt")...)
			f.publish(t)
			return executionFixturePrivateKey(t, f.document.base, "transport-extra.key")
		}},
		{name: "additional console CA", key: func(t *testing.T, f *executionConfigFixture) ed25519.PrivateKey {
			writeCertificate(t, f.document.base, "console-extra", true, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil)
			f.bundle.ConsoleCaPem = append(bytes.Clone(f.bundle.ConsoleCaPem), executionConfigFile(t, f.document.base, "console-extra.crt")...)
			f.publish(t)
			return executionFixturePrivateKey(t, f.document.base, "console-extra.key")
		}},
		{name: "device CA", key: func(t *testing.T, f *executionConfigFixture) ed25519.PrivateKey {
			return executionFixturePrivateKey(t, f.document.base, "device.key")
		}},
		{name: "server TLS leaf", start: true, key: func(t *testing.T, f *executionConfigFixture) ed25519.PrivateKey {
			return executionFixturePrivateKey(t, f.document.base, "server.key")
		}},
		{name: "release key", key: func(_ *testing.T, f *executionConfigFixture) ed25519.PrivateKey { return f.releaseKey }},
		{name: "targets-only release key", start: true, key: func(t *testing.T, f *executionConfigFixture) ed25519.PrivateKey {
			key := executionSigningKey(t)
			release, err := metadata.Root().FromBytes(f.bundle.ReleaseRootJson)
			if err != nil {
				t.Fatal(err)
			}
			public, err := metadata.KeyFromPublicKey(key.Public())
			if err != nil {
				t.Fatal(err)
			}
			if err := release.Signed.AddKey(public, "targets"); err != nil {
				t.Fatal(err)
			}
			release.Signatures = nil
			signer, err := signature.LoadSignerVerifier(f.releaseKey, crypto.Hash(0))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := release.Sign(signer); err != nil {
				t.Fatal(err)
			}
			encoded, err := release.ToBytes(false)
			if err != nil {
				t.Fatal(err)
			}
			f.bundle.ReleaseRootJson = encoded
			f.publish(t)
			return key
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newExecutionConfigFixture(t)
			reserved := test.key(t, f)
			other := executionSigningKey(t)
			if test.start {
				configureExecutionSigning(t, f, other, reserved)
			} else {
				configureExecutionSigning(t, f, reserved, other)
			}
			rejectExecutionSigning(t, f)
		})
	}
}

func TestExecutionSigningRejectsPKCS8(t *testing.T) {
	valid := func(t *testing.T) []byte {
		t.Helper()
		return executionSigningPEM(t, executionSigningKey(t))
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPKCS8, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecPKCS8, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	ecSEC1, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	encrypted := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encryptedPKCS8(t)})
	for _, test := range []struct {
		name    string
		plan    []byte
		start   []byte
		protect string
		mode    os.FileMode
	}{
		{name: "empty", plan: []byte{}, start: valid(t)},
		{name: "whitespace", plan: []byte(" \n\t"), start: valid(t)},
		{name: "leading non-whitespace", plan: append([]byte("comment\n"), valid(t)...), start: valid(t)},
		{name: "malformed first block before valid key", plan: append([]byte("-----BEGIN PRIVATE KEY-----\nnot-base64\n"), valid(t)...), start: valid(t)},
		{name: "trailing non-whitespace", plan: append(valid(t), []byte("not-a-key")...), start: valid(t)},
		{name: "pem header", plan: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER(t, executionSigningKey(t)), Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}}), start: valid(t)},
		{name: "two blocks", plan: append(valid(t), valid(t)...), start: valid(t)},
		{name: "encrypted type", plan: encrypted, start: valid(t)},
		{name: "encrypted pkcs8", plan: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encryptedPKCS8(t)}), start: valid(t)},
		{name: "sec1 type", plan: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecSEC1}), start: valid(t)},
		{name: "sec1 inside private key", plan: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecSEC1}), start: valid(t)},
		{name: "pkcs1 type", plan: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}), start: valid(t)},
		{name: "pkcs1 inside private key", plan: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}), start: valid(t)},
		{name: "openssh type", plan: pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: pkcs8DER(t, executionSigningKey(t))}), start: valid(t)},
		{name: "pkcs8 rsa", plan: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaPKCS8}), start: valid(t)},
		{name: "pkcs8 ecdsa", start: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecPKCS8}), plan: valid(t)},
		{name: "group readable", plan: valid(t), start: valid(t), protect: "start.key", mode: 0640},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newExecutionConfigFixture(t)
			writeFixtureFile(t, f.document.base, "plan.key", test.plan)
			writeFixtureFile(t, f.document.base, "start.key", test.start)
			if test.protect != "" {
				if err := os.Chmod(filepath.Join(f.document.base, test.protect), test.mode); err != nil {
					t.Fatal(err)
				}
			}
			f.document.Proto.ExecutionSigning = &configv1.ExecutionSigningConfig{PlanKeyFile: "plan.key", StartKeyFile: "start.key"}
			rejectExecutionSigning(t, f)
		})
	}
}

func executionSigningSchemaConfig() *configv1.ServerConfig {
	return &configv1.ServerConfig{
		DeploymentId: uuid.NewString(), PublicUrl: "https://localhost:7444", DevicePublicUrl: proto.String("https://localhost:7445"),
		AdminListener:  &configv1.ListenerConfig{Address: "127.0.0.1", Port: 7444},
		DeviceListener: &configv1.ListenerConfig{Address: "127.0.0.1", Port: 7445},
		Database:       &configv1.DatabaseConfig{UrlFile: "database-url", MaxConnections: 2},
		Tls:            &configv1.TLSConfig{CertificateFile: "server.crt", PrivateKeyFile: "server.key"},
		DeviceCa:       &configv1.DeviceCAConfig{CertificateFile: "device.crt", PrivateKeyFile: "device.key"},
		Authentication: &configv1.AuthenticationConfig{Primary: &configv1.AuthenticationConfig_Keycloak{Keycloak: &configv1.KeycloakDirectory{
			Issuer: "https://idp.example/realms/lindm", ClientId: "login", ClientSecretFile: "oidc-secret",
			DirectoryClientId: "directory", DirectoryClientSecretFile: "directory-secret",
		}}},
		ExecutionBootstrap: &configv1.ExecutionBootstrapConfig{RootFile: "execution-root.json", BootstrapFile: "bootstrap.dsse.json"},
		ExecutionSigning:   &configv1.ExecutionSigningConfig{PlanKeyFile: "plan.key", StartKeyFile: "start.key"},
	}
}

func validateExecutionSigningSchema(t *testing.T, cfg *configv1.ServerConfig) error {
	t.Helper()
	validator, err := protovalidate.New(protovalidate.WithMessages(cfg))
	if err != nil {
		t.Fatal(err)
	}
	return validator.Validate(cfg)
}

func resolveExecutionSigning(t *testing.T, f *executionConfigFixture) *Resources {
	t.Helper()
	resources, err := f.document.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resources.HTTPClient.CloseIdleConnections)
	return resources
}

func rejectExecutionSigning(t *testing.T, f *executionConfigFixture) {
	t.Helper()
	resources, err := f.document.Resolve()
	if err == nil {
		resources.HTTPClient.CloseIdleConnections()
		t.Fatal("accepted invalid execution signing")
	}
}

func configureExecutionSigning(t *testing.T, f *executionConfigFixture, plan, start ed25519.PrivateKey) {
	t.Helper()
	writeExecutionSigningKey(t, f.document.base, "plan.key", plan)
	writeExecutionSigningKey(t, f.document.base, "start.key", start)
	f.document.Proto.ExecutionSigning = &configv1.ExecutionSigningConfig{PlanKeyFile: "plan.key", StartKeyFile: "start.key"}
}

func assertSigningKey(t *testing.T, loaded ed25519.PrivateKey, id string, want ed25519.PrivateKey) {
	t.Helper()
	public := ed25519.PublicKey(want[ed25519.SeedSize:])
	got, err := trust.KeyID(public)
	if err != nil || got != id || !bytes.Equal(loaded, want) {
		t.Fatal("loaded execution signing key does not match its file")
	}
	message := []byte("domain-separated")
	if !ed25519.Verify(public, message, ed25519.Sign(loaded, message)) {
		t.Fatal("loaded execution signing key cannot sign")
	}
}

func executionSigningKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func writeExecutionSigningKey(t *testing.T, dir, name string, key ed25519.PrivateKey) {
	t.Helper()
	writeFixtureFile(t, dir, name, executionSigningPEM(t, key))
}

func executionSigningPEM(t *testing.T, key ed25519.PrivateKey) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER(t, key)})
}

func pkcs8DER(t *testing.T, key ed25519.PrivateKey) []byte {
	t.Helper()
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func executionFixturePrivateKey(t *testing.T, dir, name string) ed25519.PrivateKey {
	t.Helper()
	block, rest := pem.Decode(executionConfigFile(t, dir, name))
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("fixture private key is not one PKCS#8 block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("fixture private key is not Ed25519")
	}
	return key
}

func encryptedPKCS8(t *testing.T) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(struct {
		Algorithm struct {
			Algorithm asn1.ObjectIdentifier
		}
		Data []byte
	}{
		Algorithm: struct {
			Algorithm asn1.ObjectIdentifier
		}{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}},
		Data: []byte{1, 2, 3, 4},
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
