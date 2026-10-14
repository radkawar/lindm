// SPDX-License-Identifier: Apache-2.0
//go:build linux

package releasebuild

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/sigstore/sigstore/pkg/signature"
)

func memoryAttestationFixture(t *testing.T) (AttestationKey, ed25519.PublicKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(der)
	id, _, err := keyID(public)
	if err != nil {
		t.Fatal(err)
	}
	path, pin := writeInventory(t, inventoryFixture(t, public, ""))
	key := AttestationKey{PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), KeyID: id, Custody: "production", Purpose: "production-release-attestation", TrustInventory: path, TrustInventorySHA256: pin}
	t.Cleanup(func() { clear(key.PrivateKeyPEM) })
	return key, public
}

func TestMemoryProductionAttestationSignsWithPinnedAuthority(t *testing.T) {
	key, public := memoryAttestationFixture(t)
	original := bytes.Clone(key.PrivateKeyPEM)
	defer clear(original)
	key.KeyID = " " + strings.ToUpper(key.KeyID) + " "
	key.TrustInventorySHA256 = " " + strings.ToUpper(key.TrustInventorySHA256) + " "
	signer, err := loadSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.close()
	payload := []byte(`{"release":"1.2.3","custody":"production"}`)
	envelope, err := signer.sign(payload, manifestType)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := signature.LoadVerifier(public, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifyEnvelope(envelope, manifestType, verifier)
	if err != nil || !bytes.Equal(verified, payload) {
		t.Fatalf("memory production signature: %v", err)
	}
	private := signer.private
	signer.close()
	if !bytes.Equal(private, make([]byte, len(private))) || !bytes.Equal(key.PrivateKeyPEM, original) {
		t.Fatal("signer did not erase its decoded key or modified caller-owned custody input")
	}
}

func TestMemoryAttestationPreservesPurposePinsAndDomainExclusions(t *testing.T) {
	key, public := memoryAttestationFixture(t)
	for _, test := range []struct {
		name   string
		change func(*AttestationKey)
	}{
		{"absent-purpose", func(k *AttestationKey) { k.Purpose = "" }},
		{"development-purpose", func(k *AttestationKey) { k.Purpose = "development-release-attestation" }},
		{"other-domain-purpose", func(k *AttestationKey) { k.Purpose = "production-offline-bundle" }},
		{"development-custody", func(k *AttestationKey) { k.Custody = "development" }},
		{"path-and-memory", func(k *AttestationKey) { k.Path = "/absent/attestation.pem" }},
		{"neither-source", func(k *AttestationKey) { k.PrivateKeyPEM = nil }},
		{"wrong-public-pin", func(k *AttestationKey) { k.KeyID = strings.Repeat("0", 64) }},
		{"absent-inventory", func(k *AttestationKey) { k.TrustInventory, k.TrustInventorySHA256 = "", "" }},
		{"substituted-inventory", func(k *AttestationKey) { k.TrustInventorySHA256 = strings.Repeat("0", 64) }},
		{"malformed-key", func(k *AttestationKey) { k.PrivateKeyPEM = []byte("not a PKCS8 key") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := key
			test.change(&changed)
			if signer, err := loadSigner(changed); err == nil {
				signer.close()
				t.Fatal("accepted invalid memory production signing authority")
			}
		})
	}
	for _, domain := range []string{"execution", "tls", "tuf", "delegated", "retired-delegated"} {
		t.Run(domain, func(t *testing.T) {
			changed := key
			changed.TrustInventory, changed.TrustInventorySHA256 = writeInventory(t, inventoryFixture(t, public, domain))
			if signer, err := loadSigner(changed); err == nil {
				signer.close()
				t.Fatal("accepted cross-domain memory signing key")
			}
		})
	}
}
