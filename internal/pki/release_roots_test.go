// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func releaseRootCertificate(t *testing.T, name string, constraints, ca, self bool) (*x509.Certificate, []byte) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: time.Unix(1, 0), NotAfter: time.Unix(2000000000, 0), BasicConstraintsValid: constraints, IsCA: ca}
	parent := template
	if !self {
		_, key, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		parent = &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "distinct issuer"}, BasicConstraintsValid: true, IsCA: true}
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, parent, public, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded})
}

func TestReleaseCASelectionNarrowsHostTrust(t *testing.T) {
	_, ca := releaseRootCertificate(t, "usable CA", true, true, true)
	_, explicitLeaf := releaseRootCertificate(t, "self-signed explicit CA:false", true, false, true)
	_, issuedLeaf := releaseRootCertificate(t, "issued leaf without constraints", false, false, false)
	legacy, legacyPEM := releaseRootCertificate(t, "legacy self-signed anchor", false, false, true)
	input := append(append(append(bytes.Clone(ca), explicitLeaf...), issuedLeaf...), legacyPEM...)
	selected, skipped, err := SelectReleaseCARoots(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) != 2 || skipped[0].Subject.CommonName != "self-signed explicit CA:false" || skipped[1].Subject.CommonName != "issued leaf without constraints" {
		t.Fatalf("skipped subjects: %v", skipped)
	}
	if !bytes.Equal(selected, append(bytes.Clone(ca), legacyPEM...)) {
		t.Fatal("host leaf trust was retained or usable roots were changed")
	}
	legacy.Signature[0] ^= 1
	if IsReleaseCAAnchor(legacy) {
		t.Fatal("unsigned legacy self-issuer accepted as an anchor")
	}
}

func TestReleaseCASelectionRequiresUsableAnchor(t *testing.T) {
	_, leaf := releaseRootCertificate(t, "explicit leaf", true, false, true)
	if selected, skipped, err := SelectReleaseCARoots(leaf); err == nil || len(selected) != 0 || len(skipped) != 1 {
		t.Fatalf("leaf-only input selected=%v skipped=%v error=%v", selected, skipped, err)
	}
	for _, input := range [][]byte{nil, []byte("not certificate PEM"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a root")})} {
		if _, _, err := SelectReleaseCARoots(input); err == nil {
			t.Fatal("invalid or nonpublic trust source accepted")
		}
	}
}
