// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func deployTLSCertificatePair(t *testing.T, edCA, edLeaf bool) (*x509.Certificate, *x509.Certificate) {
	t.Helper()
	key := func(ed bool) crypto.Signer {
		if ed {
			_, signer, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return signer
		}
		signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return signer
	}
	caKey, leafKey := key(edCA), key(edLeaf)
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "installed transport CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "installed console"}, DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, leafKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return ca, leaf
}

func TestNativeGeneratedTLSRejectsEd25519BeforeBrowserQualification(t *testing.T) {
	for _, test := range []struct {
		name         string
		edCA, edLeaf bool
	}{{"browser-compatible", false, false}, {"old-generated-ed25519", true, true}, {"ed25519-issuer", true, false}, {"ed25519-leaf-spki", false, true}} {
		t.Run(test.name, func(t *testing.T) {
			ca, leaf := deployTLSCertificatePair(t, test.edCA, test.edLeaf)
			err := validateDeployTLS(ca, leaf, "https://localhost:18444")
			if (err != nil) != (test.edCA || test.edLeaf) {
				t.Fatalf("generated TLS algorithm admission: %v", err)
			}
			observed := deployCertificateEvidence(leaf)
			if len(observed.SPKISHA256) != 64 || len(observed.SHA256) != 64 || observed.SignatureAlgorithm != leaf.SignatureAlgorithm.String() || observed.PublicKeyAlgorithm != leaf.PublicKeyAlgorithm.String() {
				t.Fatalf("actual certificate algorithms not retained: %+v", observed)
			}
			if !test.edCA && !test.edLeaf && validateDeployTLS(ca, leaf, "https://wrong-host.invalid") == nil {
				t.Fatal("generated certificate bypassed hostname verification")
			}
		})
	}
}

func TestNativeBrowserTrustRetainsExactInstalledPublicCAAndRejectsCutoverReplacement(t *testing.T) {
	private, evidence := t.TempDir(), t.TempDir()
	request := prepareDeploySetupBrowser(VMDeploySetupOptions{EvidenceDirectory: evidence}, private)
	if _, err := os.Stat(request.CAFile); !os.IsNotExist(err) {
		t.Fatal("native browser preparation injected a laboratory trust fixture")
	}
	ca, _ := deployTLSCertificatePair(t, false, false)
	// Preserve the exact PEM bytes rather than re-encoding an equivalent root.
	installed := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), '\n')
	observed := &VMDeployTLSEvidence{Phase: "installed"}
	if _, err := retainDeployTLSCertificate(&request, observed, "console-ca.crt", installed, ""); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{request.CAFile, filepath.Join(evidence, "installed-console-ca.crt")} {
		data, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(data, installed) {
			t.Fatalf("private NSS trust did not retain installed public CA bytes: %v", err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("public trust evidence escaped private file custody: %v", err)
		}
	}
	other, _ := deployTLSCertificatePair(t, false, false)
	replacement := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Raw})
	if _, err := retainDeployTLSCertificate(&request, &VMDeployTLSEvidence{Phase: "restored"}, "console-ca.crt", replacement, observed.ConsoleCA.SHA256); err == nil {
		t.Fatal("fresh destination console CA silently replaced original browser trust")
	}
	retained, err := os.ReadFile(request.CAFile)
	if err != nil || !bytes.Equal(retained, installed) {
		t.Fatal("rejected cutover replaced browser trust")
	}
}

func TestNativeDeviceEd25519TrustRemainsSeparateFromBrowserNSS(t *testing.T) {
	ca, leaf := deployTLSCertificatePair(t, true, true)
	if err := validateDeployTLSChain(ca, leaf, "https://localhost:18445"); err != nil {
		t.Fatalf("valid Ed25519 device transport rejected: %v", err)
	}
	private, evidence := t.TempDir(), t.TempDir()
	request := prepareDeploySetupBrowser(VMDeploySetupOptions{EvidenceDirectory: evidence}, private)
	observed := &VMDeployTLSEvidence{Phase: "installed"}
	installed := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	if _, err := retainDeployTLSCertificate(&request, observed, "transport-ca.crt", installed, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(request.CAFile); !os.IsNotExist(err) {
		t.Fatal("device transport CA was imported as browser trust")
	}
	retained, err := os.ReadFile(filepath.Join(private, "transport-ca.crt"))
	if err != nil || !bytes.Equal(retained, installed) || observed.DeviceCA.PublicKeyAlgorithm != "Ed25519" || observed.DeviceCA.SignatureAlgorithm != "Ed25519" {
		t.Fatalf("authentic enrollment/recovery transport trust not retained: %v", err)
	}
	other, _ := deployTLSCertificatePair(t, true, true)
	replacement := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Raw})
	if _, err := retainDeployTLSCertificate(&request, &VMDeployTLSEvidence{Phase: "restored"}, "transport-ca.crt", replacement, observed.DeviceCA.SHA256); err == nil {
		t.Fatal("restore silently replaced enrolled devices' transport authority")
	}
}
