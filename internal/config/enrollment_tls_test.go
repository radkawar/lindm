// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"testing"
)

func TestEnrollmentTLSUsesOnlyVerifiedNativeDownloadIssuer(t *testing.T) {
	for _, source := range []string{"bootstrap", "trusted file", "full chain", "missing", "unrelated device CA", "wrong administrative hostname", "signed wrong console pin", "signed missing console pin", "signed transport-only pin"} {
		t.Run(source, func(t *testing.T) {
			fixture := newExecutionConfigFixture(t)
			document := fixture.document
			certificate, err := keyPair(document.base, "admin.crt", "admin.key")
			if err != nil {
				t.Fatal(err)
			}
			consoleCA, err := keyPair(document.base, "console-ca.crt", "console-ca.key")
			if err != nil {
				t.Fatal(err)
			}
			resources := &Resources{AdminServerCertificate: certificate}
			switch source {
			case "bootstrap":
				resources.ExecutionBootstrap = &ExecutionBootstrap{ConsoleCAPEM: fixture.bundle.GetConsoleCaPem()}
			case "trusted file":
				document.Proto.TrustedCaFile = "console-ca.crt"
			case "full chain":
				resources.AdminServerCertificate.Certificate = append(resources.AdminServerCertificate.Certificate, consoleCA.Leaf.Raw)
			case "unrelated device CA":
				document.Proto.TrustedCaFile = "device.crt"
			case "wrong administrative hostname":
				document.Proto.TrustedCaFile = "console-ca.crt"
				document.Proto.PublicUrl = "https://another-console.example:7444"
			case "signed wrong console pin", "signed missing console pin", "signed transport-only pin":
				// Even an otherwise valid local/download trust source cannot
				// replace the independently signed console-origin pin.
				document.Proto.TrustedCaFile = "console-ca.crt"
				resources.AdminCACertificate = consoleCA.Leaf
				resources.AdminServerCertificate.Certificate = append(resources.AdminServerCertificate.Certificate, consoleCA.Leaf.Raw)
				resources.ExecutionBootstrap = &ExecutionBootstrap{TransportCAPEM: fixture.bundle.GetConsoleCaPem()}
				if source == "signed wrong console pin" {
					resources.ExecutionBootstrap.ConsoleCAPEM = fixture.bundle.GetTransportCaPem()
				}
			}
			if err := document.resolveEnrollmentTLS(resources); err != nil {
				t.Fatal(err)
			}
			ready := source == "bootstrap" || source == "trusted file" || source == "full chain"
			if resources.EnrollmentTLSUnavailable == ready {
				t.Fatalf("HTTPS trust availability mismatch: %s", source)
			}
			if !ready {
				if resources.EnrollmentTLSCAPEM != "" || resources.EnrollmentTLSCASHA256 != "" {
					t.Fatal("unverified CA exposed as installation trust")
				}
				return
			}
			block, rest := pem.Decode([]byte(resources.EnrollmentTLSCAPEM))
			if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
				t.Fatal("expected exactly one pinned PEM CA certificate")
			}
			digest := sha256.Sum256(consoleCA.Leaf.Raw)
			if resources.EnrollmentTLSCASHA256 != hex.EncodeToString(digest[:]) {
				t.Fatal("CA fingerprint does not authenticate certificate DER")
			}
			if string(block.Bytes) != string(consoleCA.Leaf.Raw) {
				t.Fatal("selected unrelated certificate material")
			}
		})
	}
}

func TestResolvedSplitBootstrapPinsNativeDownloadCA(t *testing.T) {
	fixture := newExecutionConfigFixture(t)
	resources, err := fixture.document.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	defer resources.HTTPClient.CloseIdleConnections()
	if resources.EnrollmentTLSUnavailable || resources.EnrollmentTLSCAPEM == "" || resources.EnrollmentTLSCASHA256 == "" {
		t.Fatal("authenticated bootstrap console trust was not projected for bare-machine enrollment")
	}
}
