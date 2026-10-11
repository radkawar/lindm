package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestEnrollmentTLSUsesOnlyVerifiedAdministrativeIssuer(t *testing.T) {
	for _, source := range []string{"bootstrap", "trusted file", "full chain", "missing", "unrelated device CA", "wrong device hostname"} {
		t.Run(source, func(t *testing.T) {
			fixture := newExecutionConfigFixture(t)
			document := fixture.document
			certificate, err := keyPair(document.base, "server.crt", "server.key")
			if err != nil {
				t.Fatal(err)
			}
			resources := &Resources{ServerCertificate: certificate}
			switch source {
			case "bootstrap":
				resources.ExecutionBootstrap = &ExecutionBootstrap{TransportCAPEM: executionConfigFile(t, document.base, "transport.crt")}
			case "trusted file":
				document.Proto.TrustedCaFile = "transport.crt"
			case "full chain":
				resources.ServerCertificate.Certificate = append(resources.ServerCertificate.Certificate, fixture.transport.Leaf.Raw)
			case "unrelated device CA":
				document.Proto.TrustedCaFile = "device.crt"
			case "wrong device hostname":
				document.Proto.TrustedCaFile = "transport.crt"
				document.Proto.DevicePublicUrl = proto.String("https://another-device.example:7445")
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
			digest := sha256.Sum256(fixture.transport.Leaf.Raw)
			if resources.EnrollmentTLSCASHA256 != hex.EncodeToString(digest[:]) {
				t.Fatal("CA fingerprint does not authenticate certificate DER")
			}
			if string(block.Bytes) != string(fixture.transport.Leaf.Raw) {
				t.Fatal("selected unrelated certificate material")
			}
		})
	}
}

func TestResolvedBootstrapPinsAdministrativeCA(t *testing.T) {
	fixture := newExecutionConfigFixture(t)
	resources, err := fixture.document.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	defer resources.HTTPClient.CloseIdleConnections()
	if resources.EnrollmentTLSUnavailable || resources.EnrollmentTLSCAPEM == "" || resources.EnrollmentTLSCASHA256 == "" {
		t.Fatal("authenticated bootstrap transport trust was not projected for bare-machine enrollment")
	}
}
