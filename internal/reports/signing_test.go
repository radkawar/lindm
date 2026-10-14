// SPDX-License-Identifier: Apache-2.0

package reports

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"google.golang.org/protobuf/proto"

	integrationsv1 "lindm/gen/lindm/integrations/v1"
)

func signingService(t *testing.T, signer crypto.Signer) *Service {
	t.Helper()
	algorithm, err := signingAlgorithm(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	return &Service{signer: signer, algorithm: algorithm, publicKey: public, fingerprint: sha256.Sum256(public)}
}

func TestSignedReportsAlgorithmsAndArchivePin(t *testing.T) {
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []crypto.Signer{ed, ec, rsaKey} {
		s := signingService(t, key)
		t.Run(s.algorithm, func(t *testing.T) {
			content := []byte("[{\"device_id\":\"example\"}]\n")
			digest := sha256.Sum256(content)
			manifest := &integrationsv1.ReportManifest{ArtifactId: "example", Kind: integrationsv1.ReportKind_REPORT_KIND_INVENTORY,
				Format: integrationsv1.ReportFormat_REPORT_FORMAT_JSON, ByteCount: uint64(len(content)), RowCount: 1, ContentSha256: digest[:]}
			encoded, err := s.signManifest(manifest)
			if err != nil {
				t.Fatal(err)
			}
			envelope := &integrationsv1.ReportSignedManifest{}
			if err := proto.Unmarshal(encoded, envelope); err != nil {
				t.Fatal(err)
			}
			// Independent verifier: exact signed protobuf bytes, standard crypto,
			// and an externally retained SPKI, not a service verification callback.
			message := append([]byte("lindm-report-manifest-v1\x00"), envelope.GetManifest()...)
			hash := sha256.Sum256(message)
			switch public := key.Public().(type) {
			case ed25519.PublicKey:
				if !ed25519.Verify(public, message, envelope.GetSignature()) {
					t.Fatal("external Ed25519 verifier rejected manifest")
				}
			case *ecdsa.PublicKey:
				if !ecdsa.VerifyASN1(public, hash[:], envelope.GetSignature()) {
					t.Fatal("external ECDSA verifier rejected manifest")
				}
			case *rsa.PublicKey:
				if err := rsa.VerifyPSS(public, crypto.SHA256, hash[:], envelope.GetSignature(), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := VerifyReportArtifact(bytes.NewReader(content), envelope, s.fingerprint[:], nil); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyReportArtifact(bytes.NewReader(append(content, 'x')), envelope, s.fingerprint[:], nil); err == nil {
				t.Fatal("accepted appended content")
			}
			if _, err := VerifyReportArtifact(bytes.NewReader(content[:len(content)-1]), envelope, s.fingerprint[:], nil); err == nil {
				t.Fatal("accepted truncated content")
			}
			wrongPin := sha256.Sum256([]byte("unapproved rotation"))
			if _, err := VerifyReportArtifact(bytes.NewReader(content), envelope, wrongPin[:], nil); err == nil {
				t.Fatal("trusted embedded key without external pin")
			}
			altered := proto.CloneOf(envelope)
			altered.Manifest = append(altered.Manifest, 0)
			if _, err := VerifyReportArtifact(bytes.NewReader(content), altered, s.fingerprint[:], nil); err == nil {
				t.Fatal("accepted altered manifest")
			}
		})
	}
}
