// SPDX-License-Identifier: Apache-2.0

//go:build linux

package server

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/sigstore/pkg/signature"
	sigstoredsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	"google.golang.org/protobuf/encoding/protojson"

	releasev1 "lindm/gen/lindm/release/v1"
)

// The fixture tests signature admission and readiness, not native transactions
// or release reproducibility. The VM console enrollment lane supplies that proof.
func bundledNativeFixture(t *testing.T, differingRelease bool) *nativeFixture {
	t.Helper()
	f := newNativeFixture(t)
	// testing.TempDir's numbered child uses 0777 minus the process umask.
	// Model the protected installed bundle rather than an ambient test directory.
	if err := os.Chmod(f.directory, 0700); err != nil {
		t.Fatal(err)
	}
	name := f.apt(t, "amd64")
	payload, err := os.ReadFile(filepath.Join(f.directory, "repo", "apt", name))
	if err != nil {
		t.Fatal(err)
	}
	if differingRelease {
		payload = []byte("a different authenticated agent release")
	}
	write := func(name string, body []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(f.directory, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	write("attestation.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	nativePublic, err := os.ReadFile(filepath.Join(f.directory, "repo", "apt", nativePublicKey))
	if err != nil {
		t.Fatal(err)
	}
	write("package-signing.asc", nativePublic)
	signer, err := signature.LoadSignerVerifier(private, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	sign := func(body []byte, kind string) []byte {
		t.Helper()
		envelope, err := sigstoredsse.WrapSignerVerifier(signer, kind).SignMessage(bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		return envelope
	}
	name = filepath.Base(name)
	write(name, payload)
	digest := nativeTestDigest(payload)
	artifact := &releasev1.ReleaseArtifact{Path: name, Product: "lindm-agent", Architecture: "amd64", Format: "deb", Sha256: digest, Size: int64(len(payload)), UnsignedSha256: digest, SecondUnsignedSha256: digest, SbomPath: name + ".sbom", ProvenancePath: name + ".provenance", SignaturePath: name + ".signature"}
	for _, item := range []struct{ name, kind string }{{artifact.SbomPath, "https://cyclonedx.org/bom"}, {artifact.ProvenancePath, "https://slsa.dev/provenance/v1"}, {artifact.SignaturePath, "https://lindm.invalid/release/artifact/v1"}} {
		statement, err := json.Marshal(map[string]any{"_type": "https://in-toto.io/Statement/v1", "subject": []any{map[string]any{"name": name, "digest": map[string]string{"sha256": digest}}}, "predicateType": item.kind, "predicate": map[string]string{"test": "signature admission only"}})
		if err != nil {
			t.Fatal(err)
		}
		write(item.name, sign(statement, "application/vnd.in-toto+json"))
	}
	observation := &releasev1.BuildObservation{SourceSha256: digest, StartedAt: "2026-10-13T00:00:00Z", FinishedAt: "2026-10-13T00:00:01Z", UnsignedSha256: map[string]string{name: digest}}
	licenses := make(map[string]string, 3)
	for _, document := range []string{"LICENSE", "NOTICE", "THIRD-PARTY-LICENSES"} {
		body := []byte("Signature-boundary fixture document: " + document + "\n")
		write(document, body)
		licenses[document] = nativeTestDigest(body)
	}
	manifest := &releasev1.ReleaseManifest{Version: "1.0.0", Revision: "signature-fixture", SourceSha256: digest, SourceDateEpoch: 1760000000, Artifacts: []*releasev1.ReleaseArtifact{artifact}, AttestationKeyId: nativeTestDigest(der), Custody: "development", Builds: []*releasev1.BuildObservation{observation, observation}, LicenseSha256: licenses}
	body, err := protojson.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	write("release.json", body)
	write("release.json.dsse", sign(body, "application/vnd.lindm.release.v1+json"))
	return f
}

func TestInstalledBundleProvidesReadyEnrollmentWithoutRepositoryConfig(t *testing.T) {
	f := bundledNativeFixture(t, false)
	resources := f.resources()
	resources.Proto.ReleaseRepository = nil
	resources.ReleaseRepositoryDirectory = ""
	native := loadNativeBundle(t.Context(), f.directory)
	if native.apt.err != nil {
		t.Fatal(native.apt.err)
	}
	instructions := enrollmentInstructions(resources, native)
	if !instructions.GetReadiness().GetReady() || instructions.GetAptRepository().GetSigningKeyFingerprint() != f.fingerprint {
		t.Fatalf("readiness or signer: %v", instructions.GetReadiness())
	}
	for _, platform := range instructions.GetPlatforms() {
		if platform.GetId() != "ubuntu-24.04" {
			continue
		}
		if !platform.GetReadiness().GetReady() || len(platform.GetAgentPackages()) != 1 || platform.GetAgentPackages()[0].GetVersion() != "1.0.0" {
			t.Fatalf("Ubuntu package availability: %v", platform)
		}
		return
	}
	t.Fatal("Ubuntu 24.04 missing from readiness")
}

func TestInstalledBundleRefusesValidNativePackageOutsideRelease(t *testing.T) {
	f := bundledNativeFixture(t, true)
	native := loadNativeBundle(t.Context(), f.directory)
	if native.apt.err == nil || !strings.Contains(native.apt.err.Error(), "release attestation") {
		t.Fatalf("accepted package outside authenticated release: %v", native.apt.err)
	}
}

func TestInstalledBundleRefusesTamperedReleaseAndUnsafeFiles(t *testing.T) {
	for _, attack := range []string{"release", "writable", "symlink"} {
		t.Run(attack, func(t *testing.T) {
			f := bundledNativeFixture(t, false)
			var err error
			switch attack {
			case "release":
				err = os.WriteFile(filepath.Join(f.directory, "release.json"), []byte("tampered"), 0600)
			case "writable":
				err = os.Chmod(filepath.Join(f.directory, "attestation.pub"), 0666)
			case "symlink":
				err = os.Symlink("attestation.pub", filepath.Join(f.directory, "untrusted-link"))
			}
			if err != nil {
				t.Fatal(err)
			}
			native := loadNativeBundle(t.Context(), f.directory)
			if native.apt.err == nil || native.rpm.err == nil || native.arch.err == nil {
				t.Fatal("unsafe bundle supplied installation instructions")
			}
		})
	}
}
