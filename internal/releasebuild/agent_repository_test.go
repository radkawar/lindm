//go:build linux

package releasebuild

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	releasev1 "lindm/gen/lindm/release/v1"
	"lindm/internal/packaging"
	"lindm/internal/platform"
)

func TestNativeMatrixCoversEverySupportedRegistryArchitecture(t *testing.T) {
	for _, release := range platform.Releases() {
		if release.Tier != platform.Tier1 && release.Tier != platform.Tier2 {
			continue
		}
		for _, architecture := range release.Architectures {
			goarch := map[string]string{"x86_64": "amd64", "aarch64": "arm64"}[architecture]
			if goarch == "" {
				t.Fatalf("supported architecture %s has no release target", architecture)
			}
			format := release.Native().Packages.Backend.PackageFormat()
			for _, product := range []string{"lindm-agent", "lindmd"} {
				if format != "" && !slices.Contains(nativeFormats(goarch, product), format) {
					t.Fatalf("%s/%s/%s missing native format %s", release.Key, architecture, product, format)
				}
			}
		}
	}
	if slices.Contains(nativeFormats("arm64", "lindm-agent"), string(packaging.FormatArch)) {
		t.Fatal("claimed unsupported Arch Linux ARM coverage")
	}
}

func TestDevelopmentRepositoryRefusesProductionFallback(t *testing.T) {
	if _, err := BuildDevelopmentAgentRepository(t.Context(), Request{}); err == nil {
		t.Fatal("accepted missing explicit development custody")
	}
	if _, err := BuildDevelopmentAgentRepository(t.Context(), Request{PackageSigner: packaging.SigningKey{Custody: packaging.CustodyProduction}, AttestationSigner: AttestationKey{Custody: "production"}}); err == nil {
		t.Fatal("used fixture helper with production signing custody")
	}
}

// This is a DSSE/export boundary fixture, not a native packaging or build proof.
func TestCanonicalExportRequiresUnsignedAgreementAndSnapshotsObservations(t *testing.T) {
	signer, key := testSigner(t)
	input := filepath.Join(t.TempDir(), "agent.deb")
	if err := writeNew(input, []byte("attestation serialization fixture"), 0644); err != nil {
		t.Fatal(err)
	}
	sum, size, err := digestFile(input)
	if err != nil {
		t.Fatal(err)
	}
	public := filepath.Join(t.TempDir(), "package.asc")
	if err := writeNew(public, []byte("public key copying fixture, not native signing authority"), 0644); err != nil {
		t.Fatal(err)
	}
	artifact := &releasev1.ReleaseArtifact{Path: "agent.deb", Product: "lindm-agent", Architecture: "amd64", Format: "deb", Sha256: sum, Size: size, UnsignedSha256: sum}
	observation := func() *releasev1.BuildObservation {
		return &releasev1.BuildObservation{SourceSha256: sum, StartedAt: "first observed start", FinishedAt: "observed finish", UnsignedSha256: map[string]string{artifact.Path: sum}}
	}
	first := &buildOutput{observation: observation(), artifacts: []builtArtifact{{artifact: artifact, path: input, sbom: []byte(`{"components":[]}`)}}, packagePublicKey: public}
	second := &buildOutput{observation: observation(), artifacts: []builtArtifact{{artifact: &releasev1.ReleaseArtifact{Path: artifact.Path, UnsignedSha256: sum, Sha256: strings.Repeat("f", 64)}}}}
	request := Request{Version: "1.2.3", Revision: "signature-boundary-fixture", SourceDateEpoch: 1760000000, AttestationSigner: key}
	second.observation.UnsignedSha256[artifact.Path] = strings.Repeat("0", 64)
	if _, err := exportRelease(t.Context(), t.TempDir(), request, signer, sum, first, second, ""); err == nil {
		t.Fatal("published signed canonical bytes before unsigned builds agreed")
	}
	second.observation.UnsignedSha256[artifact.Path] = sum
	output := t.TempDir()
	manifest, err := exportRelease(t.Context(), output, request, signer, sum, first, second, "")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Artifacts[0].Sha256 != sum || manifest.Artifacts[0].SecondUnsignedSha256 != sum {
		t.Fatal("export did not select canonical first signed bytes and real second unsigned digest")
	}
	first.observation.UnsignedSha256["server.deb"] = strings.Repeat("1", 64)
	if len(manifest.Builds[0].UnsignedSha256) != 1 || artifact.SecondUnsignedSha256 != "" {
		t.Fatal("later server builds mutated the signed agent subset observations/artifact")
	}
	if _, err := Verify(t.Context(), output, filepath.Join(output, "attestation.pub"), key.KeyID); err != nil {
		t.Fatal(err)
	}
}

func TestOCIEmbedsIdenticalCanonicalBundleAndRejectsSubstitution(t *testing.T) {
	directory := t.TempDir()
	binary := filepath.Join(directory, "binary")
	if err := writeNew(binary, []byte("OCI serialization fixture, not executable"), 0755); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(directory, "agent-repository")
	if err := os.MkdirAll(filepath.Join(bundle, "repo", "apt"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"release.json": "signed manifest serialization fixture", "repo/apt/agent.deb": "canonical signed agent bytes"} {
		if err := writeNew(filepath.Join(bundle, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	ca, _, _ := testCABundle(t)
	pin, _, err := digestFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	var digest string
	for _, name := range []string{"first.oci.tar", "second.oci.tar"} {
		path := filepath.Join(directory, name)
		if err := buildOCI(binary, ca, path, "lindmd", "amd64", 1760000000, bundle); err != nil {
			t.Fatal(err)
		}
		got, _, err := digestFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if digest != "" && got != digest {
			t.Fatal("identical canonical bundle produced different OCI archives")
		}
		digest = got
		if err := verifyOCIImage(path, "lindmd", "amd64", pin, bundle); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bundle, "repo", "apt", "agent.deb"), []byte("substituted package"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := verifyOCIImage(filepath.Join(directory, "first.oci.tar"), "lindmd", "amd64", pin, bundle); err == nil {
		t.Fatal("accepted OCI payload different from canonical signed bundle")
	}
}

func TestCompleteRepositoryAdmissionRejectsUnattestedPackagesAndKeySubstitution(t *testing.T) {
	for _, attack := range []string{"none", "package", "extra", "missing", "key"} {
		t.Run(attack, func(t *testing.T) {
			directory, public, pin := releaseFixture(t)
			manifest, err := Verify(t.Context(), directory, public, pin)
			if err != nil {
				t.Fatal(err)
			}
			// Signature/digest boundary only: native repository signature
			// authentication is covered separately by packaging/native consumers.
			key := []byte("repository public-key comparison fixture")
			if err := writeNew(filepath.Join(directory, "package-signing.asc"), key, 0644); err != nil {
				t.Fatal(err)
			}
			for _, format := range []string{"apt", "rpm", "arch"} {
				root := filepath.Join(directory, "repo", format)
				if err := os.MkdirAll(root, 0700); err != nil {
					t.Fatal(err)
				}
				if err := writeNew(filepath.Join(root, "lindm-package-signing.asc"), key, 0644); err != nil {
					t.Fatal(err)
				}
			}
			artifact := manifest.Artifacts[0]
			packaged := filepath.Join(directory, "repo", "apt", artifact.Path)
			if err := copyNew(filepath.Join(directory, artifact.Path), packaged, 0644); err != nil {
				t.Fatal(err)
			}
			switch attack {
			case "package":
				err = os.WriteFile(packaged, []byte("modified"), 0644)
			case "extra":
				err = writeNew(filepath.Join(directory, "repo", "rpm", "unattested.rpm"), []byte("extra"), 0644)
			case "missing":
				err = os.Remove(packaged)
			case "key":
				err = os.WriteFile(filepath.Join(directory, "repo", "apt", "lindm-package-signing.asc"), []byte("different authority"), 0644)
			}
			if err != nil {
				t.Fatal(err)
			}
			err = verifyRepositoryPayloads(directory, manifest)
			if attack == "none" && err != nil {
				t.Fatal(err)
			}
			if attack != "none" && err == nil {
				t.Fatal("accepted repository substitution or incomplete signed subset")
			}
		})
	}
}

func TestCanonicalBundleNormalizesWritableAncillaryMetadataWithoutChangingBytes(t *testing.T) {
	bundle := t.TempDir()
	metadata := filepath.Join(bundle, "repo", "rpm", "repodata")
	if err := os.MkdirAll(metadata, 0775); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(metadata, 0775); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(metadata, "repomd.xml")
	if err := writeNew(path, []byte("signed metadata permission boundary"), 0664); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0664); err != nil {
		t.Fatal(err)
	}
	before, _, err := digestFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := normalizeAgentRepository(bundle); err != nil {
		t.Fatal(err)
	}
	after, _, err := digestFile(path)
	if err != nil || after != before {
		t.Fatalf("normalization changed signed bytes: %v", err)
	}
	for name, mode := range map[string]os.FileMode{bundle: 0755, metadata: 0755, path: 0444} {
		info, err := os.Lstat(name)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("unprotected bundle member %s: %v", name, err)
		}
	}
}
