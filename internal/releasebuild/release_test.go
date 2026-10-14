// SPDX-License-Identifier: Apache-2.0

//go:build linux

package releasebuild

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	releasev1 "lindm/gen/lindm/release/v1"
)

func testSigner(t *testing.T) (*releaseSigner, AttestationKey) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "keys")
	id, err := GenerateDevelopmentKey(directory)
	if err != nil {
		t.Fatal(err)
	}
	key := AttestationKey{Path: filepath.Join(directory, "attestation.pem"), KeyID: id, Custody: "development"}
	signer, err := loadSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer, key
}

func TestSigningCustodyRejectsWrongPurposeIdentityAndAccess(t *testing.T) {
	_, key := testSigner(t)
	for _, changed := range []AttestationKey{{Path: key.Path, KeyID: key.KeyID, Custody: "production"}, {Path: key.Path, KeyID: strings.Repeat("0", 64), Custody: key.Custody}} {
		if _, err := loadSigner(changed); err == nil {
			t.Fatal("accepted wrong custody or identity")
		}
	}
	if err := os.Chmod(key.Path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSigner(key); err == nil {
		t.Fatal("accepted world-readable release key")
	}
	if err := os.Chmod(key.Path, 0600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(filepath.Dir(key.Path), "linked.pem")
	if err := os.Symlink(key.Path, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtected(linked, 16384); err == nil {
		t.Fatal("accepted linked release key")
	}
}

func releaseFixture(t *testing.T) (string, string, string) {
	t.Helper()
	signer, key := testSigner(t)
	directory := t.TempDir()
	name := "lindm-agent_1.2.3_amd64.deb"
	if err := writeNew(filepath.Join(directory, name), []byte("bounded artifact signing test input"), 0600); err != nil {
		t.Fatal(err)
	}
	sum, size, err := digestFile(filepath.Join(directory, name))
	if err != nil {
		t.Fatal(err)
	}
	artifact := &releasev1.ReleaseArtifact{Path: name, Product: "lindm-agent", Architecture: "amd64", Format: "deb", Sha256: sum, Size: size, UnsignedSha256: sum, SecondUnsignedSha256: sum, SbomPath: name + ".sbom", ProvenancePath: name + ".provenance", SignaturePath: name + ".signature"}
	for _, item := range []struct{ path, kind string }{{artifact.SbomPath, "https://cyclonedx.org/bom"}, {artifact.ProvenancePath, "https://slsa.dev/provenance/v1"}, {artifact.SignaturePath, "https://lindm.invalid/release/artifact/v1"}} {
		encoded, err := signer.statement(artifact, item.kind, map[string]string{"test": "signature boundary only"})
		if err != nil {
			t.Fatal(err)
		}
		if err := writeNew(filepath.Join(directory, item.path), encoded, 0600); err != nil {
			t.Fatal(err)
		}
	}
	observation := &releasev1.BuildObservation{SourceSha256: sum, StartedAt: "2026-10-10T00:00:00Z", FinishedAt: "2026-10-10T00:00:01Z", UnsignedSha256: map[string]string{name: sum}}
	manifest := &releasev1.ReleaseManifest{Version: "1.2.3", Revision: "fixture", SourceSha256: sum, SourceDateEpoch: 1760000000, Artifacts: []*releasev1.ReleaseArtifact{artifact}, AttestationKeyId: key.KeyID, Custody: "development", Builds: []*releasev1.BuildObservation{observation, observation}}
	payload, err := protojson.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeNew(filepath.Join(directory, "release.json"), payload, 0600); err != nil {
		t.Fatal(err)
	}
	envelope, err := signer.sign(payload, manifestType)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeNew(filepath.Join(directory, "release.json.dsse"), envelope, 0600); err != nil {
		t.Fatal(err)
	}
	return directory, filepath.Join(filepath.Dir(key.Path), "attestation.pub"), key.KeyID
}

func TestExportVerificationRejectsTamperWrongKeyAndSwappedStatements(t *testing.T) {
	for _, attack := range []string{"artifact", "manifest", "sbom", "wrong-key", "wrong-domain", "linked-artifact"} {
		t.Run(attack, func(t *testing.T) {
			directory, public, id := releaseFixture(t)
			manifest, err := Verify(t.Context(), directory, public, id)
			if err != nil {
				t.Fatal(err)
			}
			artifact := manifest.Artifacts[0]
			switch attack {
			case "artifact":
				err = os.WriteFile(filepath.Join(directory, artifact.Path), []byte("tampered"), 0600)
			case "manifest":
				err = os.WriteFile(filepath.Join(directory, "release.json"), []byte("{}"), 0600)
			case "sbom":
				var data []byte
				data, err = os.ReadFile(filepath.Join(directory, artifact.ProvenancePath))
				if err == nil {
					err = os.WriteFile(filepath.Join(directory, artifact.SbomPath), data, 0600)
				}
			case "wrong-key":
				id = strings.Repeat("0", 64)
			case "wrong-domain":
				var data []byte
				data, err = os.ReadFile(filepath.Join(directory, "release.json.dsse"))
				if err == nil {
					data = bytes.Replace(data, []byte(manifestType), []byte(statementType), 1)
					err = os.WriteFile(filepath.Join(directory, "release.json.dsse"), data, 0600)
				}
			case "linked-artifact":
				path := filepath.Join(directory, artifact.Path)
				var data []byte
				data, err = os.ReadFile(path)
				if err == nil {
					other := filepath.Join(t.TempDir(), "artifact")
					err = os.WriteFile(other, data, 0600)
					if err == nil {
						err = os.Remove(path)
					}
					if err == nil {
						err = os.Symlink(other, path)
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(t.Context(), directory, public, id); err == nil {
				t.Fatal("accepted modified export")
			}
		})
	}
}

func TestIndependentSourceCopiesAndPayloadComparison(t *testing.T) {
	source := t.TempDir()
	if err := writeNew(filepath.Join(source, "source.go"), []byte("package sample\n"), 0644); err != nil {
		t.Fatal(err)
	}
	first, second := filepath.Join(t.TempDir(), "first"), filepath.Join(t.TempDir(), "second")
	for _, path := range []string{first, second} {
		if err := copySource(source, path); err != nil {
			t.Fatal(err)
		}
	}
	digest, err := treeDigest(first)
	if err != nil {
		t.Fatal(err)
	}
	other, err := treeDigest(second)
	if err != nil || digest != other {
		t.Fatalf("copies differ: %v", err)
	}
	if err := os.Chmod(filepath.Join(second, "source.go"), 0755); err != nil {
		t.Fatal(err)
	}
	other, err = treeDigest(second)
	if err != nil || digest == other {
		t.Fatal("source digest ignored executable permissions")
	}
	artifact := &releasev1.ReleaseArtifact{Path: "a.deb", UnsignedSha256: digest}
	left := &buildOutput{observation: &releasev1.BuildObservation{SourceSha256: digest}, artifacts: []builtArtifact{{artifact: artifact}}}
	right := &buildOutput{observation: &releasev1.BuildObservation{SourceSha256: digest, UnsignedSha256: map[string]string{"a.deb": digest}}, artifacts: []builtArtifact{{artifact: artifact}}}
	if err := compareBuilds(left, right); err != nil {
		t.Fatal(err)
	}
	right.observation.UnsignedSha256["a.deb"] = other
	if err := compareBuilds(left, right); err == nil {
		t.Fatal("accepted nonreproducible payload")
	}
}

func TestOCIArchiveIsDeterministicAndBindsBinary(t *testing.T) {
	directory := t.TempDir()
	binary := filepath.Join(directory, "binary")
	payload := []byte("OCI serialization regression input, not an executable")
	if err := writeNew(binary, payload, 0755); err != nil {
		t.Fatal(err)
	}
	caBundle, _, _ := testCABundle(t)
	first, second := filepath.Join(directory, "first.tar"), filepath.Join(directory, "second.tar")
	for _, path := range []string{first, second} {
		if err := buildOCI(binary, caBundle, path, "lindmd", "arm64", 1760000000, filepath.Join("..", "packaging", "assets")); err != nil {
			t.Fatal(err)
		}
	}
	a, _, err := digestFile(first)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := digestFile(second)
	if err != nil || a != b {
		t.Fatalf("OCI bytes differ: %v", err)
	}
	f, err := os.Open(first)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}()
	reader := tar.NewReader(f)
	found := false
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(header.Name, "blobs/") && !json.Valid(data) {
			layer := tar.NewReader(bytes.NewReader(data))
			entry, err := layer.Next()
			if err != nil {
				t.Fatal(err)
			}
			content, err := io.ReadAll(layer)
			if err != nil {
				t.Fatal(err)
			}
			if entry.Name != "usr/bin/lindmd" || entry.Uid != 0 || entry.Mode != 0555 || !bytes.Equal(content, payload) {
				t.Fatal("OCI layer lost binary binding")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("missing executable OCI layer")
	}
}
