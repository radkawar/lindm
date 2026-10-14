// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	releasev1 "lindm/gen/lindm/release/v1"
)

func auditInputDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestHistoricalAuditSnapshotsManifestBoundPackage(t *testing.T) {
	release, private := t.TempDir(), t.TempDir()
	original := []byte("authenticated native package")
	path := filepath.Join(release, "server.deb")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	manifest := &releasev1.ReleaseManifest{Artifacts: []*releasev1.ReleaseArtifact{{Path: "server.deb", Product: "lindmd", Format: "deb", Architecture: "amd64", Sha256: auditInputDigest(original), Size: int64(len(original))}}}
	inputs, err := snapshotDeployAuditNativeInputs(context.Background(), release, private, "deb", "", "", manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	retained, err := os.ReadFile(inputs.PackagePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(retained) != string(original) {
		t.Fatal("authenticated snapshot followed replaced release member")
	}
	if _, err := snapshotDeployAuditNativeInputs(context.Background(), release, private, "deb", "", "", manifest); err == nil {
		t.Fatal("replacement admitted against original manifest")
	}
}

func TestHistoricalAuditNativeInputRejectsMismatchAndLinks(t *testing.T) {
	original := []byte("original bytes")
	for _, kind := range []string{"digest", "size", "symlink", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			source := filepath.Join(directory, "source")
			if err := os.WriteFile(source, original, 0600); err != nil {
				t.Fatal(err)
			}
			digest, size, bound := auditInputDigest(original), int64(len(original)), int64(1024)
			switch kind {
			case "digest":
				digest = auditInputDigest([]byte("other bytes"))
			case "size":
				size++
			case "oversize":
				bound = 1
			case "symlink":
				link := filepath.Join(directory, "linked")
				if err := os.Symlink(source, link); err != nil {
					t.Fatal(err)
				}
				source = link
			}
			if err := snapshotDeployAuditInput(context.Background(), source, filepath.Join(directory, "copy"), digest, size, bound); err == nil {
				t.Fatal("unbound historical input accepted")
			}
		})
	}
}

func TestHistoricalAuditRejectsRPMKeyPathSubstitution(t *testing.T) {
	release, private := t.TempDir(), t.TempDir()
	original := []byte("native package")
	if err := os.WriteFile(filepath.Join(release, "server.rpm"), original, 0600); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(private, "outside.asc")
	if err := os.WriteFile(key, []byte("substituted public key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key, filepath.Join(release, "package-signing.asc")); err != nil {
		t.Fatal(err)
	}
	manifest := &releasev1.ReleaseManifest{Artifacts: []*releasev1.ReleaseArtifact{{Path: "server.rpm", Product: "lindmd", Format: "rpm", Architecture: "amd64", Sha256: auditInputDigest(original), Size: int64(len(original))}}}
	if _, err := snapshotDeployAuditNativeInputs(context.Background(), release, private, "rpm", auditInputDigest([]byte("substituted public key")), "", manifest); err == nil {
		t.Fatal("RPM public key symlink admitted")
	}
}

func TestHistoricalAuditRejectsManifestPathTraversal(t *testing.T) {
	for _, name := range []string{"../server.deb", "/server.deb", "nested/server.deb", "."} {
		manifest := &releasev1.ReleaseManifest{Artifacts: []*releasev1.ReleaseArtifact{{Path: name, Product: "lindmd", Format: "deb", Architecture: "amd64", Sha256: auditInputDigest([]byte("x")), Size: 1}}}
		if _, err := snapshotDeployAuditNativeInputs(context.Background(), t.TempDir(), t.TempDir(), "deb", "", "", manifest); err == nil {
			t.Fatalf("unsafe path %q admitted", name)
		}
	}
}
