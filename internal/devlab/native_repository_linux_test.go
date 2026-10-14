// SPDX-License-Identifier: Apache-2.0

//go:build linux

package devlab

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	adminv1 "lindm/gen/lindm/admin/v1"
	releasev1 "lindm/gen/lindm/release/v1"
	"lindm/internal/packaging"
)

func TestNativeRepositoryCustodyNeverServesPrivateSigner(t *testing.T) {
	root := filepath.Join(t.TempDir(), "release")
	for _, custody := range []string{root, filepath.Join(root, "keys"), filepath.Join(root, "repo", "apt", "signer")} {
		if err := nativeRepositoryCustody(root, custody, []string{"arm64"}); err == nil {
			t.Fatalf("served signing custody accepted: %s", custody)
		}
	}
	for _, custody := range []string{root + "-custody", filepath.Join(filepath.Dir(root), "keys")} {
		if err := nativeRepositoryCustody(root, custody, []string{"arm64", "amd64"}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNativeRepositoryArchitecturesRejectDuplicatesAndPaths(t *testing.T) {
	root := filepath.Join(t.TempDir(), "release")
	for _, architectures := range [][]string{{"arm64", "arm64"}, {"../release"}, {"aarch64"}, {""}} {
		if err := nativeRepositoryCustody(root, root+"-custody", architectures); err == nil {
			t.Fatalf("invalid architecture selection accepted: %q", architectures)
		}
	}
}

func TestNativeEnrollmentPublicationIncludesOnlyAdmittedPacmanArchitecture(t *testing.T) {
	if !slices.Equal(nativeEnrollmentFormats("amd64"), []packaging.Format{packaging.FormatDEB, packaging.FormatRPM, packaging.FormatArch}) {
		t.Fatal("own-server fixture omits the admitted Arch enrollment repository")
	}
	if !slices.Equal(nativeEnrollmentFormats("arm64"), []packaging.Format{packaging.FormatDEB, packaging.FormatRPM}) {
		t.Fatal("generic arm64 package build invented an Arch Linux ARM installation row")
	}
}

func TestNativeEnrollmentArtifactRequiresEveryRequestedPackageFamily(t *testing.T) {
	manifest := &releasev1.ReleaseManifest{Artifacts: []*releasev1.ReleaseArtifact{
		{Product: packaging.PackageName, Architecture: "amd64", Format: "deb"},
		{Product: packaging.PackageName, Architecture: "amd64", Format: "rpm"},
		{Product: packaging.PackageName, Architecture: "amd64", Format: "arch"},
	}}
	if err := nativeEnrollmentArtifactArchitectures(manifest, []string{"amd64"}); err != nil {
		t.Fatal(err)
	}
	if err := nativeEnrollmentArtifactArchitectures(manifest, []string{"amd64", "arm64"}); err == nil {
		t.Fatal("requested architecture without signed packages was accepted")
	}
	manifest.Artifacts = manifest.Artifacts[:2]
	if err := nativeEnrollmentArtifactArchitectures(manifest, []string{"amd64"}); err == nil {
		t.Fatal("admitted pacman architecture without a signed package was accepted")
	}
	manifest.Artifacts = []*releasev1.ReleaseArtifact{
		{Product: "lindmd", Architecture: "arm64", Format: "deb"},
		{Product: "lindmd", Architecture: "arm64", Format: "rpm"},
	}
	if err := nativeEnrollmentArtifactArchitectures(manifest, []string{"arm64"}); err == nil {
		t.Fatal("server packages were accepted as signed agent packages")
	}
}

func TestNativeEnrollmentServerCopyIsPrivateAndDigestBound(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "lindmd")
	binary := []byte("operator-selected server artifact")
	if err := os.WriteFile(source, binary, 0700); err != nil {
		t.Fatal(err)
	}
	destinations := []string{filepath.Join(root, "first", "lindmd"), filepath.Join(root, "second", "lindmd")}
	expected := sha256.Sum256(binary)
	for _, destination := range destinations {
		if err := os.Mkdir(filepath.Dir(destination), 0700); err != nil {
			t.Fatal(err)
		}
		digest, err := copyNativeEnrollmentServer(source, destination)
		if err != nil {
			t.Fatal(err)
		}
		if digest != hex.EncodeToString(expected[:]) {
			t.Fatal("fixture server copy lost its exact digest")
		}
		info, err := os.Stat(destination)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0500 {
			t.Fatal("fixture server executable is writable or accessible to other users")
		}
	}
	if _, err := copyNativeEnrollmentServer(source, destinations[0]); err == nil {
		t.Fatal("another fixture's executable was overwritten")
	}
	if err := os.Chmod(source, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := copyNativeEnrollmentServer(source, filepath.Join(root, "invalid")); err == nil {
		t.Fatal("non-executable source was accepted")
	}
}

func TestNativeEnrollmentReadinessErrorKeepsDistinctLoaderRemedies(t *testing.T) {
	apt := &adminv1.EnrollmentReadiness{Reason: "native_repository_unavailable", Remedy: "APT index has a digest mismatch"}
	rpm := &adminv1.EnrollmentReadiness{Reason: "native_repository_unavailable", Remedy: "RPM metadata permits group writes"}
	instructions := &adminv1.GetEnrollmentInstructionsResponse{
		Readiness: &adminv1.EnrollmentReadiness{Reason: "native_repository_unavailable", Remedy: "Install a signed agent artifact"},
		Platforms: []*adminv1.EnrollmentPlatform{
			{Id: "ubuntu-24.04", PackageFamily: "apt", Readiness: apt},
			{Id: "debian-13", PackageFamily: "apt", Readiness: apt},
			{Id: "fedora-44", PackageFamily: "dnf", Readiness: rpm},
		},
	}
	message := nativeEnrollmentReadinessError(instructions).Error()
	for _, expected := range []string{"native_repository_unavailable", "Install a signed agent artifact", "ubuntu-24.04 (apt)", apt.GetRemedy(), "fedora-44 (dnf)", rpm.GetRemedy()} {
		if !strings.Contains(message, expected) {
			t.Fatalf("startup failure omitted actionable loader detail %q: %s", expected, message)
		}
	}
	if strings.Count(message, apt.GetRemedy()) != 1 {
		t.Fatal("startup failure repeats identical loader errors for each distribution")
	}
}
