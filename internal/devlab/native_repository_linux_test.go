//go:build linux

package devlab

import (
	"path/filepath"
	"slices"
	"testing"

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
