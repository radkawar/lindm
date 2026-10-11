//go:build linux

package devlab

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/packaging"
	"lindm/internal/platform"
)

// NativeEnrollmentRepository records actual native package and signed metadata
// publication. Private signing custody is never under the served directory.
type NativeEnrollmentRepository struct {
	APTURL            string                    `json:"apt_url"`
	RPMURL            string                    `json:"rpm_url"`
	ArchURL           string                    `json:"arch_url,omitempty"`
	SignerFingerprint string                    `json:"signer_fingerprint"`
	Artifacts         []packaging.Artifact      `json:"artifacts"`
	APT               *packaging.APTRepository  `json:"apt"`
	RPM               *packaging.RPMRepository  `json:"rpm"`
	Arch              *packaging.ArchRepository `json:"arch,omitempty"`
}

// ConfigureNativeEnrollmentRepository builds this checkout's real agent packages
// and publishes admitted native formats before lindmd starts. The caller owns a NEW
// custodyDirectory and its cleanup. Existing published repositories are never
// overwritten. This is development signing, not production signing custody.
func ConfigureNativeEnrollmentRepository(ctx context.Context, cfg *configv1.ServerConfig, sourceRepository, custodyDirectory string, architectures []string) (*NativeEnrollmentRepository, error) {
	if cfg.GetReleaseRepository().GetDirectory() == "" || sourceRepository == "" || len(architectures) == 0 {
		return nil, errors.New("native enrollment publication requires a release repository, checkout and explicit architectures")
	}
	root, err := filepath.Abs(cfg.GetReleaseRepository().GetDirectory())
	if err != nil {
		return nil, err
	}
	custody, err := filepath.Abs(custodyDirectory)
	if err != nil {
		return nil, err
	}
	if err := nativeRepositoryCustody(root, custody, architectures); err != nil {
		return nil, err
	}
	if err := os.Mkdir(custody, 0700); err != nil {
		return nil, err
	}
	signer, err := packaging.GenerateDevelopmentSigner(ctx, custody)
	if err != nil {
		return nil, err
	}
	result := &NativeEnrollmentRepository{APTURL: cfg.GetPublicUrl() + "/repo/apt", RPMURL: cfg.GetPublicUrl() + "/repo/rpm", SignerFingerprint: signer.Fingerprint}
	var debs, rpms, archPackages []string
	for _, architecture := range architectures {
		output := filepath.Join(custody, architecture)
		if err := os.Mkdir(output, 0700); err != nil {
			return nil, err
		}
		built, err := packaging.BuildSource(ctx, packaging.SourceRequest{Repository: sourceRepository, Revision: "console-enrollment-lab", BuildRequest: packaging.BuildRequest{Version: "0.1.0", TargetArchitecture: architecture, OutputDir: output, Formats: nativeEnrollmentFormats(architecture), Signer: *signer}})
		if err != nil {
			return nil, err
		}
		for _, artifact := range built.Artifacts {
			switch artifact.Format {
			case packaging.FormatDEB:
				debs = append(debs, artifact.Path)
			case packaging.FormatRPM:
				rpms = append(rpms, artifact.Path)
			case packaging.FormatArch:
				archPackages = append(archPackages, artifact.Path)
			}
		}
		result.Artifacts = append(result.Artifacts, built.Artifacts...)
	}
	repo := filepath.Join(root, "repo")
	if err := os.Mkdir(repo, 0700); err != nil {
		return nil, err
	}
	result.APT, err = packaging.PublishAPT(ctx, packaging.APTRequest{OutputDir: repo, DEBs: debs, Signer: *signer})
	if err != nil {
		return nil, err
	}
	result.RPM, err = packaging.PublishRPM(ctx, packaging.RPMRequest{OutputDir: repo, RPMs: rpms, Signer: *signer})
	if err != nil {
		return nil, err
	}
	cfg.ReleaseRepository.NativeRepositories = &configv1.NativeRepositoriesConfig{AptSigningKeyFingerprint: proto.String(signer.Fingerprint), RpmSigningKeyFingerprint: proto.String(signer.Fingerprint)}
	if len(archPackages) != 0 {
		result.Arch, err = packaging.PublishArch(ctx, packaging.ArchRequest{OutputDir: repo, Packages: archPackages, Signer: *signer})
		if err != nil {
			return nil, err
		}
		result.ArchURL = cfg.GetPublicUrl() + "/repo/arch"
		cfg.ReleaseRepository.NativeRepositories.ArchSigningKeyFingerprint = proto.String(signer.Fingerprint)
	}
	return result, nil
}

// Publish pacman only for architectures admitted by registry lifecycle rows.
// A generic aarch64 package build is not Arch Linux ARM qualification.
func nativeEnrollmentFormats(architecture string) []packaging.Format {
	formats := []packaging.Format{packaging.FormatDEB, packaging.FormatRPM}
	native := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[architecture]
	for _, release := range platform.Releases() {
		if release.Native().Packages.Backend == platform.BackendPacman &&
			release.Supported(platform.Lifecycle) && slices.Contains(release.Architectures, native) {
			return append(formats, packaging.FormatArch)
		}
	}
	return formats
}

func nativeRepositoryCustody(root, custody string, architectures []string) error {
	rel, err := filepath.Rel(root, custody)
	if err != nil {
		return err
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return errors.New("native package signing custody must be outside the served release repository")
	}
	for i, architecture := range architectures {
		if (architecture != "arm64" && architecture != "amd64") || slices.Contains(architectures[:i], architecture) {
			return fmt.Errorf("native publication requires distinct amd64 or arm64 architectures, got %q", architecture)
		}
	}
	return nil
}

// OpenEnrollmentConsoleAuthorityFixture starts a local-auth server with real
// current-build native repositories, ready for browser-created credentials.
func OpenEnrollmentConsoleAuthorityFixture(ctx context.Context, repository, sourceRepository, binary string, architectures []string) (*AuthorityFixture, error) {
	return openAuthorityFixtureWithOptions(ctx, repository, binary, authorityDeviceActions, LoadAuthorityOptions{NativeEnrollmentArchitectures: architectures, NativeEnrollmentSourceRepository: sourceRepository})
}
