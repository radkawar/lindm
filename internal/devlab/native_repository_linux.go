//go:build linux

package devlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"connectrpc.com/connect"

	adminv1 "lindm/gen/lindm/admin/v1"
	configv1 "lindm/gen/lindm/config/v1"
	releasev1 "lindm/gen/lindm/release/v1"
	"lindm/internal/config"
	"lindm/internal/packaging"
	"lindm/internal/platform"
	"lindm/internal/releasebuild"
)

// NativeEnrollmentRepository records the signed development artifact and the
// server's observed readiness. It is not a production signing or native VM claim.
type NativeEnrollmentRepository struct {
	APTURL                       string                     `json:"apt_url"`
	RPMURL                       string                     `json:"rpm_url"`
	ArchURL                      string                     `json:"arch_url,omitempty"`
	SignerFingerprint            string                     `json:"signer_fingerprint"`
	BundleDirectory              string                     `json:"bundle_directory"`
	ServerBinary                 string                     `json:"server_binary"`
	ServerSHA256                 string                     `json:"server_sha256"`
	ConfigSHA256                 string                     `json:"config_sha256"`
	ReleaseRepositoryConfigured  bool                       `json:"release_repository_configured"`
	NativeRepositoriesConfigured bool                       `json:"native_repositories_configured"`
	Ready                        bool                       `json:"ready"`
	Manifest                     *releasev1.ReleaseManifest `json:"manifest"`
}

// buildNativeEnrollmentArtifact creates a private executable-adjacent bundle.
// lindmd discovers it through the same artifact verification as an installed
// /usr/share/lindmd/agent-repository, without native repository configuration.
// Requested architectures must be present; the payload carries the complete
// stock native matrix. Dedicated development signing keys are removed before
// lindmd starts, and are never part of the artifact.
func (f *AuthorityFixture) buildNativeEnrollmentArtifact(ctx context.Context, cfg *configv1.ServerConfig, sourceRepository string, architectures []string) (resultErr error) {
	if sourceRepository == "" || len(architectures) == 0 {
		return errors.New("native enrollment artifact requires a source checkout and explicit architectures")
	}
	if cfg.GetReleaseRepository().GetNativeRepositories() != nil {
		return errors.New("native enrollment artifact refuses configured native repositories")
	}
	artifactDirectory := filepath.Join(f.directory, "server-artifact")
	bundle := filepath.Join(artifactDirectory, "agent-repository")
	custody := filepath.Join(f.directory, "native-package-custody")
	if err := nativeRepositoryCustody(bundle, custody, architectures); err != nil {
		return err
	}
	if err := os.Mkdir(artifactDirectory, 0700); err != nil {
		return err
	}
	binary := filepath.Join(artifactDirectory, "lindmd")
	digest, err := copyNativeEnrollmentServer(f.binary, binary)
	if err != nil {
		return err
	}
	if err := os.Mkdir(custody, 0700); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(custody)) }()
	signer, err := packaging.GenerateDevelopmentSigner(ctx, custody)
	if err != nil {
		return err
	}
	attestationDirectory := filepath.Join(custody, "attestation")
	keyID, err := releasebuild.GenerateDevelopmentKey(attestationDirectory)
	if err != nil {
		return err
	}
	manifest, err := releasebuild.BuildDevelopmentAgentRepository(ctx, releasebuild.Request{
		Repository: sourceRepository, Output: bundle, Version: "0.1.0", Revision: "console-enrollment-lab",
		SourceDateEpoch: packaging.DefaultSourceDateEpoch, PackageSigner: *signer,
		AttestationSigner: releasebuild.AttestationKey{Path: filepath.Join(attestationDirectory, "attestation.pem"), KeyID: keyID, Custody: "development"},
	})
	if err != nil {
		return fmt.Errorf("build signed enrollment artifact: %w", err)
	}
	if err := nativeEnrollmentArtifactArchitectures(manifest, architectures); err != nil {
		return err
	}
	f.NativeRepository = &NativeEnrollmentRepository{
		APTURL: cfg.GetPublicUrl() + "/repo/apt", RPMURL: cfg.GetPublicUrl() + "/repo/rpm", ArchURL: cfg.GetPublicUrl() + "/repo/arch",
		SignerFingerprint: signer.Fingerprint, BundleDirectory: bundle, ServerBinary: binary, ServerSHA256: digest, Manifest: manifest,
	}
	f.binary = binary
	return nil
}

func nativeEnrollmentArtifactArchitectures(manifest *releasev1.ReleaseManifest, architectures []string) error {
	for _, architecture := range architectures {
		for _, format := range nativeEnrollmentFormats(architecture) {
			if !slices.ContainsFunc(manifest.GetArtifacts(), func(artifact *releasev1.ReleaseArtifact) bool {
				return artifact.GetProduct() == packaging.PackageName && artifact.GetArchitecture() == architecture && artifact.GetFormat() == string(format)
			}) {
				return fmt.Errorf("signed enrollment artifact lacks %s agent package for %s", format, architecture)
			}
		}
	}
	return nil
}

// copyNativeEnrollmentServer streams the operator-selected binary into owned
// fixture state, preventing concurrent fixtures from sharing an adjacent bundle.
func copyNativeEnrollmentServer(source, destination string) (_ string, resultErr error) {
	input, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer func() { resultErr = errors.Join(resultErr, input.Close()) }()
	info, err := input.Stat()
	if err != nil {
		return "", err
	}
	const limit int64 = 512 << 20
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Size() <= 0 || info.Size() > limit {
		return "", errors.New("native enrollment artifact requires a bounded executable lindmd")
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0500)
	if err != nil {
		return "", err
	}
	defer func() { resultErr = errors.Join(resultErr, output.Close()) }()
	hash := sha256.New()
	count, err := io.Copy(io.MultiWriter(output, hash), io.LimitReader(input, limit+1))
	if err != nil {
		return "", err
	}
	if count != info.Size() {
		return "", errors.New("native enrollment server changed while copying")
	}
	if err := output.Sync(); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// recordNativeEnrollmentReadiness binds publication evidence to actual server
// configuration and its authenticated enrollment response, not a fixture promise.
func (f *AuthorityFixture) recordNativeEnrollmentReadiness(ctx context.Context) (resultErr error) {
	if f.NativeRepository == nil {
		return nil
	}
	document, err := config.Load(f.configPath())
	if err != nil {
		return err
	}
	publication := f.NativeRepository
	publication.ReleaseRepositoryConfigured = document.Proto.GetReleaseRepository() != nil
	publication.NativeRepositoriesConfigured = document.Proto.GetReleaseRepository().GetNativeRepositories() != nil
	if publication.NativeRepositoriesConfigured {
		return errors.New("stock enrollment fixture unexpectedly configures native repositories")
	}
	publication.ConfigSHA256, err = scaleOutBinaryDigest(f.configPath())
	if err != nil {
		return err
	}
	owner, err := f.OpenOwnerSession(ctx)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, closeReleaseSession(owner)) }()
	instructions, err := owner.Admin.GetEnrollmentInstructions(ctx, connect.NewRequest(&adminv1.GetEnrollmentInstructionsRequest{}))
	if err != nil {
		return err
	}
	if !instructions.Msg.GetReadiness().GetReady() {
		return fmt.Errorf("stock enrollment fixture is not ready: %s", instructions.Msg.GetReadiness().GetReason())
	}
	if instructions.Msg.GetAptRepository().GetSigningKeyFingerprint() != publication.SignerFingerprint ||
		instructions.Msg.GetDnfRepository().GetSigningKeyFingerprint() != publication.SignerFingerprint ||
		instructions.Msg.GetArchRepository().GetSigningKeyFingerprint() != publication.SignerFingerprint {
		return errors.New("stock enrollment fixture did not load its signed artifact package key")
	}
	publication.Ready = true
	return nil
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
		return errors.New("native package signing custody must be outside the served agent artifact")
	}
	for i, architecture := range architectures {
		if (architecture != "arm64" && architecture != "amd64") || slices.Contains(architectures[:i], architecture) {
			return fmt.Errorf("native publication requires distinct amd64 or arm64 architectures, got %q", architecture)
		}
	}
	return nil
}

// OpenEnrollmentConsoleAuthorityFixture starts a local-auth server with an
// authenticated development agent bundle, ready for browser-created credentials.
// A non-empty publicHost (see ValidatePublicHost) names both origins instead of
// localhost; callers map it to the fixture's loopback listeners themselves.
func OpenEnrollmentConsoleAuthorityFixture(ctx context.Context, repository, sourceRepository, binary string, architectures []string, publicHost string) (*AuthorityFixture, error) {
	return openAuthorityFixtureWithOptions(ctx, repository, binary, authorityDeviceActions, LoadAuthorityOptions{NativeEnrollmentArchitectures: architectures, NativeEnrollmentSourceRepository: sourceRepository, publicHost: publicHost, stockEnrollment: true})
}

// OpenStockConsoleAuthorityFixture adds the real signed agent artifact to a
// disposable local console. Synthetic population remains separate from native
// enrollment evidence; no release repository configuration is installed.
func OpenStockConsoleAuthorityFixture(ctx context.Context, repository, sourceRepository, binary string) (*AuthorityFixture, error) {
	return openAuthorityFixtureWithOptions(ctx, repository, binary, authorityLocalConsole, LoadAuthorityOptions{NativeEnrollmentArchitectures: []string{"amd64", "arm64"}, NativeEnrollmentSourceRepository: sourceRepository, stockEnrollment: true})
}
