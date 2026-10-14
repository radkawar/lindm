// SPDX-License-Identifier: Apache-2.0

//go:build linux

package releasebuild

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"google.golang.org/protobuf/proto"

	releasev1 "lindm/gen/lindm/release/v1"
	"lindm/internal/packaging"
	"lindm/internal/platform"
)

// nativeFormats derives the supported registry's native matrix, including
// derivatives' native bases. It does not confuse Arch Linux with Arch Linux ARM.
func nativeFormats(architecture, product string) []string {
	if product == "lindmctl" {
		return []string{"deb", "rpm"}
	}
	var formats []string
	for _, release := range platform.Releases() {
		if release.Tier != platform.Tier1 && release.Tier != platform.Tier2 {
			continue
		}
		kernel := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[architecture]
		if !slices.Contains(release.Architectures, kernel) {
			continue
		}
		format := release.Native().Packages.Backend.PackageFormat()
		if format != "" && !slices.Contains(formats, format) {
			formats = append(formats, format)
		}
	}
	slices.Sort(formats)
	return formats
}

func bundleForProduct(product, bundle string) string {
	if product == "lindmd" {
		return bundle
	}
	return ""
}

func exportRelease(ctx context.Context, exported string, request Request, signer *releaseSigner, sourceDigest string, first, second *buildOutput, bundle, licenses string) (*releasev1.ReleaseManifest, error) {
	if err := compareBuilds(first, second); err != nil {
		return nil, err
	}
	names := packaging.LicenseNames()
	licenseHashes := make(map[string]string, len(names))
	for _, name := range names {
		if err := copyNew(filepath.Join(licenses, name), filepath.Join(exported, name), 0o644); err != nil {
			return nil, err
		}
		sum, _, err := digestBoundedFile(filepath.Join(exported, name), maxDocument)
		if err != nil {
			return nil, err
		}
		licenseHashes[name] = sum
	}
	var bundleDigest string
	if bundle != "" {
		var err error
		bundleDigest, err = treeDigest(bundle)
		if err != nil {
			return nil, err
		}
	}
	manifest := &releasev1.ReleaseManifest{Version: request.Version, Revision: request.Revision, SourceSha256: sourceDigest, SourceDateEpoch: request.SourceDateEpoch, AttestationKeyId: signer.id, Custody: request.AttestationSigner.Custody, Builds: []*releasev1.BuildObservation{proto.CloneOf(first.observation), proto.CloneOf(second.observation)}, LicenseSha256: licenseHashes}
	if bundle != "" {
		manifest.ServerNotice = proto.CloneOf(request.ServerNotice)
	}
	for _, built := range first.artifacts {
		artifact := proto.CloneOf(built.artifact)
		artifact.SecondUnsignedSha256 = second.observation.GetUnsignedSha256()[artifact.GetPath()]
		if err := exportArtifact(exported, built); err != nil {
			return nil, err
		}
		artifact.SbomPath = artifact.GetPath() + ".sbom.dsse.json"
		artifact.ProvenancePath = artifact.GetPath() + ".provenance.dsse.json"
		artifact.SignaturePath = artifact.GetPath() + ".signature.dsse.json"
		var bom any
		if err := json.Unmarshal(built.sbom, &bom); err != nil {
			return nil, err
		}
		provenance := provenancePredicate(request, artifact, sourceDigest, request.OCICASHA256, bundleDigest, first.observation, second.observation)
		if err := writeAttestations(exported, signer, artifact, bom, provenance, manifest.GetCustody()); err != nil {
			return nil, err
		}
		manifest.Artifacts = append(manifest.Artifacts, artifact)
	}
	if err := writeSignedManifest(exported, signer, manifest); err != nil {
		return nil, err
	}
	if err := writeNew(filepath.Join(exported, "attestation.pub"), signer.public, 0644); err != nil {
		return nil, err
	}
	if err := copyNew(first.packagePublicKey, filepath.Join(exported, "package-signing.asc"), 0644); err != nil {
		return nil, err
	}
	if bundle != "" {
		if err := copySource(bundle, filepath.Join(exported, "agent-repository")); err != nil {
			return nil, err
		}
	}
	return Verify(ctx, exported, filepath.Join(exported, "attestation.pub"), signer.id)
}

func publishAgentRepositories(ctx context.Context, bundle string, request Request, manifest *releasev1.ReleaseManifest) error {
	repositories := filepath.Join(bundle, "repo")
	if err := os.Mkdir(repositories, 0700); err != nil {
		return err
	}
	paths := map[string][]string{}
	for _, artifact := range manifest.GetArtifacts() {
		if artifact.GetProduct() != "lindm-agent" {
			return errors.New("releasebuild: repository bundle contains non-agent artifacts")
		}
		paths[artifact.GetFormat()] = append(paths[artifact.GetFormat()], filepath.Join(bundle, artifact.GetPath()))
	}
	if _, err := packaging.PublishAPT(ctx, packaging.APTRequest{OutputDir: repositories, DEBs: paths["deb"], Signer: request.PackageSigner, SourceDateEpoch: request.SourceDateEpoch}); err != nil {
		return err
	}
	if _, err := packaging.PublishRPM(ctx, packaging.RPMRequest{OutputDir: repositories, RPMs: paths["rpm"], Signer: request.PackageSigner, SourceDateEpoch: request.SourceDateEpoch}); err != nil {
		return err
	}
	_, err := packaging.PublishArch(ctx, packaging.ArchRequest{OutputDir: repositories, Packages: paths[string(packaging.FormatArch)], Signer: request.PackageSigner, SourceDateEpoch: request.SourceDateEpoch})
	return err
}

// normalizeAgentRepository applies the installed bundle's protected modes after
// external repository tools finish. Their ancillary metadata/directories can
// inherit the caller's writable umask; permission changes preserve signed bytes.
func normalizeAgentRepository(bundle string) error {
	return filepath.WalkDir(bundle, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.IsDir() {
			return os.Chmod(path, 0755)
		}
		if !info.Mode().IsRegular() || info.Size() <= 0 {
			return fmt.Errorf("releasebuild: agent repository member %q must be a nonempty regular file", path)
		}
		return os.Chmod(path, 0444)
	})
}

// CanonicalizeEmbeddedRepository restores the protected modes of a server
// release's embedded agent repository (directory/agent-repository) after a
// transport that keeps bytes but not modes, such as an offline bundle's
// staging. The release provenance digest binds those modes, so Verify must see
// the canonical tree; bytes still have to match. A release without the
// directory is unchanged.
func CanonicalizeEmbeddedRepository(directory string) error {
	bundle := filepath.Join(directory, "agent-repository")
	info, err := os.Lstat(bundle)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("releasebuild: embedded agent repository is not a directory")
	}
	return normalizeAgentRepository(bundle)
}
