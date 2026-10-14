// SPDX-License-Identifier: Apache-2.0

//go:build linux

package offlinebundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"syscall"
	"time"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	bundlev1 "lindm/gen/lindm/bundle/v1"
	releasev1 "lindm/gen/lindm/release/v1"
	updatev1 "lindm/gen/lindm/update/v1"
	"lindm/internal/advisory/feed"
	"lindm/internal/packaging"
	"lindm/internal/releasebuild"
	"lindm/internal/releaseupdate"
)

// MaxValidity is the longest signed bundle lifetime. TUF targets and advisory
// freshness keep their own shorter expiry inside it.
const MaxValidity = 30 * 24 * time.Hour

// ExportRequest is an in-process export invocation on a connected station.
type ExportRequest struct {
	// Output must not exist; the bundle is assembled privately beside it and
	// renamed into place only after signing.
	Output   string
	Sequence uint64
	Validity time.Duration
	// Release is a release export verified with the pinned attestation key.
	Release, ReleasePublicKey, ReleaseKeyID string
	// PackageSigner signs the APT/RPM repository metadata; RPM packages must
	// already carry this signer's signatures from the release build.
	PackageSigner packaging.SigningKey
	// UpdatesRepository is the station TUF repository, verified from UpdatesRoot.
	UpdatesRepository string
	UpdatesRoot       []byte
	Rings             []string
	// Feeds are acquired over authenticated HTTPS by HTTPClient.
	Feeds      []*advisoryv1.FeedSource
	HTTPClient *http.Client
	Signer     SigningKey
	Now        func() time.Time
}

// Export builds and signs one complete offline bundle.
func Export(ctx context.Context, request ExportRequest) (_ *bundlev1.OfflineBundleManifest, resultErr error) {
	if request.Now == nil {
		request.Now = time.Now
	}
	if request.Sequence == 0 || request.Sequence > 1<<63-1 || request.Validity <= 0 || request.Validity > MaxValidity {
		return nil, errors.New("offlinebundle: positive sequence and validity of at most 30 days required")
	}
	if len(request.Feeds) > 0 && request.HTTPClient == nil {
		return nil, errors.New("offlinebundle: advisory acquisition requires an HTTPS client")
	}
	signer, err := loadSigningKey(request.Signer)
	if err != nil {
		return nil, err
	}
	output, err := filepath.Abs(request.Output)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("offlinebundle: output must not exist")
	}
	release, err := releasebuild.Verify(ctx, request.Release, request.ReleasePublicKey, request.ReleaseKeyID)
	if err != nil {
		return nil, fmt.Errorf("verify release export: %w", err)
	}
	work, err := os.MkdirTemp(filepath.Dir(output), ".lindm-bundle-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, os.RemoveAll(work))
		}
	}()
	manifest := &bundlev1.OfflineBundleManifest{
		BundleId: uuid.NewString(), Sequence: request.Sequence, SigningKeyId: signer.id, Custody: signer.custody,
		Release: &bundlev1.BundleRelease{Version: release.GetVersion(), AttestationKeyId: release.GetAttestationKeyId(), ArtifactCount: int32(len(release.GetArtifacts()))},
	}
	manifest.Release.ManifestSha256, err = copyRelease(request.Release, filepath.Join(work, releaseDir), release)
	if err != nil {
		return nil, err
	}
	manifest.Repositories, err = buildRepositories(ctx, work, release, request.PackageSigner)
	if err != nil {
		return nil, err
	}
	exported, err := releaseupdate.ExportOffline(ctx, releaseupdate.OfflineExportConfig{Source: request.UpdatesRepository, BootstrapRoot: request.UpdatesRoot, Destination: filepath.Join(work, updatesDir), Rings: request.Rings, Now: request.Now})
	if err != nil {
		return nil, fmt.Errorf("export verified TUF authority: %w", err)
	}
	manifest.Updates = &bundlev1.BundleUpdates{FirstRootVersion: exported.FirstRootVersion, RootVersion: exported.RootVersion, TargetsVersion: exported.TargetsVersion, Channels: exported.Rings}
	if err := bindUpdatePackages(filepath.Join(work, updatesDir), manifest.GetUpdates(), release); err != nil {
		return nil, err
	}
	if len(request.Feeds) > 0 {
		client, err := feed.New(request.HTTPClient)
		if err != nil {
			return nil, err
		}
		if err := os.Mkdir(filepath.Join(work, advisoryDir), 0755); err != nil {
			return nil, err
		}
		for _, source := range request.Feeds {
			snapshot, err := acquireSnapshot(ctx, client, source, filepath.Join(work, advisoryDir, source.GetId()), request.Now)
			if err != nil {
				return nil, fmt.Errorf("acquire advisory feed %s: %w", source.GetId(), err)
			}
			manifest.Advisories = append(manifest.Advisories, snapshot)
		}
	}
	manifest.Files, err = listFiles(ctx, work)
	if err != nil {
		return nil, err
	}
	created := request.Now().UTC()
	manifest.CreatedAt, manifest.ExpiresAt = timestamppb.New(created), timestamppb.New(created.Add(request.Validity))
	if err := protovalidate.Validate(manifest); err != nil {
		return nil, fmt.Errorf("validate bundle manifest: %w", err)
	}
	document, err := (protojson.MarshalOptions{Indent: "  "}).Marshal(manifest)
	if err != nil {
		return nil, err
	}
	envelope, err := signer.sign(document)
	if err != nil {
		return nil, err
	}
	if err := writeNewFile(filepath.Join(work, ManifestName), document, 0644); err != nil {
		return nil, err
	}
	if err := writeNewFile(filepath.Join(work, EnvelopeName), envelope, 0644); err != nil {
		return nil, err
	}
	if err := syncDirectory(work); err != nil {
		return nil, err
	}
	if err := os.Rename(work, output); err != nil {
		return nil, err
	}
	return manifest, syncDirectory(filepath.Dir(output))
}

// copyRelease copies exactly the attested release files and returns the
// SHA-256 of release.json. A server release also carries the attested agent
// repository subset it embeds (agent-repository/), which release verification
// requires, so import authenticates it rather than the bundle dropping it.
func copyRelease(source, destination string, release *releasev1.ReleaseManifest) (string, error) {
	if err := os.Mkdir(destination, 0755); err != nil {
		return "", err
	}
	names := []string{"release.json", "release.json.dsse"}
	server := false
	for _, artifact := range release.GetArtifacts() {
		names = append(names, artifact.GetPath(), artifact.GetSbomPath(), artifact.GetProvenancePath(), artifact.GetSignaturePath())
		if artifact.GetNativeSignaturePath() != "" {
			names = append(names, artifact.GetNativeSignaturePath())
		}
		server = server || artifact.GetProduct() == "lindmd"
	}
	var manifestDigest string
	for _, name := range names {
		if filepath.Base(name) != name {
			return "", errors.New("offlinebundle: release export path is not a base name")
		}
		digest, err := copyFileDigest(filepath.Join(source, name), filepath.Join(destination, name))
		if err != nil {
			return "", err
		}
		if name == "release.json" {
			manifestDigest = digest
		}
	}
	if server {
		if err := copyReleaseTree(filepath.Join(source, agentRepositoryDir), filepath.Join(destination, agentRepositoryDir)); err != nil {
			return "", fmt.Errorf("offlinebundle: copy embedded agent repository: %w", err)
		}
	}
	return manifestDigest, nil
}

// agentRepositoryDir is the server release's embedded agent repository.
const agentRepositoryDir = "agent-repository"

// copyReleaseTree copies a release subtree of directories and regular files
// only; anything else (a symlink, device or socket) is refused.
func copyReleaseTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		switch {
		case entry.IsDir():
			return os.Mkdir(target, 0755)
		case entry.Type().IsRegular():
			_, err := copyFileDigest(path, target)
			return err
		default:
			return fmt.Errorf("%s is not a regular file", relative)
		}
	})
}

// buildRepositories publishes one APT and one RPM repository per architecture,
// plus a pacman repository where the release carries Arch packages (amd64),
// from the attested release packages, binding each to the package signer.
func buildRepositories(ctx context.Context, work string, release *releasev1.ReleaseManifest, signer packaging.SigningKey) ([]*bundlev1.NativeRepository, error) {
	var repositories []*bundlev1.NativeRepository
	for _, architecture := range []string{"amd64", "arm64"} {
		parent := filepath.Join(work, reposDir, architecture)
		if err := os.MkdirAll(parent, 0700); err != nil {
			return nil, err
		}
		for _, format := range []string{"deb", "rpm", string(packaging.FormatArch)} {
			var paths, names []string
			for _, artifact := range release.GetArtifacts() {
				if artifact.GetArchitecture() == architecture && artifact.GetFormat() == format {
					paths = append(paths, filepath.Join(work, releaseDir, artifact.GetPath()))
					names = append(names, artifact.GetPath())
				}
			}
			// Arch packages exist only where the release targets Arch Linux.
			if len(paths) == 0 && format == string(packaging.FormatArch) {
				continue
			}
			if len(paths) == 0 {
				return nil, fmt.Errorf("offlinebundle: release export has no %s %s packages", architecture, format)
			}
			sort.Strings(names)
			var fingerprint string
			switch format {
			case "deb":
				repository, err := packaging.PublishAPT(ctx, packaging.APTRequest{OutputDir: parent, DEBs: paths, Signer: signer, SourceDateEpoch: release.GetSourceDateEpoch()})
				if err != nil {
					return nil, fmt.Errorf("publish %s APT repository: %w", architecture, err)
				}
				if !repository.InReleaseVerified || !repository.PackagesHashVerified {
					return nil, errors.New("offlinebundle: APT repository was not verified after signing")
				}
				fingerprint = repository.Fingerprint
			case "rpm":
				repository, err := packaging.PublishRPM(ctx, packaging.RPMRequest{OutputDir: parent, RPMs: paths, Signer: signer, SourceDateEpoch: release.GetSourceDateEpoch()})
				if err != nil {
					return nil, fmt.Errorf("publish %s RPM repository: %w", architecture, err)
				}
				if !repository.RepoMetadataSigned || !repository.GPGCheck {
					return nil, errors.New("offlinebundle: RPM repository metadata is not signed")
				}
				fingerprint = repository.Fingerprint
			default:
				// PublishArch reads each package's adjacent attested .sig and
				// verifies it against the signer before signing lindm.db.
				repository, err := packaging.PublishArch(ctx, packaging.ArchRequest{OutputDir: parent, Packages: paths, Signer: signer, SourceDateEpoch: release.GetSourceDateEpoch()})
				if err != nil {
					return nil, fmt.Errorf("publish %s pacman repository: %w", architecture, err)
				}
				if !repository.PackagesVerified || !repository.RepoMetadataSigned {
					return nil, errors.New("offlinebundle: pacman repository was not verified after signing")
				}
				fingerprint = repository.Fingerprint
			}
			repositories = append(repositories, &bundlev1.NativeRepository{Format: format, Architecture: architecture, SigningKeyFingerprint: fingerprint, Packages: names})
		}
		// Served trees must be readable by the importing server, which stages
		// its own private copy; the bundle itself keeps conventional modes.
		if err := os.Chmod(parent, 0755); err != nil {
			return nil, err
		}
	}
	return repositories, os.Chmod(filepath.Join(work, reposDir), 0755)
}

// bindUpdatePackages requires every proposed update artifact to be byte-for-byte
// one of the attested release agent packages, so SBOM/provenance cover it.
func bindUpdatePackages(directory string, updates *bundlev1.BundleUpdates, release *releasev1.ReleaseManifest) error {
	data, err := readBoundedRegular(filepath.Join(directory, "metadata", fmt.Sprintf("%d.targets.json", updates.GetTargetsVersion())), releaseupdate.MaxMetadataBytes)
	if err != nil {
		return err
	}
	targets, err := metadata.Targets().FromBytes(data)
	if err != nil {
		return err
	}
	for _, ring := range updates.GetChannels() {
		catalog, err := readBoundedRegular(filepath.Join(directory, "channels", ring+".json"), releaseupdate.MaxCatalogBytes)
		if err != nil {
			return err
		}
		channel := new(updatev1.AgentUpdateChannel)
		if err := protojson.Unmarshal(catalog, channel); err != nil {
			return err
		}
		for _, artifact := range channel.GetArtifacts() {
			info := targets.Signed.Targets[artifact.GetTargetPath()]
			if info == nil {
				return fmt.Errorf("offlinebundle: channel %s names unknown target %s", ring, artifact.GetTargetPath())
			}
			digest := hex.EncodeToString(info.Hashes["sha256"])
			if !slices.ContainsFunc(release.GetArtifacts(), func(candidate *releasev1.ReleaseArtifact) bool {
				return candidate.GetProduct() == "lindm-agent" && candidate.GetSha256() == digest && candidate.GetSize() == info.Length && candidate.GetArchitecture() == artifact.GetArchitecture() && candidate.GetFormat() == artifact.GetPackageFormat()
			}) {
				return fmt.Errorf("offlinebundle: update target %s is not an attested release agent package", artifact.GetTargetPath())
			}
		}
	}
	return nil
}

func acquireSnapshot(ctx context.Context, client *feed.Client, source *advisoryv1.FeedSource, destination string, now func() time.Time) (_ *bundlev1.AdvisorySnapshot, err error) {
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	// PostgreSQL stores microseconds; sign exactly the value freshness uses.
	acquired := now().UTC().Truncate(time.Microsecond)
	acquisition, err := client.Acquire(ctx, source, file)
	if err != nil {
		return nil, err
	}
	if err := file.Sync(); err != nil {
		return nil, err
	}
	snapshot := &bundlev1.AdvisorySnapshot{Source: source, AcquiredAt: timestamppb.New(acquired), Artifacts: acquisition.Artifacts}
	if acquisition.SnapshotAt != nil {
		snapshot.SnapshotAt = timestamppb.New(*acquisition.SnapshotAt)
	}
	return snapshot, nil
}

// listFiles records every regular file below the assembled tree, rejecting
// anything else so the signed manifest describes the complete bundle.
func listFiles(ctx context.Context, work string) ([]*bundlev1.BundleFile, error) {
	root, err := os.OpenRoot(work)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	var files []*bundlev1.BundleFile
	err = walkTree(ctx, root, ".", func(name string, entry fs.DirEntry) error {
		if !entry.Type().IsRegular() {
			return fmt.Errorf("offlinebundle: export produced non-regular %s", name)
		}
		f, err := root.Open(name)
		if err != nil {
			return err
		}
		digest := sha256.New()
		n, copyErr := io.Copy(digest, contextReader{ctx, f})
		if err := errors.Join(copyErr, f.Close()); err != nil {
			return err
		}
		files = append(files, &bundlev1.BundleFile{Path: name, Sha256: hex.EncodeToString(digest.Sum(nil)), Size: n})
		return nil
	})
	sort.Slice(files, func(i, j int) bool { return files[i].GetPath() < files[j].GetPath() })
	return files, err
}

func copyFileDigest(source, destination string) (_ string, err error) {
	input, err := os.OpenFile(source, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	info, err := input.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("offlinebundle: release input must be a regular file")
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, output.Close()) }()
	digest := sha256.New()
	if _, err := io.Copy(io.MultiWriter(output, digest), input); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), output.Sync()
}
