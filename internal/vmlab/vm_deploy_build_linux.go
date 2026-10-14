// SPDX-License-Identifier: Apache-2.0
//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/mod/semver"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/releasebuild"
	"lindm/internal/releasekit"
)

const DeployBuildMemoryMiB = 8192
const coldReleaseDiskBytes = 32 << 30
const coldReleaseScope = "production-cold-release-build-only"

var coldReleaseRevision = regexp.MustCompile(`^[0-9a-f]{40}$`)
var coldReleaseEpoch = regexp.MustCompile(`^[1-9][0-9]{0,11}$`)
var coldReleaseVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

type VMDeployBuildOptions struct {
	Repository, Revision, CacheDir, WorkDir, EvidenceDirectory string
	OperatorRecipientFile, FirstVersion, NewerVersion          string
}

type VMDeployBuildResult struct {
	Scope                string                               `json:"scope"`
	LifecycleQualified   bool                                 `json:"lifecycle_qualified"`
	SourceRevision       string                               `json:"source_revision"`
	SourceDateEpoch      string                               `json:"source_date_epoch"`
	GitBundleSHA256      string                               `json:"git_bundle_sha256"`
	GuestGitClone        bool                                 `json:"guest_git_clone"`
	GuestNoSwap          bool                                 `json:"guest_no_swap"`
	ImageID              string                               `json:"image_id"`
	ImageSHA256          string                               `json:"image_sha256"`
	MemoryMiB            int                                  `json:"memory_mib"`
	MinimumDiskBytes     int64                                `json:"minimum_disk_bytes"`
	ReleaseKeyID         string                               `json:"release_key_id"`
	FirstVersion         string                               `json:"first_version"`
	NewerVersion         string                               `json:"newer_version"`
	StartedAt            time.Time                            `json:"started_at"`
	FinishedAt           time.Time                            `json:"finished_at"`
	Stages               []VMProductionReleaseSigningStage    `json:"stages"`
	Evidence             []VMProductionReleaseSigningEvidence `json:"evidence"`
	OwnedCleanupComplete bool                                 `json:"owned_cleanup_complete"`
	Passed               bool                                 `json:"passed"`
}

// RunVMDeployBuild is deliberately one admitted guest, never full deploy
// qualification. Actual committed source crosses only as a private Git bundle;
// the fresh guest clones it, installs vendor-authenticated pinned SDKs, and runs
// literal customer Make entrypoints. No host key, passphrase or cache is used.
func RunVMDeployBuild(ctx context.Context, manifest *labv1.ImageManifest, options VMDeployBuildOptions) (result *VMDeployBuildResult, resultErr error) {
	if ctx == nil || !coldReleaseRevision.MatchString(options.Revision) || !coldReleaseVersionsValid(options.FirstVersion, options.NewerVersion) {
		return nil, errors.New("cold release build requires context, exact committed revision and strictly newer semantic release versions")
	}
	hardware, err := productionSigningHardware(manifest, &VMHardwareOptions{MemoryMiB: DeployBuildMemoryMiB, CPUs: 2, Architecture: "x86_64", Accelerator: "kvm", AllowNetwork: true, minimumDiskBytes: coldReleaseDiskBytes})
	if err != nil {
		return nil, err
	}
	for _, directory := range []string{options.Repository, options.CacheDir, options.WorkDir, options.EvidenceDirectory} {
		if err := productionSigningDirectory(directory); err != nil {
			return nil, err
		}
	}
	result = &VMDeployBuildResult{Scope: coldReleaseScope, SourceRevision: options.Revision, ImageID: manifest.GetId(), MemoryMiB: DeployBuildMemoryMiB, MinimumDiskBytes: coldReleaseDiskBytes, FirstVersion: options.FirstVersion, NewerVersion: options.NewerVersion, StartedAt: time.Now().UTC()}
	work, err := os.MkdirTemp(options.WorkDir, "cold-release-")
	if err != nil {
		return result, err
	}
	var guest *guestVM
	defer func() {
		var cleanupErr error
		if guest != nil {
			cleanupErr = guest.close()
		}
		cleanupErr = errors.Join(cleanupErr, os.RemoveAll(work))
		result.OwnedCleanupComplete = cleanupErr == nil
		resultErr = errors.Join(resultErr, cleanupErr)
		result.Passed = resultErr == nil && result.GuestGitClone && result.GuestNoSwap && result.ReleaseKeyID != ""
		result.FinishedAt = time.Now().UTC()
	}()
	bundle := filepath.Join(work, "source.bundle")
	if err := prepareColdReleaseBundle(ctx, options, bundle, result); err != nil {
		return result, err
	}
	guest, image, err := newVerifiedSeededGuest(ctx, manifest, options.CacheDir, work, false, &hardware, nil)
	if err != nil {
		return result, err
	}
	result.ImageSHA256 = image.SHA256
	if err := guest.connect(ctx); err != nil {
		return result, err
	}
	if _, err := coldReleaseCommand(ctx, guest, result, "cloud-init", "sudo -n cloud-init status --wait", nil, 15*time.Minute); err != nil {
		return result, err
	}
	if _, err := coldReleaseCommand(ctx, guest, result, "native-prerequisites", "sudo -n /bin/bash -s", strings.NewReader(productionSigningNativeSetup), 30*time.Minute); err != nil {
		return result, err
	}
	if err := prepareColdReleaseGuest(ctx, guest, result, options, bundle); err != nil {
		return result, err
	}
	if err := buildColdReleaseGuest(ctx, guest, result, options); err != nil {
		diagnosticContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Minute)
		defer cancel()
		return result, errors.Join(err, collectColdReleaseFiles(diagnosticContext, guest, result, options, true))
	}
	if err := exportColdReleases(ctx, guest, result, options); err != nil {
		return result, err
	}
	return result, nil
}

func prepareColdReleaseBundle(ctx context.Context, options VMDeployBuildOptions, destination string, result *VMDeployBuildResult) error {
	command := exec.CommandContext(ctx, "git", "-C", options.Repository, "rev-parse", "HEAD")
	output, err := command.Output()
	if err != nil || strings.TrimSpace(string(output)) != options.Revision {
		return errors.New("cold release source HEAD differs from independently pinned revision")
	}
	command = exec.CommandContext(ctx, "git", "-C", options.Repository, "show", "-s", "--format=%ct", options.Revision)
	output, err = command.Output()
	if err != nil {
		return err
	}
	result.SourceDateEpoch = strings.TrimSpace(string(output))
	if !coldReleaseEpoch.MatchString(result.SourceDateEpoch) {
		return errors.New("source commit epoch is invalid")
	}
	if err := exec.CommandContext(ctx, "git", "-C", options.Repository, "bundle", "create", destination, "HEAD").Run(); err != nil {
		return err
	}
	if err := os.Chmod(destination, 0600); err != nil {
		return err
	}
	file, err := openRegular(destination)
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	if err := errors.Join(copyErr, file.Close()); err != nil {
		return err
	}
	result.GitBundleSHA256 = hex.EncodeToString(hash.Sum(nil))
	return nil
}

func coldReleaseCommand(ctx context.Context, guest *guestVM, result *VMDeployBuildResult, name, command string, input io.Reader, timeout time.Duration) (guestCommandResult, error) {
	started := time.Now().UTC()
	output, err := guest.runResult(ctx, command, input, productionSigningLogLimit, timeout)
	if err == nil && output.ExitCode != 0 {
		err = fmt.Errorf("cold release stage %s exited %d", name, output.ExitCode)
	}
	result.Stages = append(result.Stages, VMProductionReleaseSigningStage{Name: name, StartedAt: started, FinishedAt: time.Now().UTC(), Passed: err == nil})
	return output, err
}

func prepareColdReleaseGuest(ctx context.Context, guest *guestVM, result *VMDeployBuildResult, options VMDeployBuildOptions, bundle string) error {
	root := productionSigningGuestRoot
	setup := "umask 077; mkdir " + nativeQuote(root) + "; mkdir " + nativeQuote(root+"/tools") + " " + nativeQuote(root+"/home") + " " + nativeQuote(root+"/go-cache") + " " + nativeQuote(root+"/go-mod") + " " + nativeQuote(root+"/go-path") + " " + nativeQuote(root+"/npm-cache")
	if _, err := coldReleaseCommand(ctx, guest, result, "empty-independent-workspace", setup, nil, time.Minute); err != nil {
		return err
	}
	for _, transfer := range []struct{ local, remote string }{{bundle, root + "/source.bundle"}, {options.OperatorRecipientFile, root + "/operator-recipient.txt"}} {
		file, err := openRegular(transfer.local)
		if err != nil {
			return err
		}
		_, transferErr := coldReleaseCommand(ctx, guest, result, "transfer-public-input", "umask 077; cat > "+nativeQuote(transfer.remote), file, 10*time.Minute)
		if err := errors.Join(transferErr, file.Close()); err != nil {
			return err
		}
	}
	clone := "set -eu; cd " + nativeQuote(root) + "; printf '%s  source.bundle\\n' " + nativeQuote(result.GitBundleSHA256) + " | sha256sum -c --strict; git init --bare bundle-verification.git; git -C bundle-verification.git bundle verify ../source.bundle; git clone --no-local source.bundle source; cd source; git checkout --detach " + nativeQuote(options.Revision) + "; test \"$(git rev-parse HEAD)\" = " + nativeQuote(options.Revision) + "; test -d .git"
	if _, err := coldReleaseCommand(ctx, guest, result, "actual-fresh-git-clone", clone, nil, 10*time.Minute); err != nil {
		return err
	}
	result.GuestGitClone = true
	if _, err := coldReleaseCommand(ctx, guest, result, "official-pinned-SDKs", "env -i PATH=/usr/bin:/bin HOME="+nativeQuote(root+"/home")+" LC_ALL=C /bin/bash -s", strings.NewReader(productionSigningInstallTools), 30*time.Minute); err != nil {
		return err
	}
	if _, err := coldReleaseCommand(ctx, guest, result, "pristine-guest-caches", productionSigningEnvironment()+" /bin/bash -s", strings.NewReader(productionSigningPristineCaches), time.Minute); err != nil {
		return err
	}
	versions, err := coldReleaseCommand(ctx, guest, result, "exact-tool-versions", productionSigningEnvironment()+" python3 -", strings.NewReader(productionSigningToolVersions), 2*time.Minute)
	if err != nil {
		return err
	}
	var tools map[string]string
	if err := json.Unmarshal(versions.Stdout, &tools); err != nil {
		return err
	}
	if tools["go"] != "go version go1.26.9 linux/amd64" || tools["node"] != "v24.21.0" || tools["npm"] == "" {
		return errors.New("cold guest SDK versions do not match immutable source pins")
	}
	if err := productionSigningWrite(filepath.Join(options.EvidenceDirectory, "guest-tool-versions.json"), versions.Stdout); err != nil {
		return err
	}
	if _, err := coldReleaseCommand(ctx, guest, result, "web-and-licenses", productionSigningEnvironment()+" /bin/bash -s", strings.NewReader(productionSigningBuildPrerequisites), 45*time.Minute); err != nil {
		return err
	}
	return nil
}

func buildColdReleaseGuest(ctx context.Context, guest *guestVM, result *VMDeployBuildResult, options VMDeployBuildOptions) error {
	root := productionSigningGuestRoot
	if _, err := coldReleaseCommand(ctx, guest, result, "no-swap-before-custody", "test \"$(wc -l < /proc/swaps)\" = 1", nil, time.Minute); err != nil {
		return err
	}
	result.GuestNoSwap = true
	build := "cd " + nativeQuote(root+"/source") + " && " + productionSigningEnvironment() + " go build -trimpath -o " + nativeQuote(root+"/cold-lab") + " ./cmd/lab"
	if _, err := coldReleaseCommand(ctx, guest, result, "matching-guest-lab-child", build, nil, 45*time.Minute); err != nil {
		return err
	}
	child := productionSigningEnvironment() + " " + nativeQuote(root+"/cold-lab") + " native cold-release-child -revision " + nativeQuote(options.Revision) + " -epoch " + nativeQuote(result.SourceDateEpoch) + " -first-version " + nativeQuote(options.FirstVersion) + " -newer-version " + nativeQuote(options.NewerVersion)
	output, err := coldReleaseCommand(ctx, guest, result, "literal-make-release-keys-and-two-releases", child, nil, 3*time.Hour)
	defer clear(output.Stdout)
	defer clear(output.Stderr)
	if err == nil {
		return nil
	}
	return errors.Join(err, writeDeployInstallerDiagnostics(options.OperatorRecipientFile, options.EvidenceDirectory, "cold-launch", output.Stdout, output.Stderr))
}

func exportColdReleases(ctx context.Context, guest *guestVM, result *VMDeployBuildResult, options VMDeployBuildOptions) error {
	if err := collectColdReleaseFiles(ctx, guest, result, options, false); err != nil {
		return err
	}
	return verifyColdReleaseExports(ctx, result, options)
}

func verifyColdReleaseExports(ctx context.Context, result *VMDeployBuildResult, options VMDeployBuildOptions) error {
	kit, err := releasekit.Load(filepath.Join(options.EvidenceDirectory, "keys"))
	if err != nil {
		return err
	}
	result.ReleaseKeyID = kit.AttestationKeyID
	for _, name := range []string{"first", "newer"} {
		if err := releasebuild.CanonicalizeEmbeddedRepository(filepath.Join(options.EvidenceDirectory, name)); err != nil {
			return err
		}
		manifest, err := releasebuild.Verify(ctx, filepath.Join(options.EvidenceDirectory, name), filepath.Join(options.EvidenceDirectory, "keys", releasekit.AttestationPublicFile), kit.AttestationKeyID)
		if err != nil {
			return err
		}
		expected := options.FirstVersion
		if name == "newer" {
			expected = options.NewerVersion
		}
		if manifest.GetVersion() != expected || manifest.GetRevision() != options.Revision {
			return errors.New("cold bundle revision/version does not match pinned actual clone")
		}
	}
	return nil
}

func collectColdReleaseFiles(ctx context.Context, guest *guestVM, result *VMDeployBuildResult, options VMDeployBuildOptions, failureOnly bool) error {
	root := productionSigningGuestRoot + "/export"
	listing, err := coldReleaseCommand(ctx, guest, result, "encrypted-public-export-list", "test -d "+nativeQuote(root)+" || exit 0; cd "+nativeQuote(root)+"; find . -type f -printf '%P\\0'", nil, time.Minute)
	if err != nil {
		return err
	}
	members := bytes.Split(listing.Stdout, []byte{0})
	if len(members) > 512 {
		return errors.New("cold release export has too many files")
	}
	for _, member := range members {
		name := string(member)
		if name == "" {
			continue
		}
		if !coldReleaseExportMember(name) {
			return errors.New("cold release export includes a nonpublic/nonencrypted member")
		}
		if failureOnly && (strings.HasPrefix(name, "first/") || strings.HasPrefix(name, "newer/")) {
			continue
		}
		path := filepath.Join(options.EvidenceDirectory, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		var digest string
		if err := copyDeployBackup(ctx, guest, root+"/"+name, path, &digest); err != nil {
			return err
		}
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		result.Evidence = append(result.Evidence, VMProductionReleaseSigningEvidence{Name: name, Path: path, SHA256: digest, Size: info.Size()})
	}
	return nil
}

func coldReleaseExportMember(name string) bool {
	if filepath.IsAbs(name) || filepath.Clean(name) != name || strings.Contains(name, "\\") {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) == 1 {
		return name == "production-custody-passphrase.age" || strings.HasSuffix(name, ".log.age")
	}
	if parts[0] == "first" || parts[0] == "newer" {
		return !strings.HasPrefix(parts[1], ".")
	}
	if parts[0] != "keys" || len(parts) != 2 {
		return false
	}
	for _, allowed := range []string{releasekit.AttestationPublicFile, releasekit.InventoryFile, releasekit.CAFile, releasekit.RootFile, "targets.json", "snapshot.json", "timestamp.json", "delegated.json", releasekit.PackagePublicFile, releasekit.BackupRecipientFile, releasekit.PinsFile, "pins.sig", releasekit.CustodyFile} {
		if parts[1] == allowed {
			return true
		}
	}
	return false
}

func coldReleaseVersionsValid(first, newer string) bool {
	return coldReleaseVersion.MatchString(first) && coldReleaseVersion.MatchString(newer) && semver.IsValid("v"+first) && semver.IsValid("v"+newer) && semver.Compare("v"+newer, "v"+first) > 0
}
