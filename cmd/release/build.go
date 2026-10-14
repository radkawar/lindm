// SPDX-License-Identifier: Apache-2.0
//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"lindm/internal/custody"
	"lindm/internal/packaging"
	"lindm/internal/releasebuild"
	"lindm/internal/releasekit"
)

func runBuild(ctx context.Context, args []string, stdout, stderr io.Writer) (err error) {
	flags := flag.NewFlagSet("release build", flag.ContinueOnError)
	flags.SetOutput(stderr)
	repository := flags.String("repo", ".", "source checkout; complete production matrix is built twice")
	directory := flags.String("keys", "release-keys", "independent operator key custody directory")
	output := flags.String("output", "artifacts/release", "new complete bundle directory; refuses overwrite")
	version := flags.String("version", "0.1.0", "semantic package version")
	revision := flags.String("revision", "", "release label; defaults to source HEAD")
	epoch := flags.Int64("source-date-epoch", 0, "reproducible timestamp; defaults to source HEAD commit time")
	passFD := flags.Int("passphrase-fd", -1, "owner-private anonymous pipe with one LF-terminated unlock passphrase")
	identityFD := flags.Int("identity-fd", -1, "owner-private anonymous pipe with the operator's age X25519 identity")
	offline := flags.String("offline", "", "comma-separated optional dependency snapshots: ubuntu-24.04,rhel-9; connected default needs neither")
	cache := flags.String("snapshot-cache", "", "explicit native dependency snapshot cache for selected offline add-ons")
	ubuntu := flags.String("ubuntu-snapshot", "", "independently authenticated Ubuntu snapshot digest")
	rhel := flags.String("rhel-snapshot", "", "independently authenticated entitled RHEL snapshot digest")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || (*passFD >= 0 && *identityFD >= 0) {
		return errors.New("build takes no positional arguments; passphrase and identity modes are exclusive")
	}
	inputs, err := installerInputs(*offline, *cache, *ubuntu, *rhel)
	if err != nil {
		return err
	}
	if err := absolutePaths(repository, directory, output); err != nil {
		return err
	}
	if err := refuseCapturedCustody(ctx, *repository, *directory); err != nil {
		return err
	}
	public, err := releasekit.Load(*directory)
	if err != nil {
		return err
	}
	*revision, *epoch, err = sourceStamp(ctx, *repository, *revision, *epoch)
	if err != nil {
		return err
	}
	stage, err := prepareBundleOutput(*output)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
	if err := protectSecrets(); err != nil {
		return err
	}
	var input *custody.SecretBuffer
	if *identityFD >= 0 {
		input, err = readIdentity(ctx, *identityFD)
	} else {
		input, err = readPassphrase(ctx, *passFD, false)
	}
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	var passphrase, identity []byte
	if *identityFD >= 0 {
		identity = input.Bytes()
	} else {
		passphrase = input.Bytes()
	}
	secrets, err := releasekit.Unlock(ctx, *directory, passphrase, identity)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, secrets.Close()) }()
	work, err := os.MkdirTemp("", "lindm-release-custodian-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(work)) }()
	packageKey, closeSigner, err := packaging.ImportProductionSigner(ctx, work, secrets.PackageSecret, secrets.PackagePassphrase)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, closeSigner()) }()
	if packageKey.Fingerprint != public.PackageFingerprint {
		return errors.New("package custodian does not match independent kit fingerprint")
	}
	inputs.TUFRoot = filepath.Join(*directory, "root.json")
	root, err := readRegular(inputs.TUFRoot, 4<<20)
	if err != nil {
		return err
	}
	inputs.TUFRootSHA256 = sha256Hex(root)
	manifest, err := releasebuild.Build(ctx, releasebuild.Request{
		Repository: *repository, Output: stage, Version: *version, Revision: *revision, SourceDateEpoch: *epoch,
		PackageSigner: *packageKey,
		AttestationSigner: releasebuild.AttestationKey{
			PrivateKeyPEM: secrets.AttestationPEM, Purpose: secrets.Purpose, KeyID: public.AttestationKeyID, Custody: "production",
			TrustInventory: filepath.Join(*directory, "inventory.json"), TrustInventorySHA256: public.InventorySHA256,
		},
		OCICABundle: filepath.Join(*directory, "ca-certificates.crt"), OCICASHA256: public.CASHA256, Installer: inputs,
	})
	if err != nil {
		return err
	}
	if manifest.GetCustody() != "production" {
		return errors.New("refuse non-production release output")
	}
	if err := verifyBundle(ctx, stage, *directory, public); err != nil {
		return err
	}
	if err := writeSHA256SUMS(stage); err != nil {
		return err
	}
	if err := publishVerifiedBundle(stage, *output); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Verified production bundle: %s\nSHA256SUMS: %s\nKeep private custody at %s; it is not in this bundle.\nVerify on the target with the independent attestation public key and SPKI pin before executing install.sh.\n", *output, filepath.Join(*output, "SHA256SUMS"), *directory)
	return err
}

func sourceStamp(ctx context.Context, repository, revision string, epoch int64) (string, int64, error) {
	var err error
	if revision == "" {
		revision, err = gitValue(ctx, repository, "rev-parse", "HEAD")
		if err != nil {
			return "", 0, err
		}
	}
	if epoch == 0 {
		stamp, err := gitValue(ctx, repository, "show", "-s", "--format=%ct", "HEAD")
		if err != nil {
			return "", 0, err
		}
		epoch, err = strconv.ParseInt(stamp, 10, 64)
		if err != nil {
			return "", 0, err
		}
	}
	return revision, epoch, nil
}

func prepareBundleOutput(output string) (string, error) {
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("release output must not exist")
	}
	if err := os.MkdirAll(filepath.Dir(output), 0700); err != nil {
		return "", err
	}
	reserved, err := os.CreateTemp(filepath.Dir(output), ".lindm-verified-release-")
	if err != nil {
		return "", err
	}
	stage := reserved.Name()
	if err := errors.Join(reserved.Close(), os.Remove(stage)); err != nil {
		return "", err
	}
	return stage, nil
}

func publishVerifiedBundle(stage, output string) (err error) {
	completed, err := os.Open(stage)
	if err != nil {
		return err
	}
	if err := errors.Join(completed.Sync(), completed.Close()); err != nil {
		return err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, stage, unix.AT_FDCWD, output, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(output))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, parent.Close()) }()
	return parent.Sync()
}

func installerInputs(offline, cache, ubuntu, rhel string) (*releasebuild.InstallerInputs, error) {
	inputs := &releasebuild.InstallerInputs{SnapshotCache: cache}
	selected := map[string]bool{}
	if offline != "" {
		for _, platform := range strings.Split(offline, ",") {
			if selected[platform] {
				return nil, fmt.Errorf("duplicate offline platform %q", platform)
			}
			selected[platform] = true
			switch platform {
			case "ubuntu-24.04":
				inputs.UbuntuSnapshot = ubuntu
			case "rhel-9":
				inputs.RHELSnapshot = rhel
			default:
				return nil, fmt.Errorf("unsupported offline platform %q; use ubuntu-24.04 or rhel-9", platform)
			}
			if cache == "" || (platform == "ubuntu-24.04" && ubuntu == "") || (platform == "rhel-9" && rhel == "") {
				return nil, fmt.Errorf("offline %s requires --snapshot-cache and its independently authenticated snapshot digest", platform)
			}
		}
	}
	if (!selected["ubuntu-24.04"] && ubuntu != "") || (!selected["rhel-9"] && rhel != "") || (offline == "" && cache != "") {
		return nil, errors.New("snapshot inputs require the matching explicit --offline platform selection")
	}
	return inputs, nil
}

func gitValue(ctx context.Context, directory string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, "git", args...)
	command.Dir = directory
	var result boundedOutput
	command.Stdout = &result
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("read source git identity: %w", err)
	}
	return strings.TrimSpace(result.String()), nil
}

func refuseCapturedCustody(ctx context.Context, repository, keys string) error {
	relative, err := filepath.Rel(repository, keys)
	if err != nil {
		return err
	}
	if relative == "." {
		return errors.New("custody directory cannot be the source checkout")
	}
	if relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		command := exec.CommandContext(ctx, "git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", relative)
		command.Dir = repository
		var selected boundedOutput
		command.Stdout = &selected
		if err := command.Run(); err != nil {
			return fmt.Errorf("inspect selected source custody paths: %w", err)
		}
		if selected.Len() != 0 {
			return errors.New("custody directory has files selected for source capture; untrack and gitignore it, or move it outside the checkout")
		}
	}
	return nil
}

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(data []byte) (int, error) {
	if len(data) > 4096-b.Len() {
		return 0, errors.New("release: source identity listing exceeds bound")
	}
	return b.Buffer.Write(data)
}
