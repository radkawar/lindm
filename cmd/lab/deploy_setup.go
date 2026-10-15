// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"

	"lindm/internal/custody"
	"lindm/internal/vmlab"
)

// runDeploySetupAdmitted is a one-guest install/first-owner observation only.
// It neither needs nor accepts newer releases or private backup identity inputs.
func runDeploySetupAdmitted(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("deploy setup", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var options vmlab.VMDeploySetupOptions
	manifestPath := flags.String("manifest", "", "pinned exact fresh x86_64 cloud image for a registry-supported native server host; connected-only hosts cannot use -airgap")
	flags.StringVar(&options.Repository, "repo", ".", "checkout containing the maintained real browser driver")
	flags.StringVar(&options.CacheDir, "cache", ".cache/lab/images", "verified vendor image cache")
	flags.StringVar(&options.WorkDir, "work-dir", "", "configured native lab work directory")
	flags.StringVar(&options.EvidenceDirectory, "evidence", "", "new private persistent first-run-only evidence directory")
	flags.StringVar(&options.LabBinary, "lab", "", "matching prebuilt native observer; this executable by default")
	flags.StringVar(&options.FirstRelease, "first-release", "", "single private signed production or development turnkey release export")
	flags.BoolVar(&options.Airgap, "airgap", false, "install the signed host-platform offline add-on with guest external networking denied; first-run-only evidence")
	flags.StringVar(&options.ReleasePublicKey, "release-public-key", "", "independently authenticated release attestation public key")
	flags.StringVar(&options.ReleaseKeyID, "release-key-id", "", "independently pinned release attestation key ID")
	flags.StringVar(&options.TUFRootFile, "tuf-root-file", "", "independently authenticated signed release-update root")
	flags.StringVar(&options.BackupRecipientFile, "backup-recipient-file", "", "backup age public recipient only; no private identity")
	flags.StringVar(&options.CustodyEscrowRecipientFile, "custody-escrow-recipient-file", "", "explicit lab operator public age recipient for memory-only quickstart passphrase escrow")
	flags.StringVar(&options.RedHatTokenFile, "redhat-token-file", "", "protected available Red Hat offline-token input; never print contents")
	record := flags.String("record", "", "new private nonsecret first-run-install-only record; never a full lifecycle qualification")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *manifestPath == "" || *record == "" || options.EvidenceDirectory == "" || options.FirstRelease == "" || options.ReleasePublicKey == "" || options.ReleaseKeyID == "" || options.TUFRootFile == "" || options.BackupRecipientFile == "" || options.CustodyEscrowRecipientFile == "" {
		return errors.New("deploy setup requires -manifest, -first-release, independent release/TUF pins, backup public recipient, lab custody escrow public recipient, -evidence and -record; no positional or private backup inputs")
	}
	if options.LabBinary == "" {
		var err error
		options.LabBinary, err = os.Executable()
		if err != nil {
			return err
		}
	}
	if err := resolvePackagePaths(&options.Repository, &options.CacheDir, &options.WorkDir, &options.EvidenceDirectory, &options.LabBinary, &options.FirstRelease, &options.ReleasePublicKey, &options.TUFRootFile, &options.BackupRecipientFile, &options.CustodyEscrowRecipientFile, &options.RedHatTokenFile, record); err != nil {
		return err
	}
	if err := prepareDeployCustodianMemory(ctx, options.Repository); err != nil {
		return err
	}
	if err := custody.LockSecretMemory(); err != nil {
		return err
	}
	if err := os.Mkdir(options.EvidenceDirectory, 0700); err != nil {
		return err
	}
	manifest, err := vmlab.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	options.Browser = deployBrowser(options.Repository)
	result, runErr := vmlab.DeploySetupVM(ctx, manifest, options)
	return errors.Join(runErr, writeLabEvidence(stdout, *record, result))
}
