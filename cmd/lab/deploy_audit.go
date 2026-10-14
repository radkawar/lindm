// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"

	"lindm/internal/packaging"
	"lindm/internal/vmlab"
)

func runDeployAuditAdmitted(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("deploy audit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var options vmlab.VMDeployAuditOptions
	manifestPath := flags.String("manifest", "", "pinned fresh Ubuntu24.04 or entitled RHEL9 x86 image")
	repository := flags.String("repo", ".", "checkout containing maintained real browser audit driver")
	flags.StringVar(&options.CacheDir, "cache", ".cache/lab/images", "verified vendor image cache")
	flags.StringVar(&options.WorkDir, "work-dir", "", "configured native lab work directory")
	flags.StringVar(&options.EvidenceDir, "evidence", "", "new private persistent audit evidence directory")
	flags.StringVar(&options.Release, "baseline-release", "", "authenticated immutable pre-turnkey export")
	flags.StringVar(&options.BaselineVerifier, "baseline-verifier", "", "private frozen lab executable built from exact immutable pre-feature source; audit only")
	flags.StringVar(&options.BaselineVerifierSHA256, "baseline-verifier-sha256", "", "independently pinned frozen verifier executable SHA256; no current verifier fallback")
	flags.StringVar(&options.ReleasePublicKey, "release-public-key", "", "independently authenticated release public key")
	flags.StringVar(&options.ReleaseKeyID, "release-key-id", "", "independently pinned release attestation key ID")
	flags.StringVar(&options.PackagePublicKeySHA256, "package-public-key-sha256", "", "independently pinned historical package public key SHA256; required for RPM, not covered by the old signed manifest")
	flags.StringVar(&options.LabBinary, "lab", "", "matching prebuilt native observer; this executable by default")
	flags.StringVar(&options.RedHatTokenFile, "redhat-token-file", "", "protected Red Hat offline-token file; never print its contents")
	flags.StringVar(&options.Signer.Home, "signer-home", "", "off-server isolated signing home to publish authenticated native APT metadata")
	flags.StringVar(&options.Signer.Fingerprint, "fingerprint", "", "independently pinned native package signer")
	flags.StringVar(&options.Signer.PassphraseFile, "passphrase-file", "", "protected production signer passphrase input")
	development := flags.Bool("development-key", false, "explicitly use development custody and record it as such")
	record := flags.String("record", "", "new nonsecret audit operation/count/friction record")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *manifestPath == "" || *record == "" || options.EvidenceDir == "" || options.Release == "" || options.ReleasePublicKey == "" || options.ReleaseKeyID == "" || options.BaselineVerifier == "" || options.BaselineVerifierSHA256 == "" {
		return errors.New("deploy audit requires -manifest, -baseline-release, independent -baseline-verifier/-baseline-verifier-sha256, explicit -release-public-key/-release-key-id, -evidence and -record")
	}
	options.Signer.Custody = packaging.CustodyProduction
	if *development {
		options.Signer.Custody = packaging.CustodyDevelopment
	}
	if options.LabBinary == "" {
		var err error
		options.LabBinary, err = os.Executable()
		if err != nil {
			return err
		}
	}
	if err := resolvePackagePaths(repository, &options.CacheDir, &options.WorkDir, &options.EvidenceDir, &options.Release, &options.ReleasePublicKey, &options.LabBinary, &options.RedHatTokenFile, &options.Signer.Home, &options.Signer.PassphraseFile, &options.BaselineVerifier, record); err != nil {
		return err
	}
	if err := os.Mkdir(options.EvidenceDir, 0700); err != nil {
		return err
	}
	manifest, err := vmlab.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	options.Browser = deployBrowser(*repository)
	result, runErr := vmlab.DeployAuditVM(ctx, manifest, options)
	return errors.Join(runErr, writeLabEvidence(stdout, *record, result))
}
