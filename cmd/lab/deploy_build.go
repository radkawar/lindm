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

func runDeployBuildAdmitted(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("deploy build", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var options vmlab.VMDeployBuildOptions
	manifest := flags.String("manifest", "", "vendor-authenticated fresh Ubuntu 24.04 x86 server image")
	flags.StringVar(&options.Repository, "repo", ".", "actual committed integrated Git checkout; never a nongit source snapshot")
	flags.StringVar(&options.Revision, "revision", "", "independently pinned full source commit SHA matching HEAD")
	flags.StringVar(&options.CacheDir, "cache", ".cache/lab/images", "verified vendor image cache only")
	flags.StringVar(&options.WorkDir, "work-dir", "", "configured private native VM work directory")
	flags.StringVar(&options.EvidenceDirectory, "evidence", "", "new private cold-builder encrypted/public artifact directory")
	flags.StringVar(&options.OperatorRecipientFile, "operator-recipient-file", "", "explicit off-server lab operator age PUBLIC recipient; no private identity or passphrase")
	flags.StringVar(&options.FirstVersion, "first-version", "", "initial production release semantic version")
	flags.StringVar(&options.NewerVersion, "newer-version", "", "strictly newer production release semantic version")
	record := flags.String("record", "", "new private production-cold-release-build-only JSON record")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *manifest == "" || *record == "" || options.EvidenceDirectory == "" || options.OperatorRecipientFile == "" {
		return errors.New("deploy build requires exact source revision, versions, vendor manifest, operator PUBLIC recipient, evidence and record")
	}
	if err := resolvePackagePaths(&options.Repository, &options.CacheDir, &options.WorkDir, &options.EvidenceDirectory, &options.OperatorRecipientFile, record); err != nil {
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
	image, err := vmlab.LoadManifest(*manifest)
	if err != nil {
		return err
	}
	result, runErr := vmlab.RunVMDeployBuild(ctx, image, options)
	return errors.Join(runErr, writeLabEvidence(stdout, *record, result))
}

func runDeployColdGuest(ctx context.Context, args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("native cold-release-child", flag.ContinueOnError)
	flags.SetOutput(stderr)
	revision := flags.String("revision", "", "actual cloned exact source commit")
	epoch := flags.String("epoch", "", "actual commit source date epoch")
	first := flags.String("first-version", "", "initial release version")
	newer := flags.String("newer-version", "", "newer release version")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("cold guest does not accept positional or secret inputs")
	}
	return vmlab.RunDeployBuildGuest(ctx, *revision, *epoch, *first, *newer)
}
