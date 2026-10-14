// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"

	"lindm/internal/vmlab"
)

func runVMAdvisories(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("vm advisories", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "pinned guest manifest with a maintained primary vendor advisory export")
	server := flags.String("lindmd", "", "built real lindmd executable")
	probe := flags.String("lab", "", "guest-architecture lab probe; defaults to this executable")
	repository := flags.String("repo", ".", "checkout and running development dependencies")
	buildRepository := flags.String("build-repo", "", "package source checkout; defaults to -repo")
	cache := flags.String("cache", ".cache/lab/images", "verified image and revalidated vendor feed cache")
	work := flags.String("work-dir", "", "parent for disposable VM and signed packages")
	diagnostics := flags.String("diagnostics", "", "private failure diagnostics parent")
	record := flags.String("record", "", "new private evidence file, including unsupported feed outcomes")
	redhatToken := flags.String("redhat-token-file", "", "protected Red Hat offline-token file; required for RHEL, whose CSAF stream matching needs the registered BaseOS/AppStream repositories")
	hardware := newVMHardwareFlags(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *manifestPath == "" || *server == "" {
		return errors.New("vm advisories requires -manifest and -lindmd; no positional arguments")
	}
	manifest, err := vmlab.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	if *probe == "" {
		*probe, err = os.Executable()
		if err != nil {
			return err
		}
	}
	result, runErr := vmlab.DispatchVM(ctx, manifest, vmlab.VMDispatchOptions{
		Repository: *repository, BuildRepository: *buildRepository, CacheDir: *cache, WorkDir: *work,
		DiagnosticsDir: *diagnostics, Hardware: hardware.options(), LabBinary: *probe, LindmdBinary: *server,
		RedHatTokenFile: *redhatToken, LocalAuthority: true, Advisories: true,
	})
	if result != nil {
		runErr = errors.Join(runErr, writeLabEvidence(stdout, *record, result))
	}
	return runErr
}
