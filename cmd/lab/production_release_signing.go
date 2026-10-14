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

func runVMProductionReleaseSigning(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("vm production-release-signing", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "pinned Ubuntu 24.04 amd64 disposable guest image")
	repository := flags.String("repo", ".", "source checkout; only public source bytes enter the guest")
	cache := flags.String("cache", ".cache/lab/images", "verified image cache")
	work := flags.String("work-dir", "", "parent for disposable no-swap guest")
	probe := flags.String("lab", "", "built lab executable; defaults to this executable")
	diagnostics := flags.String("diagnostics", "", "existing private diagnostics directory")
	record := flags.String("record", "", "new tests-only evidence file; not lifecycle evidence")
	hardware := newVMHardwareFlags(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *manifestPath == "" || *record == "" {
		return errors.New("vm production-release-signing requires -manifest and -record; no positional arguments")
	}
	manifest, err := vmlab.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	binary := *probe
	if binary == "" {
		binary, err = os.Executable()
		if err != nil {
			return err
		}
	}
	selected := hardware.options()
	selected.MemoryMiB, selected.CPUs = vmlab.ProductionReleaseSigningMemoryMiB, 2
	result, runErr := vmlab.RunVMProductionReleaseSigning(ctx, manifest, vmlab.VMProductionReleaseSigningOptions{Repository: *repository, CacheDir: *cache, WorkDir: *work, LabBinary: binary, DiagnosticsDir: *diagnostics, Hardware: selected})
	if result != nil {
		runErr = errors.Join(runErr, writeLabEvidence(stdout, *record, result))
	}
	return runErr
}
