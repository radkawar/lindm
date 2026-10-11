package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"

	"lindm/internal/vmlab"
)

func runVMUpdates(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("vm updates", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "verified manifest of a release/architecture with a maintained update lane (internal/platform registry)")
	repository := flags.String("repo", ".", "checkout containing the existing development fixture")
	buildRepository := flags.String("build-repo", "", "source checkout with built embedded console; default is -repo")
	cache := flags.String("cache", ".cache/lab/images", "verified image cache")
	work := flags.String("work-dir", "", "existing private working parent")
	diagnostics := flags.String("diagnostics", "", "private owned failure diagnostics parent")
	record := flags.String("record", "", "write nonsecret evidence to a new private file")
	probe := flags.String("lab", "", "prebuilt guest lab probe; default is this executable")
	hardware := newVMHardwareFlags(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" || flags.NArg() != 0 {
		return errors.New("-manifest FILE is required; positional arguments are not accepted")
	}
	if *probe == "" {
		self, err := os.Executable()
		if err != nil {
			return err
		}
		*probe = self
	}
	manifest, err := vmlab.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	result, runErr := vmlab.UpdateVM(ctx, manifest, vmlab.VMUpdateOptions{Repository: *repository, BuildRepository: *buildRepository, CacheDir: *cache, WorkDir: *work, LabBinary: *probe, DiagnosticsDir: *diagnostics, Hardware: hardware.options()})
	if result == nil {
		return runErr
	}
	return errors.Join(runErr, writeLabEvidence(stdout, *record, result))
}
