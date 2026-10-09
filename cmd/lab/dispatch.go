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

func runVMDispatch(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("vm dispatch", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "pinned Ubuntu or Fedora image manifest")
	server := flags.String("lindmd", "", "built real lindmd executable")
	repository := flags.String("repo", ".", "checkout and running development dependencies")
	cache := flags.String("cache", ".cache/lab/images", "verified image cache")
	work := flags.String("work-dir", "", "parent for disposable VM and signed packages")
	diagnostics := flags.String("diagnostics", "", "existing private directory for failure diagnostics")
	record := flags.String("record", "", "new private nonsecret evidence file, including incomplete scenarios")
	hold := flags.Duration("hold", 0, "hold the live console before revocation for up to one hour; timeout or SIGINT resumes revocation and cleanup")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *manifestPath == "" || *server == "" {
		return errors.New("vm dispatch requires -manifest and -lindmd; no positional arguments")
	}
	manifest, err := vmlab.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	result, runErr := vmlab.DispatchVM(ctx, manifest, vmlab.VMDispatchOptions{Repository: *repository, CacheDir: *cache, WorkDir: *work, DiagnosticsDir: *diagnostics, LabBinary: binary, LindmdBinary: *server, Hold: *hold, Progress: stderr})
	if result != nil {
		runErr = errors.Join(runErr, writeLabEvidence(stdout, *record, result))
	}
	return runErr
}
