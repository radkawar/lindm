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

func runVMDispatch(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("vm dispatch", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "pinned supported native distribution image manifest")
	server := flags.String("lindmd", "", "built real lindmd executable")
	probe := flags.String("lab", "", "guest-architecture lab probe executable; defaults to this executable")
	repository := flags.String("repo", ".", "checkout and running development dependencies")
	buildRepository := flags.String("build-repo", "", "package source checkout (default: -repo); does not relocate development fixtures")
	cache := flags.String("cache", ".cache/lab/images", "verified image cache")
	work := flags.String("work-dir", "", "parent for disposable VM and signed packages")
	diagnostics := flags.String("diagnostics", "", "existing private directory for failure diagnostics")
	redhatToken := flags.String("redhat-token-file", "", "protected Red Hat offline-token file; optional for offline RPM installs, required for RHEL repository access")
	record := flags.String("record", "", "new private nonsecret evidence file, including incomplete scenarios")
	hold := flags.Duration("hold", 0, "hold the live console before revocation for up to one hour; timeout or SIGINT resumes revocation and cleanup")
	localAuthority := flags.Bool("local-authority", false, "use isolated local password/WebAuthn authority instead of Keycloak")
	powerActions := flags.Bool("power-actions", false, "qualify signed restart, refresh inventory and shutdown instead of service scenarios")
	runtimeAuthorization := flags.Bool("runtime-authorization", false, "qualify runtime authorization and browser organization apply with two local humans on Ubuntu 24.04")
	advisoryExceptions := flags.Bool("advisory-exceptions", false, "qualify native findings and exact two-human risk acceptance with refusal evidence; requires -local-authority")
	hardware := newVMHardwareFlags(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *manifestPath == "" || *server == "" {
		return errors.New("vm dispatch requires -manifest and -lindmd; no positional arguments")
	}
	if *runtimeAuthorization && *record == "" {
		return errors.New("runtime authorization qualification requires a new -record evidence path")
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
	result, runErr := vmlab.DispatchVM(ctx, manifest, vmlab.VMDispatchOptions{Repository: *repository, BuildRepository: *buildRepository, CacheDir: *cache, WorkDir: *work, DiagnosticsDir: *diagnostics, Hardware: hardware.options(), LabBinary: binary, LindmdBinary: *server, RedHatTokenFile: *redhatToken, Hold: *hold, Progress: stderr, LocalAuthority: *localAuthority, PowerActions: *powerActions, RuntimeAuthorization: *runtimeAuthorization, AdvisoryExceptions: *advisoryExceptions})
	if result != nil {
		recordErr := writeLabEvidence(stdout, *record, result)
		runErr = errors.Join(runErr, recordErr)
		if *runtimeAuthorization && recordErr == nil {
			runErr = errors.Join(runErr, os.Chmod(*record, 0400))
		}
	}
	return runErr
}
