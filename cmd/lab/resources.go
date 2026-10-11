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

// Resource qualification reuses DispatchVM's isolated database, authenticated
// enrollment and installed native packages. It never attaches to a live demo.
func runVMResources(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("vm resources", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "pinned Ubuntu 22.04/24.04/26.04, Debian 12/13, Fedora 44 or RHEL/AlmaLinux/Rocky 9/10 image manifest")
	redhatToken := flags.String("redhat-token-file", "", "protected Red Hat offline-token file; required for RHEL repository access (maintained registration, unregistration and activation-key deletion)")
	server := flags.String("lindmd", "", "built real lindmd executable")
	probe := flags.String("lab", "", "built lab executable; defaults to this executable")
	repository := flags.String("repo", ".", "private checkout with running development dependencies")
	buildRepository := flags.String("build-repo", "", "package source checkout; defaults to -repo")
	cache := flags.String("cache", ".cache/lab/images", "verified image cache")
	work := flags.String("work-dir", "", "parent for memory-guarded disposable VM and signed package lease")
	diagnostics := flags.String("diagnostics", "", "existing private failure diagnostics directory")
	record := flags.String("record", "", "new private evidence file with per-kind outcomes and SHA256 native records")
	localAuthority := flags.Bool("local-authority", false, "isolated local password/WebAuthn authority instead of Keycloak")
	kinds := flags.String("kinds", "packages,files", "connected kind groups: packages,files,accounts,sysctl,definitions,password,firewall,secret-password,local-admin (firewall boots a second probe-peer guest; secret-password and local-admin configure escrow custody and prove SSH password logins; local-admin requires -local-authority)")
	phase := flags.String("phase", "executor", "executor: signed native bootstrap without profile gate bypass; connected: real server assignment/release after qualification")
	hardware := newVMHardwareFlags(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *manifestPath == "" || *server == "" || *record == "" {
		return errors.New("vm resources requires -manifest, -lindmd and -record; no positional arguments")
	}
	if *phase != "executor" && *phase != "connected" {
		return errors.New("resource qualification phase must be executor or connected")
	}
	selected, err := vmlab.ResourceKindSelection(*kinds)
	if err != nil {
		return err
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
	result, runErr := vmlab.DispatchVM(ctx, manifest, vmlab.VMDispatchOptions{Repository: *repository, BuildRepository: *buildRepository, CacheDir: *cache, WorkDir: *work, DiagnosticsDir: *diagnostics, Hardware: hardware.options(), LabBinary: binary, LindmdBinary: *server, RedHatTokenFile: *redhatToken, LocalAuthority: *localAuthority, Resources: true, ResourceExecutionOnly: *phase == "executor", ResourceKinds: selected})
	if result != nil {
		runErr = errors.Join(runErr, writeLabEvidence(stdout, *record, result))
	}
	return runErr
}
