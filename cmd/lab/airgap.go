//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"
	"time"

	"lindm/internal/devlab"
	"lindm/internal/labexec"
	"lindm/internal/vmlab"
)

// runVMAirgap is a two-stage lane. Without -network-container it creates an
// exact-owned loopback-only Docker network namespace and re-runs this command
// inside it as the invoking user (sudo is used only for nsenter). Inside, the
// server, its dedicated PostgreSQL, the guest's QEMU and this process share
// that namespace; nothing in it has a route off the host.
func runVMAirgap(ctx context.Context, args []string, stdout, stderr io.Writer, site bool) error {
	flags := flag.NewFlagSet("vm airgap", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var options vmlab.VMAirgapOptions
	manifestPath := flags.String("manifest", "", "verified manifest with a maintained airgap lane (image must already be cached)")
	flags.StringVar(&options.Repository, "repo", ".", "checkout containing the development fixture trust")
	flags.String("build-repo", "", "source checkout for remote binary staging; default is -repo")
	flags.StringVar(&options.CacheDir, "cache", ".cache/lab/images", "verified image cache")
	flags.StringVar(&options.WorkDir, "work-dir", "", "existing private working parent on the bundles' filesystem")
	flags.StringVar(&options.DiagnosticsDir, "diagnostics", "", "private owned failure diagnostics parent")
	flags.StringVar(&options.LabBinary, "lab", "", "prebuilt guest lab probe; default is this executable")
	flags.StringVar(&options.ServerBinary, "lindmd", "", "prebuilt release-stamped lindmd")
	flags.StringVar(&options.FirstBundle, "first-bundle", "", "signed bundle imported before the site server starts")
	flags.StringVar(&options.SecondBundle, "second-bundle", "", "signed newer bundle imported while serving")
	flags.StringVar(&options.ExpiredBundle, "expired-bundle", "", "optional signed bundle that has expired")
	flags.StringVar(&options.ReplayBundle, "replay-bundle", "", "optional valid bundle sequenced between first and second")
	flags.StringVar(&options.BundlePublicKey, "bundle-public-key", "", "pinned bundle-signing public key PEM")
	flags.StringVar(&options.BundleKeyID, "bundle-key-id", "", "pinned bundle-signing key ID")
	flags.StringVar(&options.ReleasePublicKey, "release-public-key", "", "pinned release attestation public key PEM")
	flags.StringVar(&options.ReleaseKeyID, "release-key-id", "", "pinned release attestation key ID")
	flags.StringVar(&options.ReleaseRoot, "release-root", "", "station TUF root JSON")
	flags.StringVar(&options.ReleaseOnlineCustody, "release-online-keys", "", "directory with only rollout.pem, snapshot.pem and timestamp.pem")
	flags.StringVar(&options.PackagePublicKey, "package-public-key", "", "ASCII-armored station package-signing public key")
	flags.StringVar(&options.PackageFingerprint, "package-fingerprint", "", "pinned package-signing fingerprint")
	flags.StringVar(&options.Advisories, "advisories", "", "site AdvisoryConfig protobuf JSON (feeds identical to the bundles')")
	flags.StringVar(&options.NetworkContainer, "network-container", "", "internal: namespace holder already entered")
	record := flags.String("record", "", "write nonsecret evidence to a new private file")
	hardware := newVMHardwareFlags(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" || options.ServerBinary == "" || options.FirstBundle == "" || options.SecondBundle == "" || options.WorkDir == "" || flags.NArg() != 0 {
		return errors.New("vm airgap requires -manifest, -lindmd, -first-bundle, -second-bundle, -work-dir and the pinned authority flags")
	}
	if !site {
		if options.NetworkContainer != "" {
			return errors.New("-network-container is internal to the isolated site stage")
		}
		return enterIsolatedSite(ctx, args, stdout, stderr)
	}
	if options.NetworkContainer == "" {
		return errors.New("isolated site stage requires its namespace holder")
	}
	if options.LabBinary == "" {
		self, err := os.Executable()
		if err != nil {
			return err
		}
		options.LabBinary = self
	}
	manifest, err := vmlab.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	options.Hardware = hardware.options()
	result, runErr := vmlab.AirgapVM(ctx, manifest, options)
	if result == nil {
		return runErr
	}
	return errors.Join(runErr, writeLabEvidence(stdout, *record, result))
}

func enterIsolatedSite(ctx context.Context, args []string, stdout, stderr io.Writer) (err error) {
	network, err := devlab.OpenIsolatedNetwork(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, network.Close()) }()
	self, err := os.Executable()
	if err != nil {
		return err
	}
	environment := []string{"HOME=" + os.Getenv("HOME"), "PATH=" + os.Getenv("PATH")}
	for _, name := range []string{"LINDM_LAB_CONFIG", "TMPDIR"} {
		if value, ok := os.LookupEnv(name); ok {
			environment = append(environment, name+"="+value)
		}
	}
	command := []string{"-n", "nsenter", "--net=" + network.NamespacePath(), "--", "setpriv", "--reuid=" + strconv.Itoa(os.Getuid()), "--regid=" + strconv.Itoa(os.Getgid()), "--init-groups", "--", "env", "-i"}
	command = append(command, environment...)
	// The site stage is unscheduled: this outer lane already holds the slot.
	command = append(command, self, "airgap-site", "-network-container", network.ContainerID)
	command = append(command, args...)
	// Cancellation lets the site stage run its owned cleanup before the group dies.
	if err := labexec.Run(ctx, labexec.Command{Path: "sudo", Args: command, Stdout: stdout, Stderr: stderr, Interrupt: syscall.SIGTERM, Grace: 3 * time.Minute}); err != nil {
		return fmt.Errorf("isolated site lane in namespace holder %s: %w", network.ContainerID, err)
	}
	return nil
}
