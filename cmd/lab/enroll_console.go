// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"

	"lindm/internal/labhost"
	"lindm/internal/platform"
	"lindm/internal/vmlab"
)

func runVMEnrollFromConsole(ctx context.Context, args []string, stdout, stderr io.Writer) (resultErr error) {
	flags := flag.NewFlagSet("vm enroll-from-console", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var options vmlab.VMConsoleEnrollmentOptions
	manifestPath := flags.String("manifest", "", "signed manifest for a registry-admitted console enrollment lane")
	record := flags.String("record", "", "required new nonsecret evidence JSON, written only after cleanup")
	repository := flags.String("repo", ".", "checkout under test containing the maintained browser runner")
	browserConfig := flags.String("browser-config", "", "required owned mode0600 Chromium owner config for clipboard capture and server-side enrollment confirmation")
	flags.StringVar(&options.CacheDir, "cache", ".cache/lab/images", "verified vendor image cache")
	flags.StringVar(&options.WorkDir, "work-dir", "", "parent for owned disposable guest state")
	flags.StringVar(&options.LabBinary, "lab-binary", "", "matching guest-architecture read-only lab observer")
	flags.StringVar(&options.AdminAddress, "admin-address", "", "optional guest-to-host IPv4 loopback forward preserving exact console origin port")
	flags.StringVar(&options.DeviceAddress, "device-address", "", "optional guest-to-host IPv4 loopback forward preserving exact device origin port")
	flags.StringVar(&options.RedHatTokenFile, "redhat-token-file", "", "protected Red Hat offline-token file; required for RHEL, which reaches its vendor repositories only when registered")
	flags.StringVar(&options.DiagnosticsDir, "diagnostics", "", "existing private directory for the native package-manager log of a failed copied command")
	hardware := newVMHardwareFlags(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *manifestPath == "" || *record == "" || *browserConfig == "" || options.LabBinary == "" {
		return errors.New("enroll-from-console requires -manifest, -record, -lab-binary and -browser-config; no positional arguments")
	}
	manifest, err := vmlab.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	private, err := os.MkdirTemp(options.WorkDir, "lindm-console-copy-")
	if err != nil {
		return err
	}
	defer func() {
		if private != "" {
			resultErr = errors.Join(resultErr, os.RemoveAll(private))
		}
	}()
	options.Hardware = hardware.options()
	options.CommandFile = filepath.Join(private, "clipboard-command")
	var capture *consoleBrowserCapture
	var enrollment *consoleBrowserEnrollment
	options.Ready = func() error {
		if _, err := fmt.Fprintln(stderr, "Fresh guest ready: capturing the production console Copy command and screenshots in Chromium."); err != nil {
			return err
		}
		capture, err = captureConsoleBrowser(ctx, *repository, private, *browserConfig, options.CommandFile, manifest)
		return err
	}
	options.VerifyEnrollment = func(ctx context.Context, result *vmlab.VMConsoleEnrollmentResult) error {
		if capture == nil || capture.SHA256 != result.CommandSHA256 {
			return errors.New("executed command differs from the browser clipboard capture")
		}
		// A stock image the lab otherwise repairs keeps its group-writable /
		// here: the console must name it and the remedy before teardown.
		expectToolPath := ""
		if len(platform.Identify(platform.OSRelease{ID: manifest.GetDistribution(), VersionID: manifest.GetVersion()}).Lab.RootPermissionsRepair) != 0 {
			expectToolPath = "/"
		}
		enrollment, err = confirmConsoleBrowserEnrollment(ctx, *repository, private, *browserConfig, result.DeviceID, expectToolPath)
		return err
	}
	result, err := vmlab.EnrollFromConsoleVM(ctx, manifest, options)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(private); err != nil {
		return err
	}
	private = ""
	return writeLabEvidence(stdout, *record, struct {
		*vmlab.VMConsoleEnrollmentResult
		BrowserCapture    *consoleBrowserCapture    `json:"browser_capture"`
		ConsoleEnrollment *consoleBrowserEnrollment `json:"console_enrollment"`
	}{result, capture, enrollment})
}

func consoleEnrollmentReverseForwards(args []string) ([]string, error) {
	forwards := make([]string, 0, 2)
	for _, name := range []string{"admin-address", "device-address"} {
		value := labhost.FlagValue(args, name)
		if value == "" {
			continue
		}
		address, err := netip.ParseAddrPort(value)
		if err != nil || address.Addr() != netip.AddrFrom4([4]byte{127, 0, 0, 1}) || address.Port() == 0 {
			return nil, fmt.Errorf("-%s must name an explicit IPv4 loopback listener", name)
		}
		forward := fmt.Sprintf("%d:127.0.0.1:%d", address.Port(), address.Port())
		if len(forwards) == 0 || forwards[0] != forward {
			forwards = append(forwards, forward)
		}
	}
	return forwards, nil
}
