package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"lindm/internal/platform"
	"lindm/internal/vmlab"
)

// provisionLaneFormat maps `lab vm provision-<format>` to its installer format.
func provisionLaneFormat(lane string) (platform.Provisioning, bool) {
	format := platform.Provisioning(strings.TrimPrefix(lane, "provision-"))
	if candidate, ok := platform.ProvisionLane(format); !ok || string(candidate) != lane {
		return "", false
	}
	return format, true
}

// provisionInstallerLane reports a lane that runs a vendor installer: like
// the encrypted lanes it needs 4 GiB and native KVM by default.
func provisionInstallerLane(lane string) bool {
	format, ok := provisionLaneFormat(lane)
	return ok && format != platform.ProvisionCloudInit
}

// runVMProvision feeds the console's copied provisioning snippet, captured
// from a real Chromium Copy, verbatim into a fresh first boot or vendor
// installation, then drives the independent approval through the console.
func runVMProvision(ctx context.Context, lane string, args []string, stdout, stderr io.Writer) (resultErr error) {
	format, ok := provisionLaneFormat(lane)
	if !ok {
		return fmt.Errorf("unknown provisioning lane %q", lane)
	}
	flags := flag.NewFlagSet("vm "+lane, flag.ContinueOnError)
	flags.SetOutput(stderr)
	var options vmlab.VMProvisionOptions
	manifestPath := flags.String("manifest", "", "signed manifest for a registry-admitted provisioning lane")
	record := flags.String("record", "", "required new nonsecret evidence JSON, written only after cleanup")
	repository := flags.String("repo", ".", "checkout under test containing the maintained browser runner")
	browserConfig := flags.String("browser-config", "", "required owned mode0600 Chromium provisioning config (owner plus approver, public-host origin)")
	flags.StringVar(&options.CacheDir, "cache", ".cache/lab/images", "verified vendor image cache")
	flags.StringVar(&options.WorkDir, "work-dir", "", "parent for owned disposable guest and installer state")
	flags.StringVar(&options.LabBinary, "lab-binary", "", "matching guest-architecture read-only lab observer")
	flags.StringVar(&options.DiagnosticsDir, "diagnostics", "", "existing private directory for a bounded installer and first-boot serial log; may hold the snippet's token, never evidence")
	// Guests reach the public-host origin through QEMU's host address; these
	// name the fixture listeners a remote lab host reverse-forwards.
	adminAddress := flags.String("admin-address", "", "optional host-loopback console listener reverse-forwarded to a remote lab host")
	deviceAddress := flags.String("device-address", "", "optional host-loopback device listener reverse-forwarded to a remote lab host")
	hardware := newVMHardwareFlags(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *manifestPath == "" || *record == "" || *browserConfig == "" || options.LabBinary == "" {
		return fmt.Errorf("%s requires -manifest, -record, -lab-binary and -browser-config; no positional arguments", lane)
	}
	if _, err := consoleEnrollmentReverseForwards([]string{"-admin-address", *adminAddress, "-device-address", *deviceAddress}); err != nil {
		return err
	}
	manifest, err := vmlab.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	release := platform.ForManifest(manifest.GetDistribution(), manifest.GetVersion())
	if options.PublicHost, err = consoleProvisioningHost(*browserConfig); err != nil {
		return err
	}
	private, err := os.MkdirTemp(options.WorkDir, "lindm-provision-copy-")
	if err != nil {
		return err
	}
	defer func() {
		if private != "" {
			resultErr = errors.Join(resultErr, os.RemoveAll(private))
		}
	}()
	options.Hardware = hardware.options()
	var capture *consoleProvisioningCapture
	var approval *consoleProvisioningApproval
	options.Capture = func(format string) (string, error) {
		if _, err := fmt.Fprintf(stderr, "Capturing the production console %s snippet and screenshots in Chromium before boot.\n", format); err != nil {
			return "", err
		}
		path, err := filepath.Abs(filepath.Join(private, "clipboard-snippet"))
		if err != nil {
			return "", err
		}
		capture, err = captureConsoleProvisioning(ctx, *repository, private, *browserConfig, path, format, release)
		if err != nil {
			return "", err
		}
		if capture.Format != format || !capture.ApprovalRequired {
			return "", errors.New("browser capture is not an approval-required token for the lane's format")
		}
		return path, nil
	}
	options.Approve = func(ctx context.Context, installationID string) (string, error) {
		if _, err := fmt.Fprintln(stderr, "Device pending: approving through the console as the independent approver; the token creator executes."); err != nil {
			return "", err
		}
		approval, err = approveConsoleProvisioning(ctx, *repository, private, *browserConfig, installationID)
		if err != nil {
			return "", err
		}
		if approval.InstallationID != installationID || capture == nil || approval.TokenID != capture.TokenID || !approval.RequesterExecuted {
			return "", errors.New("console approval is not bound to the captured token and this pending installation")
		}
		return approval.DeviceID, nil
	}
	options.VerifyEnrollment = func(_ context.Context, result *vmlab.VMProvisionResult) error {
		if capture == nil || capture.SHA256 != result.SnippetSHA256 {
			return errors.New("installed snippet differs from the browser clipboard capture")
		}
		if approval == nil || approval.DeviceID != result.DeviceID || approval.Lifecycle != "Enrolled" {
			return errors.New("console did not show the provisioned device enrolled")
		}
		return nil
	}
	var result *vmlab.VMProvisionResult
	if format == platform.ProvisionCloudInit {
		result, err = vmlab.ProvisionCloudInitVM(ctx, manifest, options)
	} else {
		result, err = vmlab.ProvisionInstallerVM(ctx, manifest, string(format), options)
	}
	if err != nil {
		return err
	}
	if err := os.RemoveAll(private); err != nil {
		return err
	}
	private = ""
	return writeLabEvidence(stdout, *record, struct {
		*vmlab.VMProvisionResult
		BrowserCapture  *consoleProvisioningCapture  `json:"browser_capture"`
		ConsoleApproval *consoleProvisioningApproval `json:"console_approval"`
	}{result, capture, approval})
}
