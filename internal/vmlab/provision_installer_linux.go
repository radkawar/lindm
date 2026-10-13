//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

// provisionInstallers maps each installer format to the vendor installer it
// is merged into.
var provisionInstallers = map[string]platform.Installer{
	string(platform.ProvisionAutoinstall): platform.Subiquity,
	string(platform.ProvisionKickstart):   platform.Anaconda,
	string(platform.ProvisionAutoYaST):    platform.AutoYaST,
}

// ProvisionInstallerVM installs a fresh encrypted machine from the signed
// vendor installer media with the console snippet merged verbatim into the
// lab's installer recipe. The install is the subject: it is never cached or
// shared. Lab-owned recipe parts run before the snippet and are scanned to
// carry no lindm input. After the LUKS cold boot the snippet's unit enrolls,
// waiting for the independent approval the lane obtains through the console.
func ProvisionInstallerVM(ctx context.Context, manifest *labv1.ImageManifest, format string, options VMProvisionOptions) (result *VMProvisionResult, err error) {
	defer func() {
		if err != nil {
			result = nil
		} else if result != nil {
			result.OwnedCleanupComplete = true
		}
	}()
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	if !strings.HasSuffix(manifest.GetImageFilename(), ".iso") {
		return nil, errors.New("installer provisioning requires an official installer ISO manifest")
	}
	media := encryptedInstallerMedia(manifest)
	installer, ok := provisionInstallers[format]
	if !ok || media.release.Lab.Installer != installer || media.desktop {
		return nil, fmt.Errorf("%s provisioning needs %s's server installer media", format, media.release.Name)
	}
	if err := provisionRelease(media.release, format, manifest.GetArchitecture()); err != nil {
		return nil, err
	}
	if err := media.release.Gate(platform.Encryption); err != nil {
		return nil, err
	}
	if installer == platform.AutoYaST {
		if manifest.GetRepositorySnapshotManifestSha256() == "" {
			return nil, errors.New("AutoYaST provisioning requires a retained signed repository snapshot closure")
		}
		if _, err := tumbleweedInstallerImage(manifest); err != nil {
			return nil, err
		}
	}
	if err := options.validate(); err != nil {
		return nil, err
	}
	if options.Hardware == nil || options.Hardware.Firmware == nil {
		return nil, errors.New("installer provisioning requires explicit UEFI firmware")
	}
	ctx, cancel := context.WithTimeout(ctx, 150*time.Minute)
	defer cancel()
	architecture, _, err := encryptedInstallerArchitecture(manifest.GetArchitecture())
	if err != nil {
		return nil, err
	}
	requested := *options.Hardware
	requested.TPM = encryptedGuestTPMObservable(manifest, architecture)
	hardware, err := encryptedMachineHardware(manifest, EncryptedVMOptions{Firmware: *options.Hardware.Firmware, Hardware: &requested})
	if err != nil {
		return nil, err
	}
	hardware.StorageBus, hardware.ExtraDisks, hardware.Desktop, hardware.AllowNetwork = "virtio-blk", 0, false, true
	workDir := options.WorkDir
	if workDir == "" {
		workDir = os.TempDir()
	}
	if workDir, err = filepath.Abs(workDir); err != nil {
		return nil, err
	}
	staging, err := os.MkdirTemp(workDir, "lindm-provision-")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(staging)) }()
	firmwareDir, err := os.MkdirTemp(staging, ".firmware-")
	if err != nil {
		return nil, err
	}
	firmware, err := prepareEncryptedFirmware(ctx, firmwareDir, *options.Hardware.Firmware)
	if err != nil {
		return nil, err
	}
	if err := copyEncryptedFile(filepath.Join(firmwareDir, "firmware-code.fd"), filepath.Join(staging, "firmware-code.fd"), 0444); err != nil {
		return nil, err
	}
	if err := copyEncryptedFile(filepath.Join(firmwareDir, "nvram.fd"), filepath.Join(staging, "nvram.fd"), 0600); err != nil {
		return nil, err
	}
	if err := os.RemoveAll(firmwareDir); err != nil {
		return nil, err
	}
	if err := os.Mkdir(filepath.Join(staging, "tpm"), 0700); err != nil {
		return nil, err
	}
	if _, err := hostCommand(ctx, staging, "qemu-img", nil, "create", "-f", "qcow2", "disk.qcow2", "24G"); err != nil {
		return nil, err
	}
	verified, err := (Fetcher{}).Fetch(ctx, manifest, options.CacheDir)
	if err != nil {
		return nil, err
	}
	snapshot, err := startImageRepositorySnapshot(ctx, manifest, options.CacheDir, provisionHostAddress)
	if err != nil {
		return nil, err
	}
	if snapshot != nil {
		defer func() { err = errors.Join(err, snapshot.Close()) }()
		media.snapshot = &tumbleweedSnapshotRepository{URL: snapshot.URL, CAPEM: snapshot.CAPEM}
	}
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, err
	}
	secret := hex.EncodeToString(secretBytes)
	loginKey, loginPublic, err := encryptedKey()
	if err != nil {
		return nil, err
	}
	hostKey, hostPublic, err := encryptedKey()
	if err != nil {
		return nil, err
	}
	recipe, err := encryptedInstallerRecipeForMachine(media, secret, loginPublic, string(hostKey), hostPublic, "", false, hardware.Architecture)
	if err != nil {
		return nil, err
	}
	defer clear(recipe)
	// Capture last before the installer boots: the token's lifetime starts
	// with the copy, not with the media download.
	snippet, pins, digest, err := captureProvisionSnippet(options, format, media.release.Native().Packages.Backend)
	if err != nil {
		return nil, err
	}
	defer clear(snippet)
	merged, labParts, err := provisionInstallerRecipe(format, recipe, snippet, options.PublicHost)
	if err != nil {
		return nil, err
	}
	defer clear(merged)
	labDigest, err := provisionLabPartsLindmFree(labParts, options.PublicHost)
	clear(labParts)
	if err != nil {
		return nil, err
	}
	installerPath, err := prepareEncryptedInstallerForMachine(ctx, staging, verified.Path, installer, merged, hardware.Architecture)
	clear(merged)
	clear(snippet)
	if err != nil {
		return nil, err
	}
	config, err := encryptedSSHConfig(loginKey, hostKey)
	if err != nil {
		return nil, err
	}
	vm := &EncryptedVM{dir: staging, config: config, firmware: firmware, initialSecret: secret, cacheDir: options.CacheDir, hardware: hardware}
	defer func() { err = errors.Join(err, vm.Kill()) }()
	console := io.Discard
	if options.DiagnosticsDir != "" {
		// Private failure diagnostics only: the installer console can echo the
		// snippet and its token, so the log is a new owner-only file in the
		// caller's private directory, never evidence.
		logFile, openErr := os.OpenFile(filepath.Join(options.DiagnosticsDir, "installer-console.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if openErr != nil {
			return nil, fmt.Errorf("create private installer console log: %w", openErr)
		}
		defer func() { err = errors.Join(err, logFile.Close()) }()
		console = &cappedWriter{w: logFile, remaining: maxInstallerLogBytes}
		vm.bootConsole = console
	}
	if err := runProvisionInstaller(ctx, vm, installerPath, console); err != nil {
		return nil, err
	}
	// The remastered media holds the token; it is no longer needed.
	if err := os.Remove(installerPath); err != nil {
		return nil, err
	}
	if _, err := vm.ColdBoot(ctx, secret); err != nil {
		return nil, fmt.Errorf("first encrypted installed boot: %w", err)
	}
	result = &VMProvisionResult{Format: format, ImageID: manifest.GetId(), ImageSHA256: verified.SHA256, Firmware: firmware, SnippetSHA256: digest}
	result.Pristine = VMProvisionPristine{VendorImageVerified: true, LabPartsSHA256: labDigest, LabPartsLindmFree: true, SnippetOnlyLindmInput: true}
	if installer == platform.Subiquity {
		// The snippet's user-data runs in the installed system's first boot.
		// Exit 2 is cloud-init's "done with recoverable errors": 26.04's
		// cloud-init warns that the installer identity's locked password is
		// not unlocked. Only unrecoverable errors fail here; the provisioning
		// unit and enrollment checks below judge the snippet's own outcome.
		status, err := vm.guest.runResult(ctx, "sudo -n cloud-init status --wait --format=json", nil, 64<<10, 30*time.Minute)
		if err != nil {
			return nil, fmt.Errorf("installed system's first-boot cloud-init: %w", err)
		}
		var parsed struct {
			Errors []string `json:"errors"`
		}
		if status.ExitCode != 0 && (status.ExitCode != 2 || json.Unmarshal(status.Stdout, &parsed) != nil || len(parsed.Errors) != 0) {
			err = fmt.Errorf("installed system's first-boot cloud-init exited with status %d", status.ExitCode)
			if options.DiagnosticsDir != "" {
				// The status names the failing or warning modules; it can quote
				// user-data, so it stays in the private diagnostics directory.
				err = errors.Join(err, os.WriteFile(filepath.Join(options.DiagnosticsDir, "cloud-init-status.json"), status.Stdout, 0600), recordProvisionDiagnostics(ctx, vm.guest, options.DiagnosticsDir))
			}
			return nil, err
		}
	}
	if err := awaitProvisionedEnrollment(ctx, vm.guest, media.release, options, pins, result); err != nil {
		return nil, err
	}
	return result, nil
}

// runProvisionInstaller runs the vendor installer to its own power-off,
// draining its serial console into console.
func runProvisionInstaller(ctx context.Context, vm *EncryptedVM, installerPath string, console io.Writer) (err error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Minute)
	defer cancel()
	if err := vm.start(ctx, installerPath); err != nil {
		return err
	}
	serial, err := vm.serial(ctx)
	if err != nil {
		return err
	}
	drained := make(chan struct{})
	go func() { _, _ = io.Copy(console, serial); close(drained) }()
	select {
	case <-ctx.Done():
		err = fmt.Errorf("provisioning installer deadline: %w", ctx.Err())
	case <-vm.guest.done:
		if !vm.guest.cmd.ProcessState.Success() {
			err = errors.New("provisioning installer QEMU exited unsuccessfully")
		}
	}
	closeErr := serial.Close()
	<-drained
	return errors.Join(err, closeErr, vm.Kill())
}

// kickstartSnippetPrerequisites are the tools the console's RPM install
// script checks with rpm -q before it would install them with DNF.
var kickstartSnippetPrerequisites = []string{"ca-certificates", "curl", "gnupg2", "openssl"}

// provisionInstallerRecipe merges the snippet into the lab recipe for the
// format and returns the merged recipe and the lab-owned parts alone.
func provisionInstallerRecipe(format string, recipe, snippet []byte, host string) (merged, lab []byte, err error) {
	hosts := provisionHostsCommand(host)
	switch platform.Provisioning(format) {
	case platform.ProvisionAutoinstall:
		parts, err := labAutoinstall(recipe, []string{"curtin", "in-target", "--target=/target", "--", "/bin/sh", "-eu", "-c", hosts})
		if err != nil {
			return nil, nil, err
		}
		if lab, err = labCloudConfig(map[string]any{"autoinstall": parts}); err != nil {
			return nil, nil, err
		}
		merged, err = mergeAutoinstall(snippet, parts)
		return merged, lab, err
	case platform.ProvisionKickstart:
		// The snippet's %post verifies the server CA with openssl and the
		// repository key with gpg. An unregistered Binary DVD install has no
		// repository in %post, and RHEL 10.2's selection does not pull in
		// either tool, so the trusted profile installs them from the DVD.
		packages, rest, ok := bytes.Cut(recipe, []byte("%packages\n"))
		if !ok {
			return nil, nil, errors.New("kickstart recipe has no %packages section")
		}
		recipe = slices.Concat(packages, []byte("%packages\n"+strings.Join(kickstartSnippetPrerequisites, "\n")+"\n"), rest)
		// A lab %post writes the hosts line in the target before the snippet.
		sections := []byte("%post --erroronfail --interpreter=/bin/sh\nset -eu\n" + hosts + "\n%end\n")
		lab = append(append([]byte{}, recipe...), sections...)
		merged, err = appendKickstart(recipe, sections, snippet)
		return merged, lab, err
	case platform.ProvisionAutoYaST:
		script, err := autoyastLabScript("lab-hosts", hosts)
		if err != nil {
			return nil, nil, err
		}
		if lab, err = spliceAutoYaSTItems(recipe, script); err != nil {
			return nil, nil, err
		}
		merged, err = spliceAutoYaST(recipe, script, snippet)
		return merged, lab, err
	default:
		return nil, nil, fmt.Errorf("no installer merge for format %q", format)
	}
}
