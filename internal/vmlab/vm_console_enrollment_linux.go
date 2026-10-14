// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/packaging"
	"lindm/internal/platform"
)

// VMConsoleEnrollmentOptions consumes a production console clipboard command,
// never a parallel installer. Ready captures it after fresh-guest admission.
// VerifyEnrollment must confirm server-side enrollment before owned teardown.
type VMConsoleEnrollmentOptions struct {
	CacheDir, WorkDir, LabBinary, CommandFile string
	AdminAddress, DeviceAddress               string
	// DiagnosticsDir receives, when the copied command fails, the guest's
	// native package-manager log tail; never the command or its output.
	DiagnosticsDir string
	// RedHatTokenFile registers an entitled (RHEL) guest, as a customer's
	// subscribed host is, so the copied DNF command reaches its vendor
	// repositories. Required for entitled releases, refused otherwise.
	RedHatTokenFile  string
	Hardware         *VMHardwareOptions
	Ready            func() error
	VerifyEnrollment func(context.Context, *VMConsoleEnrollmentResult) error
}

// VMConsoleEnrollmentResult contains only independent native observations. A
// completed record proves installation/enrollment, not physical qualification.
type VMConsoleEnrollmentResult struct {
	ImageID              string             `json:"image_id"`
	ImageSHA256          string             `json:"image_sha256"`
	Runtime              *vmRuntimeEvidence `json:"runtime"`
	CommandSHA256        string             `json:"command_sha256"`
	Pristine             bool               `json:"pristine"`
	Lifecycle            string             `json:"lifecycle"`
	DeviceID             string             `json:"device_id"`
	Generation           string             `json:"generation"`
	Package              string             `json:"package"`
	BinarySHA256         string             `json:"binary_sha256"`
	OwnedCleanupComplete bool               `json:"owned_cleanup_complete"`
	RedHat               *VMRedHatEvidence  `json:"redhat,omitempty"`
}

// EnrollFromConsoleVM never stages a lindm agent, repository, CA or bootstrap
// into the guest. Only the captured command may install them. Rolling vendor
// repositories are bound to the manifest's snapshot before enrollment; their
// vendor trust is separate from the lindm server's enrollment authority.
// The read-only lab observer is uploaded AFTER that command exits successfully.
func EnrollFromConsoleVM(ctx context.Context, manifest *labv1.ImageManifest, options VMConsoleEnrollmentOptions) (result *VMConsoleEnrollmentResult, err error) {
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
	release := manifestRelease(manifest)
	if err := release.LabLane(platform.LaneEnrollFromConsole); err != nil {
		return nil, err
	}
	if err := validateVMRedHatToken(release, options.RedHatTokenFile); err != nil {
		return nil, err
	}
	if release.Lab.Entitlement && options.RedHatTokenFile == "" {
		return nil, errors.New("console enrollment of an entitled guest requires -redhat-token-file: the unregistered vendor image has no repository for the copied DNF command")
	}
	if options.CommandFile == "" || options.LabBinary == "" || options.Ready == nil || options.VerifyEnrollment == nil {
		return nil, errors.New("console enrollment requires private clipboard capture, matching guest lab binary and server-side enrollment verification")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Minute)
	defer cancel()
	hardware := VMHardwareOptions{StorageBus: "virtio-blk"}
	if options.Hardware != nil {
		hardware = *options.Hardware
	}
	hardware.AllowNetwork, hardware.stockAcceptance = true, true
	vm, image, err := newVerifiedGuestWithHardware(ctx, manifest, options.CacheDir, options.WorkDir, false, &hardware)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, vm.close()) }()
	if err := vm.connect(ctx); err != nil {
		return nil, err
	}
	if _, err := vm.run(ctx, "sudo -n cloud-init status --wait --format=json", nil, 64<<10, 5*time.Minute); err != nil {
		return nil, err
	}
	if err := pinArchRepositories(ctx, vm, manifest); err != nil {
		return nil, err
	}
	snapshot, err := prepareGuestRollingSnapshot(ctx, vm, manifest, options.CacheDir)
	if err != nil {
		return nil, err
	}
	if snapshot != nil {
		defer func() { err = errors.Join(err, snapshot.Close()) }()
	}
	backend := manifestRelease(manifest).Native().Packages.Backend
	// Arch's stock cloud databases belong to its image date, not necessarily
	// the repository date. Establish that whole-system snapshot together;
	// never refresh its databases and leave a partially upgraded base.
	if backend == platform.BackendPacman {
		if _, err := vm.run(ctx, "sudo -n pacman --sync --refresh --sysupgrade --noconfirm", nil, 1<<20, 20*time.Minute); err != nil {
			return nil, fmt.Errorf("prepare whole-system enrollment snapshot: %w", err)
		}
	}
	tool, query, err := consoleEnrollmentPackageQuery(backend)
	if err != nil {
		return nil, err
	}
	pristine := `set -eu
if command -v lindm-agent >/dev/null; then exit 1; fi
for path in /usr/bin/lindm-agent /etc/lindm /var/lib/lindm /run/lindm; do test ! -e "$path"; done
command -v ` + nativeQuote(tool) + ` >/dev/null
if ` + query + ` >/dev/null 2>&1; then exit 1; fi
`
	if _, err := vm.run(ctx, "sudo -n sh -eu -c "+nativeQuote(pristine), nil, 4096, time.Minute); err != nil {
		return nil, errors.New("console enrollment refuses a guest with a preinstalled agent or prior enrollment state")
	}
	result = &VMConsoleEnrollmentResult{ImageID: manifest.GetId(), ImageSHA256: image.SHA256, Pristine: true}
	result.Runtime, err = vm.runtimeEvidence(ctx)
	if err != nil {
		return nil, err
	}
	if release.Lab.Entitlement {
		result.RedHat = new(VMRedHatEvidence)
		var registration *vmRedHatRegistration
		if registration, err = registerConsoleEnrollmentRedHat(ctx, vm, options, result.RedHat); err != nil {
			return nil, err
		}
		defer func() {
			err = errors.Join(err, releaseConsoleEnrollmentRedHat(ctx, vm, options.LabBinary, registration))
		}()
	}
	var forwards []*guestForward
	defer func() { err = errors.Join(err, closeLifecycleForwards(forwards)) }()
	for _, address := range []string{options.AdminAddress, options.DeviceAddress} {
		if address == "" {
			continue
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil || host != "127.0.0.1" {
			return nil, errors.New("console fixture forward must be an explicit IPv4 loopback listener")
		}
		forward, err := newGuestForward(ctx, vm, address, address)
		if err != nil {
			return nil, err
		}
		forwards = append(forwards, forward)
	}
	if err := options.Ready(); err != nil {
		return nil, err
	}
	command, err := readConsoleCommand(options.CommandFile)
	if err != nil {
		return nil, err
	}
	defer clear(command)
	if err := os.Remove(options.CommandFile); err != nil {
		return nil, errors.New("cannot consume protected console command file")
	}
	digest := sha256.Sum256(command)
	result.CommandSHA256 = hex.EncodeToString(digest[:])
	// Send exact clipboard bytes over private stdin, never command argv. Do not
	// echo output: package tools or an interrupted command may include secrets.
	executed, runErr := vm.runResult(ctx, "sh -s", bytes.NewReader(command), 1<<20, 20*time.Minute)
	clear(command)
	defer clear(executed.Stdout)
	defer clear(executed.Stderr)
	if runErr != nil {
		return nil, errors.New("captured console command transport failed (secret-bearing output withheld; command not retried)")
	}
	if executed.ExitCode != 0 {
		failure := fmt.Errorf("captured console command exited %d (output withheld; command not retried)", executed.ExitCode)
		return nil, errors.Join(failure, saveConsolePackageLog(ctx, vm, backend, options.DiagnosticsDir))
	}
	if _, err := vm.run(ctx, "sudo -n install -d -m 0755 /var/tmp/lindm-native-lab", nil, 4096, time.Minute); err != nil {
		return nil, err
	}
	if err := uploadLifecycleProbe(ctx, vm, options.LabBinary); err != nil {
		return nil, err
	}
	status, err := waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED)
	if err != nil {
		return nil, err
	}
	if !vmValidID(status.GetDeviceId()) || !vmValidID(status.GetEnrollmentGeneration()) {
		return nil, errors.New("enrollment did not install an enrolled device identity")
	}
	result.DeviceID, result.Generation = status.GetDeviceId(), status.GetEnrollmentGeneration()
	result.Lifecycle = status.GetLifecycle().String()
	if _, err := vm.run(ctx, "sudo -n systemctl is-active --quiet lindm-executor.service && sudo -n systemctl is-active --quiet lindm-agent.service", nil, 4096, time.Minute); err != nil {
		return nil, err
	}
	observed, err := vm.run(ctx, query, nil, 4096, time.Minute)
	if err != nil {
		return nil, err
	}
	result.Package = strings.TrimSpace(string(observed))
	observed, err = vm.run(ctx, "sha256sum "+packaging.BinaryPath, nil, 4096, time.Minute)
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(observed))
	if len(fields) != 2 || len(fields[0]) != 64 {
		return nil, errors.New("installed agent binary digest missing")
	}
	if _, err := hex.DecodeString(fields[0]); err != nil {
		return nil, err
	}
	result.BinarySHA256 = fields[0]
	if err := options.VerifyEnrollment(ctx, result); err != nil {
		return nil, fmt.Errorf("server-side enrollment was not confirmed before guest teardown: %w", err)
	}
	return result, nil
}

// registerConsoleEnrollmentRedHat registers the fresh entitled guest through
// the maintained hosted path, standing in for the customer's subscription. The
// registration probe is removed again before the copied command runs, so the
// read-only observer is still present only after that command.
func registerConsoleEnrollmentRedHat(ctx context.Context, vm *guestVM, options VMConsoleEnrollmentOptions, evidence *VMRedHatEvidence) (*vmRedHatRegistration, error) {
	if err := lifecycleCommand(ctx, vm, "stage registration probe directory", "test ! -e "+nativeGuestDir+"; install -d -m 0755 "+nativeGuestDir); err != nil {
		return nil, err
	}
	if err := uploadLifecycleProbe(ctx, vm, options.LabBinary); err != nil {
		return nil, err
	}
	registration, err := registerVMRedHat(ctx, vm, options.RedHatTokenFile, evidence)
	if err != nil {
		return nil, err
	}
	if err := lifecycleCommand(ctx, vm, "remove registration probe before the console command", "rm -f -- "+guestLifecycleProbe); err != nil {
		return nil, errors.Join(err, registration.Close())
	}
	return registration, nil
}

// releaseConsoleEnrollmentRedHat unregisters and deletes the activation key.
// Unregistration runs through the observer probe, which the lane uploads only
// after a successful command; it is restored when the lane stopped earlier.
func releaseConsoleEnrollmentRedHat(ctx context.Context, vm *guestVM, labBinary string, registration *vmRedHatRegistration) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
	defer cancel()
	if _, err := vm.run(ctx, "test -x "+guestLifecycleProbe, nil, 1024, time.Minute); err != nil {
		if err := uploadLifecycleProbe(ctx, vm, labBinary); err != nil {
			return errors.Join(err, registration.Close())
		}
	}
	return registration.Close()
}

func consoleEnrollmentPackageQuery(backend platform.Backend) (tool, query string, err error) {
	switch backend {
	case platform.BackendAPT:
		return "dpkg-query", "dpkg-query -W -f='${Package} ${Version} ${Architecture}\\n' lindm-agent", nil
	case platform.BackendDNF4, platform.BackendDNF5, platform.BackendZypper:
		return "rpm", "rpm -q --qf '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\\n' lindm-agent", nil
	case platform.BackendPacman:
		return "pacman", "pacman --query lindm-agent", nil
	default:
		return "", "", errors.New("console enrollment has no native package query for this backend")
	}
}

// consolePackageLogs names each backend's own native log. Package managers
// record repository URLs and solver, signature and download errors there,
// never the copied command's bootstrap fetches or enrollment material.
var consolePackageLogs = map[platform.Backend]string{
	platform.BackendAPT:    "/var/log/apt/term.log",
	platform.BackendDNF4:   "/var/log/dnf.log",
	platform.BackendDNF5:   "/var/log/dnf5.log",
	platform.BackendZypper: "/var/log/zypper.log",
	platform.BackendPacman: "/var/log/pacman.log",
}

// saveConsolePackageLog keeps a failed copied command's diagnosable cause
// without its secret-bearing output: the native package-manager log tail.
func saveConsolePackageLog(ctx context.Context, vm *guestVM, backend platform.Backend, directory string) error {
	path, ok := consolePackageLogs[backend]
	if directory == "" || !ok || vm.client == nil || vm.processError() != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	result, err := vm.runResult(ctx, "sudo -n tail -n 1500 "+nativeQuote(path), nil, 2<<20, 10*time.Second)
	if err != nil {
		return fmt.Errorf("collect private console package log: %w", err)
	}
	data, err := json.Marshal(struct {
		Source, Path string
		ExitCode     int
		Log          string
	}{"console-command-package-log", path, result.ExitCode, string(result.Stdout)})
	if err != nil {
		return err
	}
	saved, err := saveGuestDiagnostics(directory, data)
	if err != nil {
		return err
	}
	return fmt.Errorf("private console package log saved to %q", saved)
}

func readConsoleCommand(path string) (_ []byte, err error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() { err = errors.Join(err, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	identity, ok := info.Sys().(*syscall.Stat_t)
	if !ok || identity.Uid != uint32(os.Geteuid()) || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() <= 0 || info.Size() > 1<<20 {
		return nil, errors.New("captured console command must be an owned nonempty mode-0600 regular file of at most 1 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		clear(data)
		return nil, err
	}
	if len(data) > 1<<20 || bytes.IndexByte(data, 0) >= 0 {
		clear(data)
		return nil, errors.New("captured console command is oversized or contains NUL")
	}
	return data, nil
}
