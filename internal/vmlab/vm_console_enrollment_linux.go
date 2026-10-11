//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	Hardware                                  *VMHardwareOptions
	Ready                                     func() error
	VerifyEnrollment                          func(context.Context, *VMConsoleEnrollmentResult) error
}

// VMConsoleEnrollmentResult contains only independent native observations. A
// completed record proves installation/enrollment, not physical qualification.
type VMConsoleEnrollmentResult struct {
	ImageID              string             `json:"image_id"`
	ImageSHA256          string             `json:"image_sha256"`
	Runtime              *vmRuntimeEvidence `json:"runtime"`
	CommandSHA256        string             `json:"command_sha256"`
	Pristine             bool               `json:"pristine"`
	DeviceID             string             `json:"device_id"`
	Generation           string             `json:"generation"`
	Package              string             `json:"package"`
	BinarySHA256         string             `json:"binary_sha256"`
	OwnedCleanupComplete bool               `json:"owned_cleanup_complete"`
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
	if err := manifestRelease(manifest).LabLane(platform.LaneEnrollFromConsole); err != nil {
		return nil, err
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
		return nil, fmt.Errorf("captured console command exited %d (output withheld; command not retried)", executed.ExitCode)
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
