//go:build linux

package vmlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/devlab"
	"lindm/internal/packaging"
	"lindm/internal/platform"
)

// VMProvisionOptions drive one provisioning lane. Capture copies the console
// snippet for the format into a new owned mode-0600 file before the guest or
// installer boots. Approve completes the independent approval for the guest's
// pending installation and returns the device it was bound to. VerifyEnrollment
// must confirm server-side enrollment before owned teardown.
type VMProvisionOptions struct {
	CacheDir, WorkDir, LabBinary string
	// PublicHost is the console and device origin hostname. Guests map it to
	// the QEMU host with a lab-owned /etc/hosts line written before the snippet.
	PublicHost string
	// Hardware selects acceleration and, for installer lanes, UEFI firmware.
	Hardware *VMHardwareOptions
	// DiagnosticsDir, when set, names an existing private directory receiving
	// a bounded installer and first-boot serial log. It may contain the
	// snippet's token and must never be published as evidence.
	DiagnosticsDir   string
	Capture          func(format string) (snippetPath string, err error)
	Approve          func(ctx context.Context, installationID string) (deviceID string, err error)
	VerifyEnrollment func(context.Context, *VMProvisionResult) error
}

// VMProvisionPristine is why no lindm input other than the snippet reached
// the device: the verified vendor bytes, the scanned lab-owned parts and the
// observer uploaded only after the snippet's unit ran.
type VMProvisionPristine struct {
	VendorImageVerified          bool   `json:"vendor_image_verified"`
	LabPartsSHA256               string `json:"lab_parts_sha256"`
	LabPartsLindmFree            bool   `json:"lab_parts_lindm_free"`
	SnippetOnlyLindmInput        bool   `json:"snippet_only_lindm_input"`
	ObserverUploadedAfterSnippet bool   `json:"observer_uploaded_after_snippet"`
}

// VMProvisionOrigin binds the installed package to the snippet's repository.
type VMProvisionOrigin struct {
	Repository string   `json:"repository"`
	Configured string   `json:"configured"`
	Observed   []string `json:"observed,omitempty"`
}

// VMProvisionSigner binds the repository trust to the snippet's pinned key.
type VMProvisionSigner struct {
	PinnedFingerprint string   `json:"pinned_fingerprint"`
	Method            string   `json:"method"`
	Observed          []string `json:"observed"`
}

// VMProvisionResult contains only independent native observations. A
// completed record proves provisioning and enrollment, not physical
// qualification.
type VMProvisionResult struct {
	Format               string                     `json:"format"`
	ImageID              string                     `json:"image_id"`
	ImageSHA256          string                     `json:"image_sha256"`
	Runtime              *vmRuntimeEvidence         `json:"runtime,omitempty"`
	Firmware             *EncryptedFirmwareEvidence `json:"firmware,omitempty"`
	SnippetSHA256        string                     `json:"snippet_sha256"`
	Pristine             VMProvisionPristine        `json:"pristine"`
	InstallationID       string                     `json:"installation_id"`
	DeviceID             string                     `json:"device_id"`
	Generation           string                     `json:"generation"`
	UnitsActive          []string                   `json:"units_active"`
	ProvisionUnit        string                     `json:"provision_unit"`
	TokenRemoved         bool                       `json:"token_removed"`
	Package              string                     `json:"package"`
	Origin               VMProvisionOrigin          `json:"origin"`
	Signer               VMProvisionSigner          `json:"signer"`
	BinarySHA256         string                     `json:"binary_sha256"`
	OwnedCleanupComplete bool                       `json:"owned_cleanup_complete"`
}

const provisionUnit = "lindm-provision.service"

func (o VMProvisionOptions) validate() error {
	if o.LabBinary == "" || o.Capture == nil || o.Approve == nil || o.VerifyEnrollment == nil {
		return errors.New("provisioning requires browser snippet capture, independent approval, server-side verification and a matching guest lab binary")
	}
	return devlab.ValidatePublicHost(o.PublicHost)
}

// provisionRelease admits a registry-maintained provisioning lane.
func provisionRelease(release *platform.Release, format, architecture string) error {
	lane, ok := platform.ProvisionLane(platform.Provisioning(format))
	if !ok {
		return fmt.Errorf("no provisioning lane for format %q", format)
	}
	if reason := release.ProvisionGate(lane); reason != "" {
		return errors.New(reason)
	}
	if err := release.LabLaneOn(lane, architecture); err != nil {
		return err
	}
	switch release.Native().Packages.Backend {
	case platform.BackendAPT, platform.BackendDNF4, platform.BackendDNF5, platform.BackendZypper:
		return nil
	default:
		return errors.New("provisioning lanes verify APT or RPM repository origin only")
	}
}

// captureProvisionSnippet consumes the protected clipboard file.
func captureProvisionSnippet(options VMProvisionOptions, format string, backend platform.Backend) ([]byte, provisionPins, string, error) {
	path, err := options.Capture(format)
	if err != nil {
		return nil, provisionPins{}, "", err
	}
	snippet, err := readConsoleCommand(path)
	if err != nil {
		return nil, provisionPins{}, "", err
	}
	if err := os.Remove(path); err != nil {
		clear(snippet)
		return nil, provisionPins{}, "", errors.New("cannot consume protected provisioning snippet file")
	}
	pins, err := provisionSnippetPins(snippet, backend, options.PublicHost)
	if err != nil {
		clear(snippet)
		return nil, provisionPins{}, "", err
	}
	digest := sha256.Sum256(snippet)
	return snippet, pins, hex.EncodeToString(digest[:]), nil
}

// awaitProvisionedEnrollment observes the snippet's unit reach its approval
// wait, uploads the read-only observer only then, obtains the independent
// approval, and records the enrolled device and its package provenance.
func awaitProvisionedEnrollment(ctx context.Context, vm *guestVM, release *platform.Release, options VMProvisionOptions, pins provisionPins, result *VMProvisionResult) error {
	err := awaitProvisionedSteps(ctx, vm, release, options, pins, result)
	if err != nil && options.DiagnosticsDir != "" {
		err = errors.Join(err, recordProvisionDiagnostics(ctx, vm, options.DiagnosticsDir))
	}
	return err
}

// provisionGuestDiagnostics shows why the snippet did not enroll: its
// units, journal and the vendor installer's own script logs. Token files are
// never read; the output stays private.
const provisionGuestDiagnostics = `exec 2>&1
set +e
systemctl --no-pager status lindm-provision.service lindm-executor.service lindm-agent.service
journalctl --no-pager -b -n 300 -u lindm-provision.service -u lindm-executor.service -u lindm-agent.service
ls -la /etc/lindm /etc/systemd/system/lindm-provision.service /usr/libexec/lindm
rpm -q lindm-agent || dpkg-query -W lindm-agent
cat /etc/hosts
tail -n 200 /var/log/cloud-init-output.log
for log in /var/adm/autoinstall/logs/* /var/log/anaconda/ks-script-*.log /var/log/installer/curtin-install.log; do test -f "$log" && { echo "== $log"; tail -n 200 "$log"; }; done
`

// recordProvisionDiagnostics writes the guest's provisioning diagnostics to a
// new owner-only file in the caller's private diagnostics directory.
func recordProvisionDiagnostics(ctx context.Context, vm *guestVM, dir string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	command := "sudo -n sh -c " + nativeQuote(provisionGuestDiagnostics)
	observed, err := vm.runResult(ctx, command, nil, 1<<20, time.Minute)
	if err != nil {
		// A timed-out wait closed the pinned transport; reconnect once.
		if vm.client != nil {
			_ = vm.client.Close()
			vm.client = nil
		}
		if connectErr := vm.connect(ctx); connectErr != nil {
			return fmt.Errorf("collect guest provisioning diagnostics: %w", errors.Join(err, connectErr))
		}
		if observed, err = vm.runResult(ctx, command, nil, 1<<20, time.Minute); err != nil {
			return fmt.Errorf("collect guest provisioning diagnostics: %w", err)
		}
	}
	defer clear(observed.Stdout)
	file, err := os.OpenFile(filepath.Join(dir, "guest-provisioning.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = file.Write(observed.Stdout)
	return errors.Join(err, file.Close())
}

func awaitProvisionedSteps(ctx context.Context, vm *guestVM, release *platform.Release, options VMProvisionOptions, pins provisionPins, result *VMProvisionResult) error {
	if err := waitProvisionUnit(ctx, vm, 25*time.Minute, func(active, outcome string) (bool, error) {
		if active == "failed" {
			return false, errors.New("provisioning unit failed before approval")
		}
		return active == "activating" || active == "active", nil
	}); err != nil {
		return fmt.Errorf("wait for the snippet's provisioning unit: %w", err)
	}
	if _, err := vm.run(ctx, "sudo -n install -d -m 0755 /var/tmp/lindm-native-lab", nil, 4096, time.Minute); err != nil {
		return err
	}
	if err := uploadLifecycleProbe(ctx, vm, options.LabBinary); err != nil {
		return err
	}
	result.Pristine.ObserverUploadedAfterSnippet = true
	installation, err := waitProvisionPending(ctx, vm, 15*time.Minute)
	if err != nil {
		return err
	}
	result.InstallationID = installation
	deviceID, err := options.Approve(ctx, installation)
	if err != nil {
		return fmt.Errorf("independent console approval: %w", err)
	}
	if !vmValidID(deviceID) {
		return errors.New("approval did not name a valid device")
	}
	if err := waitProvisionUnit(ctx, vm, 15*time.Minute, func(active, outcome string) (bool, error) {
		switch {
		case active == "failed" || (outcome != "" && outcome != "success"):
			return false, fmt.Errorf("provisioning unit ended %s/%s after approval", active, outcome)
		default:
			return active == "active" && outcome == "success", nil
		}
	}); err != nil {
		return fmt.Errorf("wait for approved enrollment: %w", err)
	}
	result.ProvisionUnit = provisionUnit + " active/success"
	// The unit removes the reusable token once enrollment succeeded.
	if _, err := vm.run(ctx, "sudo -n test ! -e /etc/lindm/provisioning-token", nil, 1024, time.Minute); err != nil {
		return errors.New("provisioning token remained on the enrolled device")
	}
	result.TokenRemoved = true
	status, err := waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED)
	if err != nil {
		return err
	}
	if status.GetInstallationId() != installation || status.GetDeviceId() != deviceID || !vmValidID(status.GetEnrollmentGeneration()) {
		return errors.New("enrolled identity differs from the approved pending installation")
	}
	result.DeviceID, result.Generation = deviceID, status.GetEnrollmentGeneration()
	units := []string{"lindm-executor.service", "lindm-agent.service"}
	for _, unit := range units {
		if _, err := vm.run(ctx, "systemctl is-active --quiet "+unit, nil, 4096, time.Minute); err != nil {
			return fmt.Errorf("%s is not active: %w", unit, err)
		}
	}
	result.UnitsActive = units
	if err := recordProvisionPackage(ctx, vm, release.Native().Packages.Backend, pins, result); err != nil {
		return err
	}
	observed, err := vm.run(ctx, "sha256sum "+packaging.BinaryPath, nil, 4096, time.Minute)
	if err != nil {
		return err
	}
	fields := strings.Fields(string(observed))
	if len(fields) != 2 || len(fields[0]) != 64 {
		return errors.New("installed agent binary digest missing")
	}
	if _, err := hex.DecodeString(fields[0]); err != nil {
		return err
	}
	result.BinarySHA256 = fields[0]
	if err := options.VerifyEnrollment(ctx, result); err != nil {
		return fmt.Errorf("server-side enrollment was not confirmed before guest teardown: %w", err)
	}
	return nil
}

// waitProvisionUnit polls the snippet's unit state until done reports true.
// The unit was installed before this wait (by cloud-init's write_files or
// in the installed target), so an absent unit, one whose start condition
// failed, or a failed executor it requires will never enroll and ends the
// wait at once.
func waitProvisionUnit(ctx context.Context, vm *guestVM, timeout time.Duration, done func(active, outcome string) (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		data, err := vm.run(ctx, "systemctl show --property=Id --property=LoadState --property=ActiveState --property=Result --property=ConditionResult "+provisionUnit+" lindm-executor.service", nil, 8192, 30*time.Second)
		if err == nil {
			units := map[string]map[string]string{}
			for block := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n\n") {
				state := map[string]string{}
				for line := range strings.SplitSeq(block, "\n") {
					if key, value, ok := strings.Cut(line, "="); ok {
						state[key] = value
					}
				}
				units[state["Id"]] = state
			}
			state, executor := units[provisionUnit], units["lindm-executor.service"]
			active, outcome := state["ActiveState"], state["Result"]
			if state["LoadState"] != "loaded" {
				return fmt.Errorf("the snippet's %s is not installed (LoadState=%s)", provisionUnit, state["LoadState"])
			}
			if active == "inactive" && state["ConditionResult"] == "no" {
				return fmt.Errorf("the snippet's %s skipped its start condition", provisionUnit)
			}
			if executor["ActiveState"] == "failed" {
				return fmt.Errorf("lindm-executor.service, which %s requires, failed (%s)", provisionUnit, executor["Result"])
			}
			if active == "active" || active == "failed" || active == "activating" {
				finished, err := done(active, outcome)
				if err != nil || finished {
					return err
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// waitProvisionPending returns the installation once the executor holds a
// pending enrollment. Acquiring authority before approval is a failure.
func waitProvisionPending(ctx context.Context, vm *guestVM, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		if status, err := readGuestAgentStatus(ctx, vm); err == nil {
			switch executor := status.GetExecutor(); executor.GetLifecycle() {
			case agentv1.Lifecycle_LIFECYCLE_PENDING_ENROLLMENT:
				if !vmValidID(executor.GetInstallationId()) {
					return "", errors.New("pending executor reported no installation identity")
				}
				return executor.GetInstallationId(), nil
			case agentv1.Lifecycle_LIFECYCLE_ENROLLED:
				return "", errors.New("approval-required device acquired authority before approval")
			case agentv1.Lifecycle_LIFECYCLE_RECOVERY_HOLD:
				return "", errors.New("provisioned executor entered recovery hold")
			}
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("wait for pending enrollment: %w", ctx.Err())
		case <-time.After(5 * time.Second):
		}
	}
}

// recordProvisionPackage observes the installed package, the repository the
// snippet configured and the signer it pinned, each from the guest itself.
func recordProvisionPackage(ctx context.Context, vm *guestVM, backend platform.Backend, pins provisionPins, result *VMProvisionResult) error {
	result.Origin.Repository, result.Signer.PinnedFingerprint = pins.Repository, pins.Fingerprint
	if backend == platform.BackendAPT {
		return recordProvisionAPT(ctx, vm, pins, result)
	}
	return recordProvisionRPM(ctx, vm, backend, pins, result)
}

func recordProvisionAPT(ctx context.Context, vm *guestVM, pins provisionPins, result *VMProvisionResult) error {
	observed, err := vm.run(ctx, "dpkg-query -W -f='${Package} ${Version} ${Architecture}\\n' lindm-agent", nil, 4096, time.Minute)
	if err != nil {
		return err
	}
	result.Package = strings.TrimSpace(string(observed))
	sources, err := vm.run(ctx, "cat /etc/apt/sources.list.d/lindm.sources", nil, 16<<10, time.Minute)
	if err != nil {
		return err
	}
	var keyring string
	for line := range strings.SplitSeq(string(sources), "\n") {
		if value, ok := strings.CutPrefix(line, "URIs: "); ok {
			result.Origin.Configured = strings.TrimSpace(value)
		}
		if value, ok := strings.CutPrefix(line, "Signed-By: "); ok {
			keyring = strings.TrimSpace(value)
		}
	}
	if result.Origin.Configured != pins.Repository || !strings.HasPrefix(keyring, "/etc/apt/keyrings/") || strings.ContainsAny(keyring, " '\"\\$`;") {
		return errors.New("installed APT source differs from the snippet's repository or keyring")
	}
	policy, err := vm.run(ctx, "apt-cache policy lindm-agent", nil, 64<<10, time.Minute)
	if err != nil {
		return err
	}
	result.Origin.Observed = aptPolicyOrigins(string(policy))
	if !slices.ContainsFunc(result.Origin.Observed, func(origin string) bool { return strings.HasPrefix(origin, strings.TrimSuffix(pins.Repository, "/")) }) {
		return errors.New("installed agent version is not offered by the snippet's repository")
	}
	// A private empty homedir: without one gpg reports creating the lab
	// user's ~/.gnupg, keybox and trustdb on stderr, which the lane refuses.
	keys, err := vm.run(ctx, `home=$(mktemp -d) && { gpg --batch --quiet --homedir "$home" --with-colons --show-keys `+keyring+`; status=$?; rm -rf -- "$home"; exit "$status"; }`, nil, 64<<10, time.Minute)
	if err != nil {
		return err
	}
	result.Signer.Method = "apt Signed-By keyring primary fingerprint"
	result.Signer.Observed = gpgPrimaryFingerprints(string(keys))
	if !slices.Equal(result.Signer.Observed, []string{pins.Fingerprint}) {
		return errors.New("APT Signed-By keyring is not exactly the snippet's pinned signing key")
	}
	return nil
}

func recordProvisionRPM(ctx context.Context, vm *guestVM, backend platform.Backend, pins provisionPins, result *VMProvisionResult) error {
	observed, err := vm.run(ctx, "rpm -q --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n' lindm-agent", nil, 4096, time.Minute)
	if err != nil {
		return err
	}
	result.Package = strings.TrimSpace(string(observed))
	repository := "/etc/yum.repos.d/lindm.repo"
	if backend == platform.BackendZypper {
		repository = "/etc/zypp/repos.d/lindm.repo"
	}
	file, err := vm.run(ctx, "cat "+repository, nil, 16<<10, time.Minute)
	if err != nil {
		return err
	}
	for line := range strings.SplitSeq(string(file), "\n") {
		if value, ok := strings.CutPrefix(line, "baseurl="); ok {
			result.Origin.Configured = strings.TrimSpace(value)
		}
	}
	if result.Origin.Configured != pins.Repository {
		return errors.New("installed repository file differs from the snippet's repository")
	}
	signatures, err := vm.run(ctx, "rpm -q --qf '%{RSAHEADER:pgpsig}|%{DSAHEADER:pgpsig}|%{SIGPGP:pgpsig}|%{SIGGPG:pgpsig}\\n' lindm-agent", nil, 4096, time.Minute)
	if err != nil {
		return err
	}
	result.Signer.Method = "rpm package signature key ID"
	result.Signer.Observed = rpmSignatureKeyIDs(string(signatures))
	if len(result.Signer.Observed) == 0 {
		return errors.New("installed agent package carries no signature")
	}
	for _, id := range result.Signer.Observed {
		if !strings.HasSuffix(pins.Fingerprint, id) {
			return errors.New("installed agent package is signed by a key other than the snippet's pinned key")
		}
	}
	return nil
}

// gpgPrimaryFingerprints returns the fingerprint of each primary key.
func gpgPrimaryFingerprints(colons string) []string {
	var out []string
	primary := false
	for line := range strings.SplitSeq(colons, "\n") {
		fields := strings.Split(line, ":")
		switch {
		case fields[0] == "pub":
			primary = true
		case primary && fields[0] == "fpr" && len(fields) > 9:
			out = append(out, strings.ToUpper(fields[9]))
			primary = false
		case fields[0] == "sub":
			primary = false
		}
	}
	return out
}
