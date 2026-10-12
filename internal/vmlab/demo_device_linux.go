//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

// DemoDeviceInput is a single-use private execution handoff, not a demo spec.
// Installation is the console-generated customer script; the token is consumed
// by the installed product bootstrap CLI and never passed in argv or logged.
type DemoDeviceInput struct {
	Hostname            string `json:"hostname"`
	Desktop             bool   `json:"desktop"`
	Assistance          bool   `json:"assistance"`
	TPMBind             bool   `json:"tpm_bind"`
	InstallScript       string `json:"install_script"`
	ProvisioningCommand string `json:"provisioning_command"`
	ResumeCommand       string `json:"resume_command"`
	Token               string `json:"token"`
	// FileRoots and KernelModuleBlocklist are the owner's root executor
	// file-provider opt-in (agentv1.NativeFileProviderConfig).
	FileRoots             []string `json:"file_roots,omitempty"`
	KernelModuleBlocklist bool     `json:"kernel_module_blocklist,omitempty"`
	// PackageProvider is the owner's protojson agentv1.NativePackageProviderConfig
	// approving native package sources on this host.
	PackageProvider json.RawMessage `json:"package_provider,omitempty"`
}

// ReadDemoDeviceInput consumes a protected staging file, including on failure.
func ReadDemoDeviceInput(path string) (_ *DemoDeviceInput, err error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close(), os.Remove(path)) }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1<<20 {
		return nil, errors.New("demo device input must be a private bounded regular file")
	}
	var input DemoDeviceInput
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("demo device input has trailing data")
	}
	return &input, nil
}

// openHeldVM shares the persistent identity boundary with held assistance.
func openHeldVM(ctx context.Context, manifest *labv1.ImageManifest, options VMAssistanceOptions, resuming bool) (_ *EncryptedVM, _ *PersistentDevice, err error) {
	var vm *EncryptedVM
	switch {
	case resuming:
		state, stateErr := readPersistentVMState(options.PersistentDir)
		if stateErr != nil {
			return nil, nil, stateErr
		}
		if state.ImageID != manifest.GetId() || state.ImageSHA256 != manifest.GetSha256() {
			return nil, nil, errors.New("persistent VM manifest differs from its recorded image")
		}
		vm, err = ResumePersistentVM(ctx, options.PersistentDir)
	case options.PersistentDir != "":
		if err = os.MkdirAll(filepath.Dir(options.PersistentDir), 0700); err != nil {
			return nil, nil, err
		}
		vm, err = ProvisionPersistentVM(ctx, manifest, options.Encrypted, options.PersistentDir)
	default:
		vm, err = NewEncryptedVM(ctx, manifest, options.Encrypted)
	}
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, vm.Close())
		}
	}()
	var saved *PersistentDevice
	if resuming {
		saved, err = vm.PersistentDevice()
		if err != nil {
			return nil, nil, err
		}
		if saved == nil {
			return nil, nil, errors.New("persistent VM has incomplete enrollment; destroy it explicitly before provisioning again")
		}
	}
	return vm, saved, nil
}

// DemoDeviceVM is the organization mode of the held assistance worker. It uses
// the same host admission, remote transport, encrypted custody and desktop
// preparation; it never creates a controller or an owner enrollment.
// Progress receives operator-facing waits, such as a vendor package run.
func DemoDeviceVM(ctx context.Context, manifest *labv1.ImageManifest, options VMAssistanceOptions, input *DemoDeviceInput, progress io.Writer) (err error) {
	if options.ControlPlane == nil || options.PersistentDir == "" || options.Hold == nil || input == nil {
		return errors.New("demo device requires persistent state, controller and held callback")
	}
	defer func() { input.Token = "" }()
	if err := validateManifest(manifest); err != nil {
		return err
	}
	release := platform.ForManifest(manifest.GetDistribution(), manifest.GetVersion())
	if err := release.Gate(platform.Encryption); err != nil {
		return err
	}
	if input.Assistance {
		if err := release.Gate(platform.Assistance); err != nil {
			return err
		}
	}
	_, statErr := os.Lstat(options.PersistentDir)
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	resuming := statErr == nil
	root := filepath.Dir(options.PersistentDir)
	registered, err := demoRedHatRegistered(root)
	if err != nil {
		return err
	}
	// The authenticated DVD supplies OS dependencies only before registration.
	var media *os.File
	if !registered {
		media, err = openDemoRepositoryMedia(ctx, manifest, release.Lab.RPMMedia, options.Encrypted.CacheDir)
		if err != nil {
			return err
		}
	}
	if media != nil {
		defer func() { err = errors.Join(err, media.Close()) }()
	}
	vm, saved, err := openHeldVM(ctx, manifest, options, resuming)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, vm.Close()) }()
	vm.repositoryMedia = media
	var boot UnlockOutcome
	fallback := false
	if saved != nil && saved.TPMActionID != "" {
		boot, fallback, err = demoUnattendedBoot(ctx, vm, options.EvidenceDir, "start", input.Hostname, progress)
	} else {
		boot, err = vm.ColdBoot(ctx, vm.InitialUnlockSecret())
	}
	if err != nil {
		return err
	}
	if !resuming && !boot.PromptSeen {
		return errors.New("new encrypted demo VM did not request its passphrase")
	}
	if _, err := observeEncryptedGuest(ctx, vm, options.Encrypted.Firmware.SecureBoot); err != nil {
		return err
	}
	if _, err := routeAssistanceLocalhost(ctx, vm.guest); err != nil {
		return err
	}
	if media != nil {
		if _, err := vm.Run(ctx, "sudo -n bash -s", strings.NewReader(demoRepositoryMediaScript(release.Lab.RPMMedia))); err != nil {
			return fmt.Errorf("configure authenticated DVD repositories: %w", err)
		}
	}
	fixture, delegation, relay, err := openAssistanceFixture(ctx, options, manifest.GetArchitecture())
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, fixture.Close()) }()
	// Customer repository clients such as curl deliberately resolve localhost
	// to loopback rather than /etc/hosts. Use the console-enrollment lane's
	// pinned guest forward as well as the assistance host-alias route.
	adminForward, err := newGuestForward(ctx, vm.guest, fixture.AdminAddress, fixture.AdminAddress)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, adminForward.Close()) }()
	control, err := openVMControlPlane(ctx, options.Repository, fixture)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, control.Close(context.WithoutCancel(ctx))) }()
	if !resuming {
		if _, err := vm.Run(ctx, "sudo -n hostnamectl set-hostname "+nativeQuote(input.Hostname), nil); err != nil {
			return err
		}
		if input.Token == "" || input.InstallScript == "" {
			return errors.New("new demo device has no customer installer or provisioning token")
		}
		if err := installDemoAgent(ctx, vm, input, options.LabBinary); err != nil {
			return err
		}
		status, err := waitGuestExecutorReady(ctx, vm.guest, agentv1.Lifecycle_LIFECYCLE_ENROLLED)
		if err != nil {
			return err
		}
		saved = &PersistentDevice{DeviceID: status.GetDeviceId()}
		if err := vm.SavePersistentDevice(saved); err != nil {
			return err
		}
	}
	if err := waitNativeActionPresence(ctx, control.session, saved.DeviceID); err != nil {
		return err
	}
	authority, err := control.executionAuthority(ctx)
	if err != nil {
		return err
	}
	if _, err := waitVMExecutionTrust(ctx, vm.guest, authority, delegation); err != nil {
		return err
	}
	var files *agentv1.NativeFileProviderConfig
	if len(input.FileRoots) != 0 || input.KernelModuleBlocklist {
		files = &agentv1.NativeFileProviderConfig{AllowedRoots: input.FileRoots, KernelModuleBlocklist: input.KernelModuleBlocklist}
	}
	var packages *agentv1.NativePackageProviderConfig
	if len(input.PackageProvider) != 0 {
		packages = new(agentv1.NativePackageProviderConfig)
		if err := protojson.Unmarshal(input.PackageProvider, packages); err != nil {
			return fmt.Errorf("decode demo package provider: %w", err)
		}
	}
	if files != nil || packages != nil {
		if err := configureDemoExecutor(ctx, vm.guest, files, packages); err != nil {
			return err
		}
	}
	if input.TPMBind && saved.TPMActionID == "" {
		if err := waitDemoPackageHolder(ctx, vm.guest, input.Hostname, progress); err != nil {
			return err
		}
		bound, err := bindDemoTPM(ctx, vm, manifest, control, saved, options.EvidenceDir, input.Hostname, progress)
		if err != nil {
			return err
		}
		fallback = fallback || bound
		// The independent TPM cold boot closes the old guest SSH transport.
		if err := adminForward.Close(); err != nil {
			return err
		}
		reopened, err := newGuestForward(ctx, vm.guest, fixture.AdminAddress, fixture.AdminAddress)
		if err != nil {
			return err
		}
		adminForward = reopened
	}
	if release.Lab.Entitlement {
		if err := registerDemoRedHat(ctx, vm.guest, root, options.RedHatTokenFile, options.LabBinary); err != nil {
			return err
		}
		// Advisory matching needs the entitled repositories in current host
		// inventory, so request the product's inventory refresh on each start.
		status, err := waitGuestExecutorReady(ctx, vm.guest, agentv1.Lifecycle_LIFECYCLE_ENROLLED)
		if err != nil {
			return err
		}
		refresh := actionRequestFor(saved.DeviceID, status.GetEnrollmentGeneration(), &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_RefreshInventory{RefreshInventory: &agentv1.RefreshInventoryAction{}}})
		if _, _, err := dispatchNativeAction(ctx, vm.guest, control.session, refresh, nil, false); err != nil {
			return fmt.Errorf("refresh registered server inventory: %w", err)
		}
	}
	ready := options.Hold
	options.Hold = func(access *AssistanceHold) error {
		access.TPMActionID, access.Resumed, access.TPMPassphraseFallback = saved.TPMActionID, resuming, fallback
		return ready(access)
	}
	if input.Desktop {
		desktop, err := labDesktopFor(options.Encrypted.Desktop, release)
		if err != nil {
			return err
		}
		if input.Assistance {
			if err := waitDemoPackageHolder(ctx, vm.guest, input.Hostname, progress); err != nil {
				return err
			}
			if err := installAssistanceCapture(ctx, vm.guest, release); err != nil {
				return err
			}
			if err := configureAssistanceGuest(ctx, vm.guest); err != nil {
				return err
			}
		}
		// One-time desktop provisioning follows its saved marker, not mere
		// state existence: an earlier run may have stopped before reaching it.
		if _, err := prepareAssistanceDesktop(ctx, vm, desktop, release, saved.DesktopPrepared); err != nil {
			return err
		}
		if !saved.DesktopPrepared {
			saved.DesktopPrepared = true
			if err := vm.SavePersistentDevice(saved); err != nil {
				return err
			}
		}
		guest := &assistanceGuestEvidence{}
		if input.Assistance {
			if err := waitAssistanceSessionUnit(ctx, vm.guest, desktop, guest); err != nil {
				return err
			}
		}
		evidence, err := newAssistanceEvidence(options.EvidenceDir)
		if err != nil {
			return err
		}
		result := &VMAssistanceResult{DeviceID: saved.DeviceID, Relay: relay, Guest: guest}
		screen := &assistanceScreen{vm: vm.guest, evidence: evidence, result: result}
		if _, err := screen.captureReference(ctx); err != nil {
			return err
		}
		return holdAssistance(ctx, vm, fixture, screen, result, options.Hold, true, nil, true)
	}
	if err := options.Hold(&AssistanceHold{DeviceID: saved.DeviceID, Hostname: input.Hostname, ConsoleOrigin: fixture.ConsoleOrigin, Persistent: true, ExistingAccount: true}); err != nil {
		return err
	}
	return waitHeldVM(ctx, vm)
}

func installDemoAgent(ctx context.Context, vm *EncryptedVM, input *DemoDeviceInput, labBinary string) error {
	installed, err := vm.guest.runResult(ctx, "sudo -n env DEBIAN_FRONTEND=noninteractive sh -eu", strings.NewReader(input.InstallScript), 1<<20, 30*time.Minute)
	if err != nil {
		return err
	}
	if installed.ExitCode != 0 {
		return fmt.Errorf("customer repository installation exited %d: %s", installed.ExitCode, installed.Stderr)
	}
	// Install from the real repository before introducing any lab observer.
	// Readiness below invokes this architecture-matched probe, not a golden file.
	if _, err := vm.guest.run(ctx, "sudo -n install -d -m 0755 /var/tmp/lindm-native-lab", nil, 4096, time.Minute); err != nil {
		return err
	}
	if err := uploadLifecycleProbe(ctx, vm.guest, labBinary); err != nil {
		return err
	}
	if _, err := waitGuestExecutorReady(ctx, vm.guest, agentv1.Lifecycle_LIFECYCLE_UNPROVISIONED); err != nil {
		return err
	}
	secret := []byte(input.Token)
	defer clear(secret)
	if _, err := vm.Run(ctx, "sudo -n sh -eu -c 'umask 077; cat > /etc/lindm/provisioning-token'", bytes.NewReader(secret)); err != nil {
		return err
	}
	command := "trap 'rm -f /etc/lindm/provisioning-token' EXIT\n" + input.ProvisioningCommand + "\n" + input.ResumeCommand + "\nsystemctl enable --now lindm-executor.service lindm-agent.service\nsystemctl restart lindm-agent.service\n"
	result, err := vm.guest.runResult(ctx, "sudo -n sh -eu", strings.NewReader(command), 64<<10, 65*time.Minute)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("customer provisioning command exited %d (secret-bearing output withheld)", result.ExitCode)
	}
	return nil
}

// demoFileRootsScript creates each absent approved root, as root with umask 022
// (root:root 0755). An existing directory is never changed.
const demoFileRootsScript = `umask 022; for root do test -d "$root" || mkdir -p -- "$root"; done`

// configureDemoExecutor writes the owner's root executor file-provider and
// package-source opt-ins (each only when given) into /etc/lindm/executor.json,
// preserving every other setting, and restarts only the executor when it
// changed. The network process never receives them; this is the device
// owner's local configuration. An approved file root must exist: Ubuntu 24.04
// ships no /etc/motd.d although its pam_motd reads it.
func configureDemoExecutor(ctx context.Context, vm *guestVM, files *agentv1.NativeFileProviderConfig, packages *agentv1.NativePackageProviderConfig) error {
	for _, provider := range []proto.Message{files, packages} {
		if !provider.ProtoReflect().IsValid() {
			continue
		}
		if err := protovalidate.Validate(provider); err != nil {
			return err
		}
	}
	if roots := files.GetAllowedRoots(); len(roots) != 0 {
		command := "sudo -n sh -eu -c " + nativeQuote(demoFileRootsScript) + " sh"
		for _, root := range roots {
			command += " " + nativeQuote(root)
		}
		created, err := vm.runResult(ctx, command, nil, 16<<10, time.Minute)
		if err != nil {
			return fmt.Errorf("create approved file roots: %w", err)
		}
		if created.ExitCode != 0 {
			return fmt.Errorf("create approved file roots: exit %d: %s", created.ExitCode, created.Stderr)
		}
	}
	data, err := vm.run(ctx, "sudo -n cat /etc/lindm/executor.json", nil, 1<<20, 10*time.Second)
	if err != nil {
		return err
	}
	config := new(agentv1.AgentConfig)
	if err := protojson.Unmarshal(data, config); err != nil {
		return err
	}
	changed := false
	if files != nil && !proto.Equal(config.GetFileProvider(), files) {
		config.FileProvider, changed = files, true
	}
	if packages != nil && !proto.Equal(config.GetPackageProvider(), packages) {
		config.PackageProvider, changed = packages, true
	}
	if !changed {
		return nil
	}
	if data, err = protojson.Marshal(config); err != nil {
		return err
	}
	command := "sudo -n sh -eu -c " + nativeQuote("umask 077; cat > /etc/lindm/executor.json.lindm; chown root:root /etc/lindm/executor.json.lindm; chmod 0600 /etc/lindm/executor.json.lindm; mv /etc/lindm/executor.json.lindm /etc/lindm/executor.json; systemctl restart lindm-executor.service")
	configured, err := vm.runResult(ctx, command, bytes.NewReader(data), 16<<10, time.Minute)
	if err != nil {
		return fmt.Errorf("configure executor providers: %w", err)
	}
	if configured.ExitCode != 0 {
		return fmt.Errorf("configure executor providers: exit %d: %s", configured.ExitCode, configured.Stderr)
	}
	_, err = waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED)
	return err
}

// bindDemoTPM dispatches the product TPM2 bind and then cold boots without a
// secret. It reports whether that boot fell back to the owner passphrase.
func bindDemoTPM(ctx context.Context, vm *EncryptedVM, manifest *labv1.ImageManifest, control *vmControlPlane, saved *PersistentDevice, evidenceDir, hostname string, progress io.Writer) (bool, error) {
	if err := installActionPrerequisites(ctx, vm.guest, manifest, false); err != nil {
		return false, err
	}
	targets, err := observeActionTargets(ctx, vm)
	if err != nil {
		return false, err
	}
	var target *agentv1.StorageTarget
	for _, item := range targets {
		if item.Identity.GetLuksUuid() == "" {
			continue
		}
		if target != nil {
			return false, errors.New("demo requires exactly one encrypted root target")
		}
		target = item.Identity
	}
	if target == nil {
		return false, errors.New("demo encrypted root target unavailable")
	}
	provider := &agentv1.DeviceActionProviderConfig{Targets: []*agentv1.QualifiedActionTarget{{Target: target, OwnerRecoveryKeyslot: 0, AllowTpm2Binding: true}}}
	if err := configureActionGuest(ctx, vm.guest, provider, nil); err != nil {
		return false, err
	}
	status, err := waitGuestExecutorReady(ctx, vm.guest, agentv1.Lifecycle_LIFECYCLE_ENROLLED)
	if err != nil {
		return false, err
	}
	request := actionRequestFor(saved.DeviceID, status.GetEnrollmentGeneration(), &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Tpm2Bind{Tpm2Bind: &agentv1.TPM2BindAction{Target: target, Pcrs: []uint32{7}}}})
	request.Reason = "Bind persistent organization demo encrypted root to its owned virtual TPM"
	credential := []byte(vm.InitialUnlockSecret())
	defer clear(credential)
	action, _, err := dispatchNativeAction(ctx, vm.guest, control.session, request, credential, false)
	if err != nil {
		return false, err
	}
	saved.TPMActionID = action.ActionID
	if err := vm.SavePersistentDevice(saved); err != nil {
		return false, err
	}
	if err := vm.PowerOff(ctx); err != nil {
		return false, err
	}
	_, fallback, err := demoUnattendedBoot(ctx, vm, evidenceDir, "bind", hostname, progress)
	if err != nil {
		return fallback, err
	}
	return fallback, waitNativeActionPresence(ctx, control.session, saved.DeviceID)
}

func waitHeldVM(ctx context.Context, vm *EncryptedVM) error {
	select {
	case <-ctx.Done():
		return nil
	case <-vm.guest.done:
		return errors.New("demo VM exited")
	}
}
