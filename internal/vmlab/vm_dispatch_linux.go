//go:build linux

package vmlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/devlab"
	"lindm/internal/packaging"
	"lindm/internal/platform"
)

const dispatchUnit = "labdispatch.service"
const dispatchWitness = "/var/lib/labdispatch.starts"
const dispatchReconcileIntervalSeconds = 300

// A slow, inert native start makes the open action observable across a real
// server restart. This fixture is installed before enrollment, never as policy.
const dispatchUnitDefinition = `[Unit]
Description=Disposable connected dispatch witness
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/usr/bin/sleep 20
ExecStart=/bin/sh -c 'echo started >> /var/lib/labdispatch.starts'
[Install]
WantedBy=multi-user.target
`

type VMDispatchOptions struct {
	Repository, CacheDir, WorkDir, DiagnosticsDir, LabBinary, LindmdBinary string
	BuildRepository                                                        string
	RedHatTokenFile                                                        string
	Hardware                                                               *VMHardwareOptions
	Hold                                                                   time.Duration
	Progress                                                               io.Writer
	// LocalAuthority uses the real password/WebAuthn authority without an IdP.
	LocalAuthority        bool
	PowerActions          bool
	RuntimeAuthorization  bool
	AdvisoryExceptions    bool
	Resources             bool
	ResourceExecutionOnly bool
	// Advisories qualifies real vendor feeds against this enrolled guest.
	Advisories bool
	// ResourceKinds selects connected lane kind groups; see resourceKindSelection.
	ResourceKinds map[string]bool
	// ReleaseUpgrade runs the connected profile across the vendor's in-place
	// release upgrade (see exerciseReleaseUpgrade); it requires guest egress.
	ReleaseUpgrade bool
}

type VMDispatchScenario struct {
	Name                   string                         `json:"name"`
	StartedAt              time.Time                      `json:"started_at"`
	FinishedAt             time.Time                      `json:"finished_at"`
	Action                 *adminv1.ResourceActionSummary `json:"action,omitempty"`
	Assignment             *adminv1.ResourceAssignment    `json:"assignment,omitempty"`
	Resource               *adminv1.ResourceState         `json:"resource,omitempty"`
	RevocationApproval     *adminv1.Approval              `json:"revocation_approval,omitempty"`
	NativeBeforeActive     string                         `json:"native_before_active,omitempty"`
	NativeBeforeEnablement string                         `json:"native_before_enablement,omitempty"`
	NativeActive           string                         `json:"native_active,omitempty"`
	NativeEnablement       string                         `json:"native_enablement,omitempty"`
	StartWitness           string                         `json:"start_witness,omitempty"`
	Coverage               string                         `json:"coverage"`
}

type VMDispatchResult struct {
	Distribution                     string                          `json:"distribution"`
	Version                          string                          `json:"version"`
	RepositorySnapshotDate           string                          `json:"repository_snapshot_date,omitempty"`
	RepositorySnapshotManifestSHA256 string                          `json:"repository_snapshot_manifest_sha256,omitempty"`
	RepositorySnapshotRepomdSHA256   string                          `json:"repository_snapshot_repomd_sha256,omitempty"`
	ImageID                          string                          `json:"image_id"`
	ImageSHA256                      string                          `json:"image_sha256"`
	PackageSHA256                    string                          `json:"package_sha256"`
	LabSHA256                        string                          `json:"lab_sha256"`
	LindmdSHA256                     string                          `json:"lindmd_sha256"`
	SignerFingerprint                string                          `json:"signer_fingerprint"`
	DeviceID                         string                          `json:"device_id"`
	Generation                       string                          `json:"generation"`
	Database                         string                          `json:"database"`
	Runtime                          *vmRuntimeEvidence              `json:"runtime,omitempty"`
	RedHat                           *VMRedHatEvidence               `json:"redhat,omitempty"`
	SELinux                          string                          `json:"selinux"`
	Baseline                         string                          `json:"baseline"`
	Scenarios                        []VMDispatchScenario            `json:"scenarios"`
	RecentActions                    []*adminv1.DeviceResourceAction `json:"recent_actions,omitempty"`
	StartedAt                        time.Time                       `json:"started_at"`
	FinishedAt                       time.Time                       `json:"finished_at"`
	Passed                           bool                            `json:"passed"`
	Failure                          string                          `json:"failure,omitempty"`
	ClockSkew                        []*VMDispatchClockEvidence      `json:"clock_skew,omitempty"`
	Hold                             *VMDispatchHoldEvidence         `json:"hold,omitempty"`
	Power                            *VMPowerEvidence                `json:"power,omitempty"`
	Resources                        *VMResourceEvidence             `json:"resources,omitempty"`
	RecoveryReadiness                *VMRecoveryReadinessEvidence    `json:"recovery_readiness,omitempty"`
	Architecture                     string                          `json:"architecture,omitempty"`
	ReleaseUpgrade                   *VMReleaseUpgradeEvidence       `json:"release_upgrade,omitempty"`
	RuntimeAuthorization             *VMRuntimeAuthorizationEvidence `json:"runtime_authorization,omitempty"`
	Advisories                       *VMAdvisoryEvidence             `json:"advisories,omitempty"`
	AdvisoryExceptions               *VMAdvisoryApprovalEvidence     `json:"advisory_exceptions,omitempty"`
}

// DispatchVM uses the same native builders, authenticated package installers,
// isolated server/database and enrollment helpers as the lifecycle lane. All
// execution authority after trust admission comes from the real server/relay.
func DispatchVM(ctx context.Context, manifest *labv1.ImageManifest, options VMDispatchOptions) (result *VMDispatchResult, err error) {
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	if options.ResourceExecutionOnly && !options.Resources {
		return nil, errors.New("direct resource execution requires the resource lane")
	}
	if options.RuntimeAuthorization && (!options.LocalAuthority || options.Resources || options.PowerActions || options.Hold != 0 || options.ReleaseUpgrade) {
		return nil, errors.New("runtime authorization requires local authority without another dispatch scenario")
	}
	if options.AdvisoryExceptions && (!options.LocalAuthority || options.Resources || options.PowerActions || options.Hold != 0 || options.ReleaseUpgrade || options.RuntimeAuthorization) {
		return nil, errors.New("advisory exception qualification requires isolated local authority without other dispatch scenarios")
	}
	release := manifestRelease(manifest)
	if options.Advisories {
		if err := release.LabLaneOn(platform.LaneAdvisories, manifest.GetArchitecture()); err != nil {
			return nil, err
		}
		if options.Resources || options.PowerActions || options.Hold != 0 {
			return nil, errors.New("advisories run without resource, power or hold scenarios")
		}
		if _, err := vmAdvisorySource(release, manifest.GetArchitecture()); err != nil {
			return nil, err
		}
	}
	if options.Resources {
		if err := release.LabLane(platform.LaneResources); err != nil {
			return nil, err
		}
		if options.PowerActions || options.Hold != 0 {
			return nil, errors.New("native resource lane runs without power actions or console hold")
		}
	}
	if (options.ResourceKinds["secret-password"] || options.ResourceKinds["local-admin"]) && (!options.Resources || options.ResourceExecutionOnly) {
		return nil, errors.New("secret delivery and managed local-admin kinds require the connected resource phase")
	}
	// Step-up and the second human's approval exist only in the local authority.
	if options.ResourceKinds["local-admin"] && !options.LocalAuthority {
		return nil, errors.New("the local-admin kind requires -local-authority for reveal step-up and approval")
	}
	budget := 50 * time.Minute
	if options.ReleaseUpgrade {
		if !options.Resources || options.ResourceExecutionOnly || options.Hardware == nil || !options.Hardware.AllowNetwork {
			return nil, errors.New("release upgrade requires the connected resource phase and explicit guest egress (-allow-network) to the vendor archive")
		}
		if _, _, err := releaseUpgradePath(manifest); err != nil {
			return nil, err
		}
		budget = releaseUpgradeBudget
	}
	format, err := NativePackageFormat(release)
	if err != nil {
		return nil, err
	}
	if err := validateVMRedHatToken(release, options.RedHatTokenFile); err != nil {
		return nil, err
	}
	if options.Hold < 0 || options.Hold > time.Hour || (options.Hold > 0 && options.Progress == nil) {
		return nil, errors.New("dispatch hold requires a progress writer and a duration between zero and one hour")
	}
	result = &VMDispatchResult{Distribution: manifest.GetDistribution(), Version: manifest.GetVersion(), ImageID: manifest.GetId(), StartedAt: time.Now().UTC()}
	result.RepositorySnapshotDate = manifest.GetRepositorySnapshotDate()
	result.RepositorySnapshotManifestSHA256 = manifest.GetRepositorySnapshotManifestSha256()
	result.RepositorySnapshotRepomdSHA256 = manifest.GetRepositorySnapshotRepomdSha256()
	defer func() {
		result.FinishedAt = time.Now().UTC()
		result.Passed = err == nil
		if err != nil {
			result.Failure = err.Error()
		}
	}()
	parent := ctx
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), budget+options.Hold)
	defer cancel()
	stopParentCancellation := context.AfterFunc(parent, cancel)
	defer stopParentCancellation()
	result.LabSHA256, err = dispatchFileDigest(options.LabBinary)
	if err != nil {
		return result, err
	}
	result.LindmdSHA256, err = dispatchFileDigest(options.LindmdBinary)
	if err != nil {
		return result, err
	}
	work, err := os.MkdirTemp(options.WorkDir, "lindm-dispatch-packages-")
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(work)) }()
	signer, err := packaging.GenerateDevelopmentSigner(ctx, work)
	if err != nil {
		return result, err
	}
	var architecture string
	switch manifest.GetArchitecture() {
	case "amd64", "x86_64":
		architecture = "amd64"
	case "arm64", "aarch64":
		architecture = "arm64"
	default:
		return result, errors.New("dispatch packages require a supported guest architecture")
	}
	result.Architecture = architecture
	built, err := packaging.BuildSource(ctx, packaging.SourceRequest{Repository: VMBuildRepository(options.Repository, options.BuildRepository), Revision: "connected-dispatch-lab", BuildRequest: packaging.BuildRequest{Version: "0.1.0", TargetArchitecture: architecture, OutputDir: work, Formats: []packaging.Format{format}, Signer: *signer}})
	if err != nil {
		return result, err
	}
	artifact := built.Artifacts[0]
	result.PackageSHA256, result.SignerFingerprint = artifact.SHA256, signer.Fingerprint
	publicKey := built.PublicKey
	var apt *packaging.APTRepository
	var arch []*packaging.ArchRepository
	if format == packaging.FormatArch {
		output := filepath.Join(work, "arch-repo")
		if err := os.Mkdir(output, 0700); err != nil {
			return result, err
		}
		repo, err := packaging.PublishArch(ctx, packaging.ArchRequest{OutputDir: output, Packages: []string{artifact.Path}, Signer: *signer})
		if err != nil {
			return result, err
		}
		arch = []*packaging.ArchRepository{repo}
		publicKey = repo.PublicKeyArmor
	}
	if format == packaging.FormatDEB {
		output := filepath.Join(work, "apt")
		if err := os.Mkdir(output, 0700); err != nil {
			return result, err
		}
		apt, err = packaging.PublishAPT(ctx, packaging.APTRequest{OutputDir: output, DEBs: []string{artifact.Path}, Signer: *signer})
		if err != nil {
			return result, err
		}
		publicKey = apt.PublicKeyArmor
	}
	if options.ResourceKinds["firewall"] && (!options.Resources || options.ResourceExecutionOnly) {
		return result, errors.New("the firewall kind requires the connected resource phase")
	}
	hardware := options.Hardware
	var firewall *firewallLane
	if options.ResourceKinds["firewall"] {
		firewall, hardware, err = newFirewallLane(ctx, manifest, options.CacheDir, options.WorkDir, options.Hardware)
		if err != nil {
			return result, err
		}
		defer func() { err = errors.Join(err, firewall.Close()) }()
	}
	vm, verified, err := newVerifiedGuestWithHardware(ctx, manifest, options.CacheDir, options.WorkDir, true, hardware)
	if err != nil {
		return result, err
	}
	defer func() {
		if result.Power != nil && result.Power.QEMUExited {
			err = errors.Join(err, vm.closeAfterExpectedExit())
		} else {
			err = errors.Join(err, vm.close())
		}
	}()
	vm.captureDiagnostics = options.DiagnosticsDir != ""
	defer func() {
		if err != nil && options.DiagnosticsDir != "" {
			err = errors.Join(err, saveLifecycleFailure(ctx, vm, options.DiagnosticsDir))
		}
	}()
	result.ImageSHA256 = verified.SHA256
	if err := vm.connect(ctx); err != nil {
		return result, err
	}
	result.Runtime, err = vm.runtimeEvidence(ctx)
	if err != nil {
		return result, err
	}
	if _, err := vm.run(ctx, "sudo -n cloud-init status --wait --format=json", nil, 64<<10, 5*time.Minute); err != nil {
		return result, err
	}
	if err := pinArchRepositories(ctx, vm, manifest); err != nil {
		return result, err
	}
	snapshot, err := prepareGuestRollingSnapshot(ctx, vm, manifest, options.CacheDir)
	if err != nil {
		return result, err
	}
	if snapshot != nil {
		defer func() { err = errors.Join(err, snapshot.Close()) }()
	}
	backend, err := nativeBackend(release)
	if err != nil {
		return result, err
	}
	if backend.DNF() {
		mode, err := vm.run(ctx, "getenforce", nil, 128, 10*time.Second)
		if err != nil {
			return result, err
		}
		result.SELinux = strings.TrimSpace(string(mode))
		if result.SELinux != "Enforcing" {
			return result, errors.New("dispatch on the DNF family requires SELinux Enforcing")
		}
	} else {
		// Leap 16 and Tumbleweed enforce SELinux by default; record the
		// kernel's state instead of assuming the family has no SELinux.
		if result.SELinux, err = guestSELinuxMode(ctx, vm); err != nil {
			return result, err
		}
	}
	packages, err := newNativeGuestPackages(ctx, vm, artifact, artifact, apt, publicKey, signer.Fingerprint, arch...)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, packages.Close()) }()
	packages.rollingSnapshot = rollingSnapshotDesired(manifest, snapshot)
	if err := uploadLifecycleProbe(ctx, vm, options.LabBinary); err != nil {
		return result, err
	}
	if options.RedHatTokenFile != "" {
		result.RedHat = new(VMRedHatEvidence)
	}
	registration, err := registerVMRedHat(ctx, vm, options.RedHatTokenFile, result.RedHat)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, registration.Close()) }()
	if err := packages.InstallFirst(ctx); err != nil {
		return result, err
	}
	if firewall != nil {
		if err := firewall.installPeer(ctx, manifest, artifact, apt, publicKey, signer.Fingerprint, arch...); err != nil {
			return result, fmt.Errorf("install probe peer package: %w", err)
		}
	}
	if options.Resources {
		result.Resources = newVMResourceEvidence()
		if err := setupVMResourceFixtures(ctx, packages, architecture, options.ResourceKinds); err != nil {
			return result, err
		}
		result.Resources.Fixture, err = resourceFixtureEvidence(ctx, packages)
		if err != nil {
			return result, err
		}
	}
	if err := packages.uploadBytes(ctx, nativeGuestDir+"/dispatch.service", []byte(dispatchUnitDefinition)); err != nil {
		return result, err
	}
	if err := lifecycleCommand(ctx, vm, "install inert dispatch fixture before enrollment", "test ! -e /etc/systemd/system/"+dispatchUnit+"; test ! -e "+dispatchWitness+"; install -o root -g root -m 0644 "+nativeGuestDir+"/dispatch.service /etc/systemd/system/"+dispatchUnit+"; if command -v restorecon >/dev/null 2>&1; then restorecon -F /etc/systemd/system/"+dispatchUnit+"; fi; systemctl daemon-reload"); err != nil {
		return result, err
	}
	if err := vmServiceNativeUnit(ctx, vm, dispatchUnit, "inactive", "disabled"); err != nil {
		return result, err
	}
	result.Baseline = "inactive/disabled; persistent start witness absent"
	openFixture := devlab.OpenAuthorityFixture
	if options.LocalAuthority {
		openFixture = devlab.OpenLocalAuthorityFixture
	}
	if options.RuntimeAuthorization {
		openFixture = devlab.OpenLocalConsoleAuthorityFixture
	}
	if options.Hold > 0 {
		if options.LocalAuthority {
			return result, errors.New("local-authority dispatch does not reserve the shared console origin")
		}
		openFixture = devlab.OpenConsoleAuthorityFixture
	}
	fixture, err := openFixture(ctx, options.Repository, options.LindmdBinary)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, fixture.Close()) }()
	result.Database = fixture.DatabaseName
	var delegation *agentv1.UpdateExecutionTrustRequest
	var resourceSigner *devlab.ExecutionTrustExercise
	if options.ResourceExecutionOnly {
		resourceSigner, err = devlab.CreateExecutionTrustExercise(ctx, options.Repository)
		if err != nil {
			return result, err
		}
		defer resourceSigner.Close()
		delegation = resourceSigner.Initial
	} else {
		configure := fixture.ConfigureServiceDispatch
		if options.ResourceKinds["secret-password"] || options.ResourceKinds["local-admin"] {
			configure = fixture.ConfigureServiceDispatchWithEscrow
		}
		delegation, err = configure(ctx)
		if err != nil {
			return result, err
		}
	}
	if firewall != nil {
		authority, err := fixture.ConfigureConnectivityProbes(ctx, firewall.targets, netip.MustParseAddr(firewallPeer4))
		if err != nil {
			return result, fmt.Errorf("configure controller connectivity probes: %w", err)
		}
		peer, err := firewall.provisionPeer(ctx, authority)
		if err != nil {
			return result, fmt.Errorf("provision probe peer: %w", err)
		}
		result.Resources.Fixture = append(result.Resources.Fixture, peer...)
	}
	guestAddresses := [2]string{"127.0.0.1:18444", "127.0.0.1:18445"}
	if options.RuntimeAuthorization {
		// Console sessions and the ordinary CLI use the actual dynamic origin.
		// Forward its signed enrollment port, not the legacy fixture alias.
		guestAddresses[0] = fixture.AdminAddress
	}
	forwards, err := openGuestForwards(ctx, vm, guestAddresses, [2]string{fixture.AdminAddress, fixture.DeviceAddress})
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, closeLifecycleForwards(forwards)) }()
	control, err := openVMControlPlane(ctx, options.Repository, fixture)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, control.Close(context.WithoutCancel(ctx))) }()
	if err := control.applyExecutionAuthority(ctx, delegation, 1, 1, 0); err != nil {
		return result, err
	}
	if _, err := waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_UNPROVISIONED); err != nil {
		return result, err
	}
	material, err := control.BootstrapMaterial(ctx)
	if err != nil {
		return result, err
	}
	issued, err := interruptBootstrap(ctx, vm, material)
	clear(material.GrantSecret)
	material.GrantSecret = nil
	if err != nil {
		return result, err
	}
	if err := control.TrackDevice(issued.GetDeviceId()); err != nil {
		return result, err
	}
	if err := lifecycleCommand(ctx, vm, "resume installed enrollment", packaging.BinaryPath+" resume"); err != nil {
		return result, err
	}
	result.DeviceID, result.Generation = issued.GetDeviceId(), issued.GetEnrollmentGeneration()
	if err := lifecycleCommand(ctx, vm, "start automatic enrolled relay", "systemctl restart lindm-agent.service"); err != nil {
		return result, err
	}
	authority, err := control.executionAuthority(ctx)
	if err != nil {
		return result, err
	}
	if _, err := waitVMExecutionTrust(ctx, vm, authority, delegation); err != nil {
		return result, err
	}
	if options.Advisories {
		result.Advisories, err = exerciseVMAdvisories(ctx, vm, control, fixture, manifest, options.CacheDir, result.DeviceID)
		return result, err
	}
	if options.ResourceExecutionOnly {
		if err := control.applyExecutionAuthority(ctx, resourceSigner.Rotated, 2, 2, 1); err != nil {
			return result, err
		}
		rotated, err := control.executionAuthority(ctx)
		if err != nil {
			return result, err
		}
		if _, err := waitVMExecutionTrust(ctx, vm, rotated, resourceSigner.Rotated); err != nil {
			return result, err
		}
		err = exerciseSignedNativeResources(ctx, packages, resourceSigner, result)
		return result, err
	}
	if options.RuntimeAuthorization {
		err = exerciseRuntimeAuthorization(ctx, vm, fixture, result)
		return result, err
	}
	if options.AdvisoryExceptions {
		result.AdvisoryExceptions = new(VMAdvisoryApprovalEvidence)
		err = exerciseAdvisoryApproval(ctx, vm, control, fixture, result, release, manifest.GetArchitecture(), filepath.Join(filepath.Dir(options.CacheDir), "advisory-feeds"))
		return result, err
	}
	if options.Resources {
		// A deliberate guest reboot closes and reopens the control-plane
		// forwards; firewall restore and sysctl persistence cross real boots.
		reboot := func(ctx context.Context) error {
			boot, err := firewallBootID(ctx, vm)
			if err != nil {
				return err
			}
			err = closeLifecycleForwards(forwards)
			forwards = nil
			if err != nil {
				return err
			}
			if err := rebootLifecycleGuest(ctx, vm, boot); err != nil {
				return err
			}
			forwards, err = openLifecycleForwards(ctx, vm, [2]string{fixture.AdminAddress, fixture.DeviceAddress})
			return err
		}
		// The update policy's own logind reboot is awaited, never triggered.
		awaitReboot := func(ctx context.Context, previousBoot string, timeout time.Duration) error {
			previous, err := uuid.Parse(previousBoot)
			if err != nil || previous == uuid.Nil {
				return errors.New("previous guest boot ID is invalid")
			}
			err = closeLifecycleForwards(forwards)
			forwards = nil
			if err != nil {
				return err
			}
			if err := awaitLifecycleGuestBoot(ctx, vm, previous, timeout); err != nil {
				return err
			}
			forwards, err = openLifecycleForwards(ctx, vm, [2]string{fixture.AdminAddress, fixture.DeviceAddress})
			return err
		}
		if firewall != nil {
			firewall.rebootDevice = reboot
		}
		if options.ReleaseUpgrade {
			err = exerciseReleaseUpgrade(ctx, packages, control, fixture, result, manifest, filepath.Join(filepath.Dir(options.CacheDir), "advisory-feeds"), reboot)
			return result, err
		}
		err = exerciseConnectedResources(ctx, packages, control, result, options.ResourceKinds, firewall, release.Lab.Updater, reboot, awaitReboot)
		return result, err
	}
	if options.PowerActions {
		result.Power = new(VMPowerEvidence)
		err = exerciseNativePower(ctx, vm, control, fixture, result, result.Power)
		return result, err
	}
	result.RecoveryReadiness, err = waitVMRecoveryReadiness(ctx, vm, control, result.DeviceID)
	if err != nil {
		return result, err
	}
	hold := func() error {
		return holdDispatchConsole(ctx, parent, stopParentCancellation, options, control, fixture, result)
	}
	if err := exerciseConnectedDispatch(ctx, vm, control, fixture, result, hold); err != nil {
		return result, err
	}
	return result, nil
}

func dispatchFileDigest(path string) (_ string, err error) {
	file, err := openRegular(path)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func dispatchWitnessValue(ctx context.Context, vm *guestVM) (string, error) {
	value, err := vm.run(ctx, "sudo -n cat "+dispatchWitness, nil, 1024, 10*time.Second)
	return string(value), err
}

func (c *vmControlPlane) dispatchState(ctx context.Context, deviceID string) (*adminv1.GetDeviceResourceStateResponse, error) {
	response, err := c.session.Admin.GetDeviceResourceState(ctx, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: deviceID}))
	if err != nil {
		return nil, fmt.Errorf("read dispatch state: %w", err)
	}
	return response.Msg, nil
}

func (c *vmControlPlane) assignDispatch(ctx context.Context, deviceID, head string, revision *adminv1.ProfileRevision) (*adminv1.ResourceAssignment, error) {
	request := &adminv1.SetResourceAssignmentRequest{RequestId: uuid.NewString(), DeviceId: deviceID, Target: &adminv1.ResourceAssignmentTarget{ProfileId: revision.GetProfileId(), RevisionId: revision.GetRevisionId()}, ReconcileIntervalSeconds: proto.Uint32(dispatchReconcileIntervalSeconds), Reason: "disposable connected native dispatch qualification"}
	if head != "" {
		request.ExpectedAssignmentId = proto.String(head)
	}
	response, err := c.session.Admin.SetResourceAssignment(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, err
	}
	return response.Msg.GetAssignment(), nil
}

func waitDispatchAction(ctx context.Context, control *vmControlPlane, deviceID, head string, open bool) (*adminv1.ResourceActionSummary, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	var last *adminv1.GetDeviceResourceStateResponse
	for {
		state, err := control.dispatchState(ctx, deviceID)
		if err != nil {
			return nil, err
		}
		last = state
		if state.GetAssignment().GetAssignmentId() != head || len(state.GetResources()) != 1 {
			return nil, errors.New("dispatch read model changed assignment or resource cardinality")
		}
		resource := state.GetResources()[0]
		action := resource.GetLatestAction()
		if open && action != nil && action.GetClosedAt() == nil && action.GetStartAuthorizedAt() != nil {
			return action, nil
		}
		if !open && resource.GetDisposition() == adminv1.ResourceDisposition_RESOURCE_DISPOSITION_SUCCEEDED {
			if action == nil || action.GetStatus().GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED || action.GetAttestedAt() == nil || action.GetReceivedAt() == nil || action.GetActionRevision() == 0 || action.GetClosedReason() != "result" {
				return nil, errors.New("SUCCEEDED lacks verified device history and server closure")
			}
			return action, nil
		}
		if resource.GetDisposition() == adminv1.ResourceDisposition_RESOURCE_DISPOSITION_ATTENTION || resource.GetDisposition() == adminv1.ResourceDisposition_RESOURCE_DISPOSITION_BLOCKED {
			return nil, fmt.Errorf("dispatch cannot converge: %s", state)
		}
		if err := lifecycleDelay(ctx, 250*time.Millisecond); err != nil {
			return nil, fmt.Errorf("wait for dispatch open=%t: %w; last=%s", open, err, last)
		}
	}
}

func exerciseConnectedDispatch(ctx context.Context, vm *guestVM, control *vmControlPlane, fixture *devlab.AuthorityFixture, result *VMDispatchResult, hold func() error) error {
	request := &adminv1.PublishProfileRevisionRequest{RequestId: uuid.NewString(), ProfileId: uuid.NewString(), Reason: "publish connected native dispatch fixture", Spec: &policyv1.ResourceProfile{Name: "Connected native dispatch", Resources: []*policyv1.ProfileResource{{ResourceId: uuid.NewString(), Desired: &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: dispatchUnit}, State: &resourcev1.ResourceDesiredState_SystemdService{SystemdService: &resourcev1.SystemdServiceDesired{Unit: dispatchUnit, Runtime: resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, Enablement: resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED}}}, Ownership: &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN}, Verification: &resourcev1.VerificationPolicy{MaxAgeSeconds: 1800, Checks: []resourcev1.HealthCheck{resourcev1.HealthCheck_HEALTH_CHECK_NATIVE_STATE}}}}}}
	published, err := control.session.Admin.PublishProfileRevision(ctx, connect.NewRequest(request))
	if err != nil {
		return err
	}
	active := published.Msg.GetRevision()
	var head string
	var sequence uint64
	run := func(name string, revision *adminv1.ProfileRevision, nativeActive, nativeEnablement string, start, restart bool, witness string) error {
		scenario := VMDispatchScenario{Name: name, StartedAt: time.Now().UTC(), Coverage: "native automatic dispatch"}
		assignment, err := control.assignDispatch(ctx, result.DeviceID, head, revision)
		if err != nil {
			return err
		}
		if assignment.GetReconcileIntervalSeconds() != dispatchReconcileIntervalSeconds {
			return errors.New("dispatch assignment did not retain the requested reconcile interval")
		}
		scenario.Assignment = assignment
		head = assignment.GetAssignmentId()
		var opened *adminv1.ResourceActionSummary
		if restart {
			opened, err = waitDispatchAction(ctx, control, result.DeviceID, head, true)
			if err != nil {
				return err
			}
			if err := fixture.Restart(ctx); err != nil {
				return err
			}
		}
		action, err := waitDispatchAction(ctx, control, result.DeviceID, head, false)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if action.GetResourceSequence() <= sequence {
			return errors.New("dispatch resource sequence did not strictly increase")
		}
		sequence = action.GetResourceSequence()
		if (action.GetStartAuthorizedAt() != nil) != start {
			return fmt.Errorf("%s: unexpected start authorization", name)
		}
		if err := vmServiceSucceeded(action.GetStatus(), start); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if restart && action.GetActionId() != opened.GetActionId() {
			return errors.New("server restart replaced the open action")
		}
		if err := vmServiceNativeUnit(ctx, vm, dispatchUnit, nativeActive, nativeEnablement); err != nil {
			return err
		}
		observed, err := dispatchWitnessValue(ctx, vm)
		if err != nil {
			return err
		}
		if observed != witness {
			return fmt.Errorf("%s: unexpected native start witness %q", name, observed)
		}
		scenario.Action, scenario.NativeActive, scenario.NativeEnablement, scenario.StartWitness, scenario.FinishedAt = action, nativeActive, nativeEnablement, observed, time.Now().UTC()
		result.Scenarios = append(result.Scenarios, scenario)
		return nil
	}
	if err := run("1 active and enabled", active, "active", "enabled", true, false, "started\n"); err != nil {
		return err
	}
	sequence, err = exerciseDispatchRechecks(ctx, vm, control, result, head, sequence)
	if err != nil {
		return err
	}
	next := proto.CloneOf(request)
	next.RequestId, next.ExpectedRevisionId = uuid.NewString(), proto.String(active.GetRevisionId())
	next.Spec.Resources[0].Desired.GetSystemdService().Runtime = resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE
	next.Spec.Resources[0].Desired.GetSystemdService().Enablement = resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_DISABLED
	published, err = control.session.Admin.PublishProfileRevision(ctx, connect.NewRequest(next))
	if err != nil {
		return err
	}
	inactive := published.Msg.GetRevision()
	if err := run("2 inactive and disabled", inactive, "inactive", "disabled", true, false, "started\nstarted\n"); err != nil {
		return err
	}
	result.Scenarios = append(result.Scenarios, VMDispatchScenario{Name: "3 unstarted supersession", Coverage: "covered by integration test, not natively exercised: minting is acquisition-driven and the executor holds the mTLS signer; no deterministic native interleaving without a fault seam"})
	if err := run("4 server restart with open action", active, "active", "enabled", true, true, "started\nstarted\nstarted\n"); err != nil {
		return err
	}
	if err := run("5 no drift without start grant", active, "active", "enabled", false, false, "started\nstarted\nstarted\n"); err != nil {
		return err
	}
	clock, err := vmDispatchClockOffset(ctx, vm, 90, func() error {
		return run("7 guest clock 90 seconds ahead", inactive, "inactive", "disabled", true, false, "started\nstarted\nstarted\n")
	})
	result.ClockSkew = append(result.ClockSkew, clock)
	if err != nil {
		return err
	}
	clock, err = vmDispatchClockOffset(ctx, vm, -90, func() error {
		return run("8 guest clock 90 seconds behind", active, "active", "enabled", true, false, "started\nstarted\nstarted\nstarted\n")
	})
	result.ClockSkew = append(result.ClockSkew, clock)
	if err != nil {
		return err
	}
	beforeHold := head
	if err := hold(); err != nil {
		return err
	}
	current, err := waitDispatchSettled(ctx, control, result.DeviceID)
	if err != nil {
		return err
	}
	head = current.GetAssignment().GetAssignmentId()
	if result.Hold != nil {
		result.Hold.AssignmentBefore, result.Hold.AssignmentAfter = beforeHold, head
		result.Hold.BrowserAssignmentsObserved = head != beforeHold
	}
	native, err := vmServiceNativeProperties(ctx, vm, dispatchUnit)
	if err != nil {
		return err
	}
	nativeActive, nativeEnablement := native["ActiveState"], native["UnitFileState"]
	beforeRevokeWitness, err := dispatchWitnessValue(ctx, vm)
	if err != nil {
		return err
	}
	scenario := VMDispatchScenario{Name: "6 revoked device denied", StartedAt: time.Now().UTC(), Coverage: "native automatic dispatch"}
	if err := control.RevokeDevice(ctx, result.DeviceID); err != nil {
		return err
	}
	scenario.RevocationApproval = control.devices[result.DeviceID].approval
	if _, err := control.assignDispatch(ctx, result.DeviceID, head, inactive); connect.CodeOf(err) != connect.CodeFailedPrecondition && connect.CodeOf(err) != connect.CodePermissionDenied {
		return fmt.Errorf("revoked device assignment was not denied: %w", err)
	}
	if err := waitGuestAuthorityRejection(ctx, vm); err != nil {
		return err
	}
	if err := vmServiceNativeUnit(ctx, vm, dispatchUnit, nativeActive, nativeEnablement); err != nil {
		return err
	}
	witness, err := dispatchWitnessValue(ctx, vm)
	if err != nil {
		return err
	}
	if witness != beforeRevokeWitness {
		return errors.New("revoked dispatch changed native start witness")
	}
	scenario.NativeActive, scenario.NativeEnablement, scenario.StartWitness, scenario.FinishedAt = nativeActive, nativeEnablement, witness, time.Now().UTC()
	result.Scenarios = append(result.Scenarios, scenario)
	state, err := control.dispatchState(ctx, result.DeviceID)
	if err != nil {
		return err
	}
	result.RecentActions = state.GetRecentActions()
	for _, scenario := range result.Scenarios {
		if scenario.Action == nil {
			continue
		}
		found := false
		for _, retained := range result.RecentActions {
			if proto.Equal(retained.GetAction(), scenario.Action) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("completed action %s absent or changed in recent_actions", scenario.Action.GetActionId())
		}
	}
	return nil
}

// Browser inspection can leave successful or attention history. Wait only for
// live work to settle, then use native state (not the old desired revision) as
// the revocation baseline.
func waitDispatchSettled(ctx context.Context, control *vmControlPlane, deviceID string) (*adminv1.GetDeviceResourceStateResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	for {
		state, err := control.dispatchState(ctx, deviceID)
		if err != nil {
			return nil, err
		}
		pending := false
		for _, resource := range state.GetResources() {
			switch resource.GetDisposition() {
			case adminv1.ResourceDisposition_RESOURCE_DISPOSITION_PENDING, adminv1.ResourceDisposition_RESOURCE_DISPOSITION_IN_PROGRESS:
				pending = true
			}
		}
		if !pending {
			return state, nil
		}
		if err := lifecycleDelay(ctx, 250*time.Millisecond); err != nil {
			return nil, fmt.Errorf("dispatch did not settle before revocation: %w", err)
		}
	}
}
