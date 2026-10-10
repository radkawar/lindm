//go:build linux

package vmlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	releasemanagementv1 "lindm/gen/lindm/releasemanagement/v1"
	updatev1 "lindm/gen/lindm/update/v1"
	"lindm/internal/devlab"
	"lindm/internal/packaging"
)

type VMUpdateOptions struct {
	Repository, CacheDir, WorkDir, LabBinary, DiagnosticsDir string
	// BuildRepository selects package and server source; empty uses Repository.
	// Repository remains the development fixture and trust root.
	BuildRepository string
}

type VMUpdateStep struct {
	Name   string                     `json:"name"`
	Status *agentv1.AgentUpdateStatus `json:"status,omitempty"`
}

type VMUpdateResult struct {
	ImageID              string                   `json:"image_id"`
	ImageSHA256          string                   `json:"image_sha256"`
	SourceSHA256         string                   `json:"source_snapshot_sha256"`
	LabSHA256            string                   `json:"lab_sha256"`
	ServerBuild          *packaging.BuildResult   `json:"server_build"`
	AgentBuilds          []*packaging.BuildResult `json:"agent_builds"`
	Runtime              *vmRuntimeEvidence       `json:"runtime"`
	SELinux              string                   `json:"selinux"`
	DeviceID             string                   `json:"device_id"`
	EnrollmentGeneration string                   `json:"enrollment_generation"`
	InitialTimestampSHA  string                   `json:"initial_timestamp_sha256"`
	InitialBootID        string                   `json:"initial_boot_id"`
	FinalBootID          string                   `json:"final_boot_id"`
	InitialSessionEpoch  uint64                   `json:"initial_session_epoch"`
	FinalSessionEpoch    uint64                   `json:"final_session_epoch"`
	InitialInventory     *vmInventoryEvidence     `json:"initial_inventory"`
	FinalInventory       *vmInventoryEvidence     `json:"final_inventory"`
	InterruptionWitness  string                   `json:"interruption_witness"`
	Steps                []VMUpdateStep           `json:"steps"`
	StartedAt            time.Time                `json:"started_at"`
	FinishedAt           time.Time                `json:"finished_at"`
	Passed               bool                     `json:"passed"`
	Outcome              string                   `json:"outcome"`
	CancellationReason   string                   `json:"cancellation_reason,omitempty"`
	Failure              string                   `json:"failure,omitempty"`
}

// UpdateVM uses real signed packages, a real isolated control plane and real
// apt/dnf transactions. It resets only its owned QEMU guest while native unpack
// is in progress; this is not physical storage-power-loss qualification.
func UpdateVM(ctx context.Context, manifest *labv1.ImageManifest, options VMUpdateOptions) (result *VMUpdateResult, err error) {
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	if (manifest.GetDistribution() != "ubuntu" || manifest.GetVersion() != "24.04" || manifest.GetArchitecture() != "amd64") && (manifest.GetDistribution() != "fedora" || manifest.GetVersion() != "44" || manifest.GetArchitecture() != "x86_64") {
		return nil, errors.New("vm updates requires Ubuntu 24.04 amd64 or Fedora 44 x86_64")
	}
	ctx, cancel := context.WithTimeout(ctx, 50*time.Minute)
	defer cancel()
	result = &VMUpdateResult{ImageID: manifest.GetId(), StartedAt: time.Now().UTC()}
	defer func() {
		result.FinishedAt = time.Now().UTC()
		switch {
		case errors.Is(ctx.Err(), context.Canceled):
			result.Outcome = "cancelled"
			result.CancellationReason = errors.Join(ctx.Err(), err).Error()
			err = errors.Join(ctx.Err(), err)
		case err != nil:
			result.Outcome, result.Failure = "failed", err.Error()
		default:
			result.Outcome, result.Passed = "passed", true
		}
	}()
	work, err := os.MkdirTemp(options.WorkDir, "lindm-update-lab-")
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(work)) }()
	built, err := buildUpdatePackages(ctx, VMBuildRepository(options.Repository, options.BuildRepository), work, manifest.GetDistribution(), manifest.GetArchitecture())
	if err != nil {
		return result, err
	}
	result.SourceSHA256, result.ServerBuild, result.AgentBuilds = built.sourceSHA256, built.server, built.builds
	result.LabSHA256, err = dispatchFileDigest(options.LabBinary)
	if err != nil {
		return result, err
	}
	vm, verified, err := newVerifiedGuest(ctx, manifest, options.CacheDir, options.WorkDir, true)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, vm.close()) }()
	vm.captureDiagnostics = options.DiagnosticsDir != ""
	defer func() {
		if err != nil && !errors.Is(ctx.Err(), context.Canceled) && options.DiagnosticsDir != "" {
			err = errors.Join(err, saveUpdateFailure(ctx, vm, options.DiagnosticsDir))
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
	result.SELinux = "not applicable"
	if manifest.GetDistribution() == "fedora" {
		mode, err := vm.run(ctx, "getenforce", nil, 128, 10*time.Second)
		if err != nil {
			return result, err
		}
		result.SELinux = strings.TrimSpace(string(mode))
		if result.SELinux != "Enforcing" {
			return result, errors.New("fedora update lane requires SELinux Enforcing")
		}
	}
	packages, err := newNativeGuestPackages(ctx, vm, built.first, built.second, built.apt, built.publicKey, built.fingerprint)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, packages.Close()) }()
	if err := uploadLifecycleProbe(ctx, vm, options.LabBinary); err != nil {
		return result, err
	}
	if err := packages.InstallFirst(ctx); err != nil {
		return result, err
	}
	fixture, publisher, err := devlab.OpenReleaseAuthorityFixture(ctx, options.Repository, built.serverBinary)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, fixture.Close()) }()
	if err := fixture.RegisterRelease(ctx, updateInitialVersion); err != nil {
		return result, err
	}
	delegation, err := fixture.ConfigureServiceDispatch(ctx)
	if err != nil {
		return result, err
	}
	forwards, err := openLifecycleForwards(ctx, vm, [2]string{fixture.AdminAddress, fixture.DeviceAddress})
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
	if err := lifecycleCommand(ctx, vm, "resume update fixture enrollment", packaging.BinaryPath+" resume"); err != nil {
		return result, err
	}
	result.DeviceID, result.EnrollmentGeneration = issued.GetDeviceId(), issued.GetEnrollmentGeneration()
	channel, target := updateChannel(built.second, 1, true, 100)
	if err := publisher.Publish(ctx, channel, map[string]string{target: built.second.Path}); err != nil {
		return result, err
	}
	initial, err := fixture.CaptureReleaseMetadata(ctx)
	if err != nil {
		return result, err
	}
	result.InitialTimestampSHA = initial.TimestampSHA256
	if err := enableGuestUpdates(ctx, vm, packages, manifest.GetDistribution()); err != nil {
		return result, err
	}
	status, err := waitUpdateObservation(ctx, vm, nil, "no_update")
	if err != nil {
		return result, err
	}
	if err := packages.assertVersion(ctx, built.first); err != nil {
		return result, err
	}
	result.Steps = append(result.Steps, VMUpdateStep{Name: "signed paused channel holds initial version", Status: status})
	result.InitialInventory, err = waitLifecycleInventory(ctx, vm, control, manifest.GetDistribution(), result.DeviceID, nil)
	if err != nil {
		return result, err
	}
	initialIdentity, err := waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED)
	if err != nil {
		return result, err
	}
	result.InitialSessionEpoch = initialIdentity.GetCommittedSessionEpoch()
	if result.InitialSessionEpoch == 0 || !initialIdentity.GetSessionEpochUsable() {
		return result, errors.New("old agent has no authenticated usable session with newer server")
	}
	channel, err = setUpdateRollout(ctx, fixture, channel, false, 0)
	if err != nil {
		return result, err
	}
	status, err = waitUpdateObservation(ctx, vm, status, "no_update")
	if err != nil {
		return result, err
	}
	if err := packages.assertVersion(ctx, built.first); err != nil {
		return result, err
	}
	result.Steps = append(result.Steps, VMUpdateStep{Name: "audited zero-percent rollout holds initial version", Status: status})
	old, err := fixture.CaptureReleaseMetadata(ctx)
	if err != nil {
		return result, err
	}
	restore, err := fixture.ReplayReleaseTimestamp(ctx, initial)
	if err != nil {
		return result, err
	}
	status, err = assertRejectedUpdate(ctx, packages, built.first, status)
	err = errors.Join(err, restore())
	if err != nil {
		return result, err
	}
	result.Steps = append(result.Steps, VMUpdateStep{Name: "signed timestamp rollback rejected", Status: status})
	status, err = waitUpdateObservation(ctx, vm, status, "no_update")
	if err != nil {
		return result, err
	}
	if err := setUpdateTransportRunning(ctx, vm, false); err != nil {
		return result, err
	}
	channel, err = setUpdateRollout(ctx, fixture, channel, false, 0)
	if err != nil {
		return result, err
	}
	restore, err = fixture.MixReleaseRollout(ctx, old)
	if err != nil {
		return result, err
	}
	if err := setUpdateTransportRunning(ctx, vm, true); err != nil {
		return result, errors.Join(err, restore())
	}
	status, err = assertRejectedUpdate(ctx, packages, built.first, status)
	err = errors.Join(err, restore())
	if err != nil {
		return result, err
	}
	result.Steps = append(result.Steps, VMUpdateStep{Name: "signed mix-and-match rollout metadata rejected", Status: status})
	status, err = waitUpdateObservation(ctx, vm, status, "no_update")
	if err != nil {
		return result, err
	}
	if err := setUpdateTransportRunning(ctx, vm, false); err != nil {
		return result, err
	}
	if _, err := fixture.BeginReleaseFreeze(ctx, 10*time.Second); err != nil {
		return result, err
	}
	if err := setUpdateTransportRunning(ctx, vm, true); err != nil {
		return result, err
	}
	status, err = waitUpdateObservation(ctx, vm, status, "no_update")
	if err != nil {
		return result, err
	}
	status, err = assertRejectedUpdate(ctx, packages, built.first, status)
	if err != nil {
		return result, err
	}
	result.Steps = append(result.Steps, VMUpdateStep{Name: "previously valid unchanged timestamp expires and is rejected", Status: status})
	channel, err = setUpdateRollout(ctx, fixture, channel, false, 0)
	if err != nil {
		return result, err
	}
	status, err = waitUpdateObservation(ctx, vm, status, "no_update")
	if err != nil {
		return result, err
	}
	if err := setUpdateTransportRunning(ctx, vm, false); err != nil {
		return result, err
	}
	channel, err = setUpdateRollout(ctx, fixture, channel, false, 100)
	if err != nil {
		return result, err
	}
	restore, err = fixture.TamperReleaseTarget(ctx, target)
	if err != nil {
		return result, err
	}
	if err := setUpdateTransportRunning(ctx, vm, true); err != nil {
		return result, errors.Join(err, restore())
	}
	status, err = assertRejectedUpdate(ctx, packages, built.first, status)
	if stopErr := setUpdateTransportRunning(ctx, vm, false); stopErr != nil {
		err = errors.Join(err, stopErr)
	}
	err = errors.Join(err, restore())
	if err != nil {
		return result, err
	}
	result.Steps = append(result.Steps, VMUpdateStep{Name: "tampered target rejected before native apply", Status: status})
	if err := lifecycleCommand(ctx, vm, "bound owned update slice disk throughput", "systemctl start lindm-updates.slice; systemctl set-property --runtime lindm-updates.slice 'IOWriteBandwidthMax=/dev/vda 1048576'; grep -Eq ' wbps=1048576([[:space:]]|$)' /sys/fs/cgroup/lindm.slice/lindm-updates.slice/io.max"); err != nil {
		return result, err
	}
	boot, err := vm.run(ctx, "cat /proc/sys/kernel/random/boot_id", nil, 128, 5*time.Second)
	if err != nil {
		return result, err
	}
	result.InitialBootID = strings.TrimSpace(string(boot))
	if err := setUpdateTransportRunning(ctx, vm, true); err != nil {
		return result, err
	}
	result.InterruptionWitness, err = waitUpdateUnpack(ctx, vm)
	if err != nil {
		return result, err
	}
	// Freeze the owned guest immediately after the unpack witness: transport
	// cleanup must not let its installer run ahead before the reset.
	if err := vm.qmpCommand(ctx, map[string]any{"execute": "stop", "id": "freeze-agent-update"}); err != nil {
		return result, err
	}
	if err := closeLifecycleForwards(forwards); err != nil {
		return result, err
	}
	forwards = nil
	if err := vm.qmpCommand(ctx, map[string]any{"execute": "system_reset", "id": "interrupt-agent-update"}); err != nil {
		return result, err
	}
	if err := vm.qmpCommand(ctx, map[string]any{"execute": "cont", "id": "resume-after-update-reset"}); err != nil {
		return result, err
	}
	previousBoot, err := uuid.Parse(result.InitialBootID)
	if err != nil || previousBoot == uuid.Nil {
		return result, errors.New("pre-update boot ID is invalid")
	}
	reboot, stopReboot := context.WithTimeout(ctx, 6*time.Minute)
	err = waitGuestBootChange(reboot, previousBoot, func(probe context.Context) (string, error) {
		if vm.client != nil {
			_ = vm.client.Close()
			vm.client = nil
		}
		if err := vm.connect(probe); err != nil {
			return "", err
		}
		boot, err := vm.run(probe, "cat /proc/sys/kernel/random/boot_id", nil, 128, 5*time.Second)
		result.FinalBootID = strings.TrimSpace(string(boot))
		return result.FinalBootID, err
	})
	stopReboot()
	if err != nil {
		return result, err
	}
	forwards, err = openLifecycleForwards(ctx, vm, [2]string{fixture.AdminAddress, fixture.DeviceAddress})
	if err != nil {
		return result, err
	}
	status, err = waitUpdateObservation(ctx, vm, nil, "installed")
	if err != nil {
		return result, err
	}
	if err := packages.assertVersion(ctx, built.second); err != nil {
		return result, err
	}
	if err := lifecycleCommand(ctx, vm, "verify recovered agent daemons", "systemctl is-active --quiet lindm-executor.service; systemctl is-active --quiet lindm-agent.service"); err != nil {
		return result, err
	}
	result.FinalInventory, err = waitLifecycleInventory(ctx, vm, control, manifest.GetDistribution(), result.DeviceID, result.InitialInventory)
	if err != nil {
		return result, err
	}
	identity, err := waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED)
	if err != nil {
		return result, err
	}
	if identity.GetDeviceId() != result.DeviceID || identity.GetEnrollmentGeneration() != result.EnrollmentGeneration {
		return result, errors.New("native update changed protected enrollment identity")
	}
	result.FinalSessionEpoch = identity.GetCommittedSessionEpoch()
	if result.FinalSessionEpoch <= result.InitialSessionEpoch || !identity.GetSessionEpochUsable() {
		return result, errors.New("updated agent did not acquire an authenticated successor session")
	}
	result.Steps = append(result.Steps, VMUpdateStep{Name: "native unpack interrupted by owned QEMU reset; boot helper completes exact update", Status: status})
	down, downTarget := updateChannel(built.first, channel.GetGeneration()+1, false, 100)
	if err := publisher.Publish(ctx, down, map[string]string{downTarget: built.first.Path}); err != nil {
		return result, err
	}
	status, err = waitUpdateObservation(ctx, vm, status, "no_update")
	if err != nil {
		return result, err
	}
	if err := packages.assertVersion(ctx, built.second); err != nil {
		return result, err
	}
	result.Steps = append(result.Steps, VMUpdateStep{Name: "fresh signed catalog cannot downgrade installed agent", Status: status})
	return result, nil
}

func updateChannel(artifact packaging.Artifact, generation uint64, paused bool, percentage uint32) (*updatev1.AgentUpdateChannel, string) {
	name := "packages/lindm-agent/" + artifact.Architecture.GOARCH + "/" + filepath.Base(artifact.Path)
	native := artifact.Version
	if artifact.Format == packaging.FormatRPM {
		native += "-" + packaging.RPMRelease
	}
	now := time.Now().UTC()
	return &updatev1.AgentUpdateChannel{Ring: "canary", Paused: paused, EligiblePercentage: percentage, Generation: generation, IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(time.Hour)), Artifacts: []*updatev1.AgentUpdateArtifact{{Version: artifact.Version, Architecture: artifact.Architecture.GOARCH, PackageFormat: string(artifact.Format), TargetPath: name, MinimumAgentVersion: "0.0.0", MaximumAgentVersion: "1.0.0", MinimumProtocolVersion: 1, MaximumProtocolVersion: 1, NativeVersion: native}}}, name
}

func setUpdateRollout(ctx context.Context, fixture *devlab.AuthorityFixture, channel *updatev1.AgentUpdateChannel, paused bool, percentage uint32) (*updatev1.AgentUpdateChannel, error) {
	return fixture.SetRollout(ctx, &releasemanagementv1.SetRolloutRequest{RequestId: uuid.NewString(), Ring: channel.GetRing(), Paused: paused, EligiblePercentage: percentage, ExpectedGeneration: channel.GetGeneration(), Reason: "Native unattended update qualification"})
}

func enableGuestUpdates(ctx context.Context, vm *guestVM, packages *nativeGuestPackages, distribution string) error {
	data, err := vm.run(ctx, "sudo -n cat /etc/lindm/executor.json", nil, 64<<10, 10*time.Second)
	if err != nil {
		return err
	}
	cfg := new(agentv1.AgentConfig)
	if err := protojson.Unmarshal(data, cfg); err != nil {
		return err
	}
	manager := agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_APT
	if distribution == "fedora" {
		manager = agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_DNF
	}
	cfg.Updates = &agentv1.AgentUpdateConfig{RepositoryUrl: "https://localhost:18444/updates/", Ring: "canary", PollIntervalSeconds: 1, Manager: manager}
	data, err = protojson.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := packages.uploadBytes(ctx, nativeGuestDir+"/update-executor.json", data); err != nil {
		return err
	}
	return lifecycleCommand(ctx, vm, "enable authenticated unattended updates", "install -o root -g root -m 0600 "+nativeGuestDir+"/update-executor.json /etc/lindm/executor.json; if command -v restorecon >/dev/null 2>&1; then restorecon -F /etc/lindm/executor.json; fi; systemctl restart lindm-executor.service lindm-agent.service")
}

func setUpdateTransportRunning(ctx context.Context, vm *guestVM, running bool) error {
	// Isolate fixture publication without spending the product's service-start
	// budget. Repeated stop/start attacks otherwise make a legitimate native
	// package restart hit StartLimitBurst rather than test update behavior.
	action := "freeze"
	if running {
		action = "thaw"
	}
	return lifecycleCommand(ctx, vm, "control owned update transport", "systemctl "+action+" lindm-agent.service")
}

func readUpdateStatus(ctx context.Context, vm *guestVM) (*agentv1.AgentUpdateStatus, error) {
	result, err := vm.runResult(ctx, "sudo -n "+nativeQuote(packaging.BinaryPath)+" update-status", nil, 64<<10, 15*time.Second)
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		// This fixed diagnostic command emits only protected update state or its
		// operational error, never configuration, keys or enrollment credentials.
		return nil, &updateStatusUnavailable{exit: result.ExitCode, detail: strings.TrimSpace(string(result.Stderr))}
	}
	response := new(agentv1.GetAgentUpdateResponse)
	if err := protojson.Unmarshal(result.Stdout, response); err != nil {
		return nil, err
	}
	if response.GetStatus() == nil || !response.GetStatus().GetEnabled() {
		return nil, errors.New("native update controller is not enabled")
	}
	return response.GetStatus(), nil
}

// The executor can legitimately be unavailable while the native helper replaces
// its service. Only a completed status command gets this retryable classification;
// authentication, malformed replies and disabled updates remain terminal.
type updateStatusUnavailable struct {
	exit   int
	detail string
}

func (e *updateStatusUnavailable) Error() string {
	return fmt.Sprintf("update-status exited %d: %.2048s", e.exit, e.detail)
}

func updateObservationTransportLost(err error) bool {
	var missing *ssh.ExitMissingError
	return sshBootNotReady(err) || errors.As(err, &missing)
}

func waitUpdateObservation(ctx context.Context, vm *guestVM, before *agentv1.AgentUpdateStatus, outcome string) (*agentv1.AgentUpdateStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	var last *agentv1.AgentUpdateStatus
	var lastErr error
	var firstTransportErr error
	var cycleFloor *timestamppb.Timestamp
	for {
		var observed *agentv1.AgentUpdateStatus
		if vm.client == nil {
			lastErr = vm.connect(ctx)
		}
		if lastErr == nil {
			observed, lastErr = readUpdateStatus(ctx, vm)
		}
		if lastErr != nil {
			var unavailable *updateStatusUnavailable
			if updateObservationTransportLost(lastErr) {
				if firstTransportErr == nil {
					firstTransportErr = fmt.Errorf("first update observation transport loss: %w", lastErr)
				}
				// runResult closes a timed-out transport. Reusing that client
				// cannot observe recovery, even if the guest stayed healthy.
				// Only this read-only observation may reconnect and retry.
				if vm.client != nil {
					_ = vm.client.Close()
					vm.client = nil
				}
			} else if !errors.As(lastErr, &unavailable) && ctx.Err() == nil {
				return nil, fmt.Errorf("observe update outcome %s: %w", outcome, lastErr)
			}
		} else {
			last = observed
			// A caller's prior sample may predate the mutation by many cycles.
			// Fence on the first post-mutation observation, then require a
			// newly started cycle; an in-flight cycle can finish using old
			// metadata. Installed is a durable native result, not a metadata
			// probe, and need not wait for another check after boot recovery.
			if cycleFloor == nil && outcome != "installed" {
				cycleFloor = last.GetAttemptStartedAt()
			}
		}
		matched := last.GetLastOutcome() == outcome && last.GetPhase() != "checking"
		if outcome == "installed" {
			matched = last.GetPhase() == "installed" && last.GetVersion() == updateNextVersion && (last.GetLastOutcome() == "installed" || last.GetLastOutcome() == "no_update")
		}
		freshCycle := outcome == "installed" || (cycleFloor != nil && last.GetAttemptStartedAt() != nil && last.GetAttemptStartedAt().AsTime().After(cycleFloor.AsTime()))
		if lastErr == nil && freshCycle && last.GetAttemptFinishedAt() != nil && (before == nil || before.GetAttemptFinishedAt() == nil || last.GetAttemptFinishedAt().AsTime().After(before.GetAttemptFinishedAt().AsTime())) && matched {
			return last, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("wait for fresh update outcome %s (phase=%s outcome=%s): %w", outcome, last.GetPhase(), last.GetLastOutcome(), errors.Join(ctx.Err(), lastErr, firstTransportErr))
		case <-ticker.C:
			lastErr = nil
		}
	}
}

func assertRejectedUpdate(ctx context.Context, packages *nativeGuestPackages, artifact packaging.Artifact, before *agentv1.AgentUpdateStatus) (*agentv1.AgentUpdateStatus, error) {
	status, err := waitUpdateObservation(ctx, packages.vm, before, "rejected")
	if err != nil {
		return nil, err
	}
	if status.GetTransactionId() != "" || status.GetPhase() != "idle" {
		return nil, errors.New("rejection fixture reached native transaction admission")
	}
	return status, packages.assertVersion(ctx, artifact)
}

func waitUpdateUnpack(ctx context.Context, vm *guestVM) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if vm.client == nil {
		if err := vm.connect(ctx); err != nil {
			return "", err
		}
	}
	// The resident probe freezes the exact admitted update cgroup only after
	// observing a real partial executable. It is a fault injection, not a
	// read-only observation, and must not be replayed on ambiguous SSH loss.
	result, err := vm.runResult(ctx, "sudo -n "+guestLifecycleProbe+" guest update-unpack", nil, 16<<10, 10*time.Minute)
	if err != nil {
		return "", fmt.Errorf("native unpack fault observation interrupted; not replayed: %w", err)
	}
	if result.ExitCode != 0 || len(result.Stderr) != 0 {
		return "", fmt.Errorf("native unpack fault observation exited %d: %.16384s", result.ExitCode, result.Stderr)
	}
	witness := strings.TrimSpace(string(result.Stdout))
	if witness == "" || !strings.HasSuffix(witness, " frozen=1") {
		return "", errors.New("native unpack observer returned no frozen helper witness")
	}
	return witness, nil
}

// Failure diagnostics must not reuse the transport whose loss caused the failure.
// Collect only operational state over a new connection with the same host-key pin;
// neither configuration nor enrollment/update authority bytes enter the record.
func saveUpdateFailure(ctx context.Context, vm *guestVM, directory string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	probe := &guestVM{dir: vm.dir, cmd: vm.cmd, done: vm.done, waitErr: vm.waitErr, log: vm.log, address: vm.address, config: vm.config, tpm: vm.tpm}
	err := probe.connect(ctx)
	var result guestCommandResult
	if err == nil {
		defer func() { _ = probe.client.Close() }()
		command := "sudo -n sh -c " + nativeQuote("cat /proc/sys/kernel/random/boot_id /proc/uptime /proc/loadavg; free -m; ps -eo pid,ppid,stat,comm; if command -v dpkg-query >/dev/null; then dpkg-query -W apt dpkg systemd; else rpm -q dnf dnf5 rpm systemd; fi; "+packaging.BinaryPath+" update-status; systemctl show ssh.service sshd.service lindm-executor.service lindm-agent.service lindm-agent-update-recovery.service -p Id -p ActiveState -p SubState -p MainPID -p NRestarts -p ExecMainStartTimestamp -p ExecMainStatus; journalctl -b --no-pager -o short-monotonic -n 240 -u ssh.service -u sshd.service -u lindm-executor.service -u lindm-agent.service -u 'lindm-agent-update-*'; journalctl -b -k --no-pager -n 80")
		result, err = probe.runResult(ctx, command, nil, 512<<10, 30*time.Second)
	}
	failure := ""
	if err != nil {
		failure = err.Error()
	}
	data, err := json.Marshal(struct {
		Source         string
		LastOperation  *guestOperationDiagnostic
		ExitCode       int
		Stdout, Stderr string
		Failure        string
	}{"fresh-pinned-update-observer", vm.lastOperation, result.ExitCode, string(result.Stdout), string(result.Stderr), failure})
	if err != nil {
		return err
	}
	path, err := saveGuestDiagnostics(directory, data)
	if err != nil {
		return err
	}
	return fmt.Errorf("private update diagnostics saved to %q", path)
}
