//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/devlab"
	"lindm/internal/packaging"
)

// VMLifecycleOptions selects real artifacts and an already running development
// control plane. Rejections must include all three native authentication failures.
type VMLifecycleOptions struct {
	Repository        string
	CacheDir          string
	WorkDir           string
	DiagnosticsDir    string
	LabBinary         string
	First             packaging.Artifact
	Second            packaging.Artifact
	APT               *packaging.APTRepository
	PublicKey         string
	SignerFingerprint string
	Rejections        []packaging.RejectionCase
	// Exercises real signed trust installation/rotation after upgrade. The
	// second package must implement execution trust; the first may use journal v1.
	ExecutionTrust bool
	// Requires the upgraded executor's signed durable service execution API.
	ServiceExecution bool
	// Uses a private real server/database and automatic network trust relay.
	ControlPlaneTrust bool
	LindmdBinary      string
	// Optional bounded observation time after the first two publications lets
	// a human inspect the actual console without changing product timers.
	ObserveFor time.Duration
	Progress   io.Writer
}

type VMLifecycleResult struct {
	Distribution             string                         `json:"distribution"`
	Version                  string                         `json:"version"`
	ImageID                  string                         `json:"image_id"`
	ImageSHA256              string                         `json:"image_sha256"`
	Runtime                  *vmRuntimeEvidence             `json:"runtime"`
	UpgradeBaseline          *vmInventoryEvidence           `json:"upgrade_baseline"`
	FirstArtifactSHA256      string                         `json:"first_artifact_sha256"`
	SecondArtifactSHA256     string                         `json:"second_artifact_sha256"`
	SignerFingerprint        string                         `json:"signer_fingerprint"`
	DeviceID                 string                         `json:"device_id"`
	Generation               string                         `json:"generation"`
	InstallationID           string                         `json:"installation_id"`
	InitialEpoch             uint64                         `json:"initial_epoch"`
	RebootEpoch              uint64                         `json:"reboot_epoch"`
	Publications             []*vmInventoryEvidence         `json:"publications"`
	FailedAttempt            *vmInventoryEvidence           `json:"failed_attempt"`
	RejectedArtifacts        []string                       `json:"rejected_artifacts"`
	PrivilegeEvidence        *labv1.NetworkBoundaryEvidence `json:"privilege_evidence"`
	ExecutionTrust           *vmExecutionTrustEvidence      `json:"execution_trust,omitempty"`
	ControlPlaneTrust        *vmControlPlaneTrustEvidence   `json:"control_plane_trust,omitempty"`
	LostIssuanceRecovered    bool                           `json:"lost_issuance_recovered"`
	PurgeRetainedIdentity    bool                           `json:"purge_retained_identity"`
	SpoolCorruptionRecovered bool                           `json:"spool_corruption_recovered"`
	RevocationObserved       bool                           `json:"revocation_observed"`
	MissingJournalHeld       bool                           `json:"missing_journal_held"`
}

// LifecycleVM exercises native authentication, protected issuance recovery,
// installed services, complete public-API inventory and retained identity. It
// returns success only after authority cleanup and QEMU/private-file teardown.
func LifecycleVM(ctx context.Context, manifest *labv1.ImageManifest, options VMLifecycleOptions) (_ *VMLifecycleResult, err error) {
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	if manifest.GetDistribution() != "ubuntu" && manifest.GetDistribution() != "fedora" {
		return nil, errors.New("native lifecycle requires Ubuntu or Fedora")
	}
	if manifest.GetArchitecture() != "amd64" && manifest.GetArchitecture() != "x86_64" {
		return nil, errors.New("native lifecycle requires amd64/x86_64")
	}
	if options.ObserveFor < 0 || options.ObserveFor > 10*time.Minute {
		return nil, errors.New("observation interval must be between zero and ten minutes")
	}
	if options.ControlPlaneTrust && (options.ExecutionTrust || options.ServiceExecution) {
		return nil, errors.New("control-plane trust is exclusive with manual trust/service execution")
	}
	if options.ControlPlaneTrust != (options.LindmdBinary != "") {
		return nil, errors.New("control-plane trust requires a prebuilt lindmd binary exclusively")
	}
	if err := packaging.UpgradeOrdered(options.First.Version, options.Second.Version); err != nil {
		return nil, err
	}
	format := packaging.FormatDEB
	if manifest.GetDistribution() == "fedora" {
		format = packaging.FormatRPM
	}
	if options.First.Format != format || options.Second.Format != format {
		return nil, errors.New("native artifacts do not match the selected distribution")
	}
	cases, err := lifecycleRejections(options.Rejections, format)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Minute+2*options.ObserveFor)
	defer cancel()
	vm, verified, err := newVerifiedGuest(ctx, manifest, options.CacheDir, options.WorkDir, true)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, vm.close()) }()
	vm.captureDiagnostics = options.DiagnosticsDir != ""
	defer func() {
		if err != nil && options.DiagnosticsDir != "" {
			err = errors.Join(err, saveLifecycleFailure(ctx, vm, options.DiagnosticsDir))
		}
	}()
	if err := vm.connect(ctx); err != nil {
		return nil, err
	}
	runtimeEvidence, err := vm.runtimeEvidence(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := vm.run(ctx, "sudo -n cloud-init status --wait --format=json", nil, 64<<10, 5*time.Minute); err != nil {
		return nil, fmt.Errorf("native guest cloud-init: %w", err)
	}
	packages, err := newNativeGuestPackages(ctx, vm, options.First, options.Second, options.APT, options.PublicKey, options.SignerFingerprint)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, packages.Close()) }()
	result := &VMLifecycleResult{Distribution: manifest.GetDistribution(), Version: manifest.GetVersion(), ImageID: manifest.GetId(), ImageSHA256: verified.SHA256, FirstArtifactSHA256: options.First.SHA256, SecondArtifactSHA256: options.Second.SHA256, SignerFingerprint: options.SignerFingerprint}
	result.Runtime = runtimeEvidence
	for _, rejection := range cases {
		var rejected *nativeAuthRejection
		if failure := packages.RejectArtifact(ctx, rejection.Artifact, rejection.APT); !errors.As(failure, &rejected) {
			return nil, fmt.Errorf("native %s authentication rejection was not established: %w", rejection.Name, failure)
		}
		result.RejectedArtifacts = append(result.RejectedArtifacts, rejection.Name)
	}
	if err := packages.InstallFirst(ctx); err != nil {
		return nil, err
	}
	if err := uploadLifecycleProbe(ctx, vm, options.LabBinary); err != nil {
		return nil, err
	}
	var isolated *devlab.AuthorityFixture
	destinations := [2]string{"127.0.0.1:18444", "127.0.0.1:18445"}
	if options.ControlPlaneTrust {
		isolated, err = devlab.OpenAuthorityFixture(ctx, options.Repository, options.LindmdBinary)
		if err != nil {
			return nil, err
		}
		defer func() { err = errors.Join(err, isolated.Close()) }()
		destinations = [2]string{isolated.AdminAddress, isolated.DeviceAddress}
	}
	forwards, err := openLifecycleForwards(ctx, vm, destinations)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, closeLifecycleForwards(forwards)) }()
	if _, err := waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_UNPROVISIONED); err != nil {
		return nil, err
	}
	// Keep the owner session fresh for its first authenticated API operation,
	// and revoke authority before the VM and its private files are torn down.
	control, err := openVMControlPlane(ctx, options.Repository, isolated)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, control.Close(context.WithoutCancel(ctx))) }()
	material, err := control.BootstrapMaterial(ctx)
	if err != nil {
		return nil, err
	}
	interrupted, err := interruptBootstrap(ctx, vm, material)
	clear(material.GrantSecret)
	material.GrantSecret = nil
	if err != nil {
		return nil, err
	}
	// Resume can activate the issued device even if its SSH response is lost.
	if err := control.TrackDevice(interrupted.GetDeviceId()); err != nil {
		return nil, err
	}
	pending, err := readGuestAgentStatus(ctx, vm)
	if err != nil {
		return nil, err
	}
	if pending.GetExecutor().GetLifecycle() != agentv1.Lifecycle_LIFECYCLE_PENDING_ENROLLMENT {
		return nil, errors.New("lost issuance did not retain a pending protected transaction")
	}
	if err := lifecycleCommand(ctx, vm, "restart executor after lost issuance", "systemctl restart lindm-executor.service"); err != nil {
		return nil, err
	}
	if _, err := waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_PENDING_ENROLLMENT); err != nil {
		return nil, err
	}
	if err := lifecycleCommand(ctx, vm, "resume original issuance", packaging.BinaryPath+" resume"); err != nil {
		return nil, err
	}
	initial, err := readGuestAgentStatus(ctx, vm)
	if err != nil {
		return nil, err
	}
	identity := initial.GetExecutor()
	if identity.GetLifecycle() != agentv1.Lifecycle_LIFECYCLE_ENROLLED || identity.GetDeviceId() != interrupted.GetDeviceId() || identity.GetEnrollmentGeneration() != interrupted.GetEnrollmentGeneration() || identity.GetInstallationId() != pending.GetExecutor().GetInstallationId() {
		return nil, errors.New("issuance recovery changed protected identity")
	}
	privilege, err := probeGuestPrivileges(ctx, vm)
	if err != nil {
		return nil, err
	}
	if privilege.GetDeviceId() != identity.GetDeviceId() || privilege.GetEnrollmentGeneration() != identity.GetEnrollmentGeneration() || !bytes.Equal(privilege.GetCertificateSha256(), interrupted.GetCertificateSha256()) {
		return nil, errors.New("resumed enrollment did not recover the exact issued certificate")
	}
	result.DeviceID = identity.GetDeviceId()
	result.Generation = identity.GetEnrollmentGeneration()
	result.InstallationID = identity.GetInstallationId()
	result.PrivilegeEvidence = privilege
	result.LostIssuanceRecovered = true
	if err := lifecycleCommand(ctx, vm, "start enrolled network process", "systemctl restart lindm-agent.service"); err != nil {
		return nil, err
	}
	first, err := waitLifecycleInventory(ctx, vm, control, manifest.GetDistribution(), result.DeviceID, nil)
	if err != nil {
		return nil, err
	}
	result.Publications = append(result.Publications, first)
	initial, err = readGuestAgentStatus(ctx, vm)
	if err != nil {
		return nil, err
	}
	identity = initial.GetExecutor()
	result.InitialEpoch = identity.GetCommittedSessionEpoch()
	if result.InitialEpoch == 0 || !identity.GetSessionEpochUsable() {
		return nil, errors.New("inventory published without a committed usable protected epoch")
	}
	if err := lifecycleProgress(ctx, options, "enrolled", first, true); err != nil {
		return nil, err
	}
	// Observation can span another scheduled publication. Choose a current,
	// fully compared baseline and a fresh cursor before changing the package.
	baseline, err := waitLifecycleInventory(ctx, vm, control, manifest.GetDistribution(), result.DeviceID, nil)
	if err != nil {
		return nil, err
	}
	result.UpgradeBaseline = baseline

	if err := packages.Upgrade(ctx); err != nil {
		return nil, err
	}
	if _, err := waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED); err != nil {
		return nil, err
	}
	upgraded, err := waitLifecycleInventory(ctx, vm, control, manifest.GetDistribution(), result.DeviceID, baseline)
	if err != nil {
		return nil, err
	}
	if err := sameGuestIdentity(ctx, vm, identity); err != nil {
		return nil, err
	}
	previous, err := control.ReadSnapshot(ctx, result.DeviceID, baseline.FirstPageToken)
	if err != nil {
		return nil, err
	}
	if previous.SnapshotID != baseline.SnapshotID || previous.Sequence != baseline.SnapshotSequence || !maps.Equal(previous.packages, baseline.packages) || !previous.CursorExpiresAt.Equal(baseline.CursorExpiresAt) {
		return nil, errors.New("new publication changed an existing package cursor")
	}
	result.Publications = append(result.Publications, upgraded)
	if err := lifecycleProgress(ctx, options, "upgraded", upgraded, true); err != nil {
		return nil, err
	}
	if options.ExecutionTrust || options.ServiceExecution {
		result.ExecutionTrust, err = exerciseVMExecutionTrust(ctx, packages, options.Repository, options.ServiceExecution)
		if err != nil {
			return nil, err
		}
	}
	if options.ControlPlaneTrust {
		result.ControlPlaneTrust, err = exerciseVMControlPlaneTrust(ctx, packages, control, isolated, options.Repository)
		if err != nil {
			return nil, err
		}
	}

	if err := closeLifecycleForwards(forwards); err != nil {
		return nil, err
	}
	forwards = nil
	if err := packages.stopAPT(); err != nil {
		return nil, err
	}
	if err := rebootLifecycleGuest(ctx, vm, identity.GetCommittedBootId()); err != nil {
		return nil, err
	}
	forwards, err = openLifecycleForwards(ctx, vm, destinations)
	if err != nil {
		return nil, err
	}
	if format == packaging.FormatDEB {
		if err := packages.startAPT(ctx, options.APT, []packaging.Artifact{options.First, options.Second}); err != nil {
			return nil, err
		}
	}
	if err := packages.AssertServices(ctx, true); err != nil {
		return nil, err
	}
	if _, err := waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED); err != nil {
		return nil, err
	}
	if result.ExecutionTrust != nil {
		if err := verifyRetainedVMExecutionTrust(ctx, vm, result.ExecutionTrust); err != nil {
			return nil, err
		}
		result.ExecutionTrust.RebootRetained = true
	}
	if result.ControlPlaneTrust != nil {
		if err := verifyRetainedVMControlPlaneTrust(ctx, vm, result.ControlPlaneTrust); err != nil {
			return nil, err
		}
		result.ControlPlaneTrust.RebootRetained = true
	}
	if err := lifecycleCommand(ctx, vm, "synchronize after reboot", "systemctl restart lindm-agent.service"); err != nil {
		return nil, err
	}
	rebooted, err := waitLifecycleInventory(ctx, vm, control, manifest.GetDistribution(), result.DeviceID, upgraded)
	if err != nil {
		return nil, err
	}
	if err := sameGuestIdentity(ctx, vm, identity); err != nil {
		return nil, err
	}
	bootStatus, err := readGuestAgentStatus(ctx, vm)
	if err != nil {
		return nil, err
	}
	result.RebootEpoch = bootStatus.GetExecutor().GetCommittedSessionEpoch()
	if result.RebootEpoch <= result.InitialEpoch || bootStatus.GetExecutor().GetCommittedBootId() == identity.GetCommittedBootId() {
		return nil, errors.New("reboot failed to acquire a protected session successor")
	}
	identity = bootStatus.GetExecutor()
	result.Publications = append(result.Publications, rebooted)
	if err := lifecycleProgress(ctx, options, "rebooted", rebooted, false); err != nil {
		return nil, err
	}

	if err := packages.Remove(ctx, false); err != nil {
		return nil, err
	}
	if err := packages.Remove(ctx, true); err != nil {
		return nil, err
	}
	if err := packages.ReinstallSecond(ctx); err != nil {
		return nil, err
	}
	if _, err := waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED); err != nil {
		return nil, err
	}
	if result.ExecutionTrust != nil {
		if err := verifyRetainedVMExecutionTrust(ctx, vm, result.ExecutionTrust); err != nil {
			return nil, err
		}
		result.ExecutionTrust.ReinstallRetained = true
	}
	if result.ControlPlaneTrust != nil {
		if err := verifyRetainedVMControlPlaneTrust(ctx, vm, result.ControlPlaneTrust); err != nil {
			return nil, err
		}
		result.ControlPlaneTrust.ReinstallRetained = true
	}
	reinstalled, err := waitLifecycleInventory(ctx, vm, control, manifest.GetDistribution(), result.DeviceID, rebooted)
	if err != nil {
		return nil, err
	}
	if err := sameGuestIdentity(ctx, vm, identity); err != nil {
		return nil, err
	}
	result.PurgeRetainedIdentity = true
	result.Publications = append(result.Publications, reinstalled)
	if err := lifecycleProgress(ctx, options, "reinstalled", reinstalled, false); err != nil {
		return nil, err
	}

	if err := lifecycleCommand(ctx, vm, "corrupt stopped unprivileged spool", "systemctl stop lindm-agent.service; test -f /var/lib/lindm/agent/spool.sqlite; printf 'deliberately damaged SQLite header' > /var/lib/lindm/agent/spool.sqlite; systemctl start lindm-agent.service"); err != nil {
		return nil, err
	}
	recovered, err := waitLifecycleInventory(ctx, vm, control, manifest.GetDistribution(), result.DeviceID, reinstalled)
	if err != nil {
		return nil, err
	}
	if recovered.HostSequence <= reinstalled.HostSequence || recovered.AttemptSequence <= reinstalled.AttemptSequence {
		return nil, errors.New("spool recovery rewound remote observation counters")
	}
	if err := sameGuestIdentity(ctx, vm, identity); err != nil {
		return nil, err
	}
	result.SpoolCorruptionRecovered = true
	result.Publications = append(result.Publications, recovered)
	if err := lifecycleProgress(ctx, options, "spool-recovered", recovered, false); err != nil {
		return nil, err
	}

	provider := "/usr/bin/dpkg-query"
	if format == packaging.FormatRPM {
		provider = "/usr/bin/rpm"
	}
	fault := "/run/systemd/system/lindm-agent.service.d/lindm-lab-permission.conf"
	if err := lifecycleCommand(ctx, vm, "deny native collector in its service namespace", "test ! -e "+fault+"; install -d -m 0755 /run/systemd/system/lindm-agent.service.d; printf '[Service]\\nInaccessiblePaths="+provider+"\\n' > "+fault+"; systemctl daemon-reload; systemctl restart lindm-agent.service"); err != nil {
		return nil, err
	}
	failed, err := control.WaitFailedAttempt(ctx, result.DeviceID, recovered, inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED, 7*time.Minute)
	if err != nil {
		return nil, err
	}
	result.FailedAttempt = failed
	if err := lifecycleProgress(ctx, options, "collection-denied", failed, false); err != nil {
		return nil, err
	}
	if err := control.RevokeDevice(ctx, result.DeviceID); err != nil {
		return nil, err
	}
	if err := waitGuestAuthorityRejection(ctx, vm); err != nil {
		return nil, err
	}
	result.RevocationObserved = true
	if err := holdMissingGuestJournal(ctx, vm); err != nil {
		return nil, err
	}
	result.MissingJournalHeld = true
	return result, nil
}

func lifecycleRejections(cases []packaging.RejectionCase, format packaging.Format) ([]packaging.RejectionCase, error) {
	selected := make([]packaging.RejectionCase, 0, 3)
	seen := make(map[string]bool, 3)
	for _, item := range cases {
		if item.Artifact.Format != format {
			continue
		}
		if item.Name != "unsigned" && item.Name != "tampered" && item.Name != "wrong-signer" {
			return nil, errors.New("unrecognized native rejection case")
		}
		if seen[item.Name] {
			return nil, errors.New("duplicate native rejection case")
		}
		seen[item.Name] = true
		selected = append(selected, item)
	}
	if len(selected) != 3 {
		return nil, errors.New("native lifecycle requires unsigned, tampered and wrong-signer fixtures")
	}
	return selected, nil
}

func lifecycleProgress(ctx context.Context, options VMLifecycleOptions, phase string, evidence *vmInventoryEvidence, observe bool) error {
	if options.Progress != nil {
		if _, err := fmt.Fprintf(options.Progress, "agent inventory matched: phase=%s device=%s snapshot_sequence=%d attempt_sequence=%d packages=%d\n", phase, evidence.DeviceID, evidence.SnapshotSequence, evidence.AttemptSequence, evidence.PackageCount); err != nil {
			return err
		}
	}
	if !observe || options.ObserveFor == 0 {
		return nil
	}
	timer := time.NewTimer(options.ObserveFor)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func waitLifecycleInventory(ctx context.Context, vm *guestVM, control *vmControlPlane, distribution, deviceID string, previous *vmInventoryEvidence) (*vmInventoryEvidence, error) {
	before, err := collectVMTruth(ctx, vm, distribution)
	if err != nil {
		return nil, err
	}
	// A native query may fail while the package transaction is finishing.
	// Permit the normal ten-minute recollection plus five-minute server
	// admission interval and heartbeat jitter; never accelerate product timers.
	evidence, err := control.WaitSnapshot(ctx, deviceID, before, previous, 18*time.Minute)
	if err != nil {
		return nil, err
	}
	actual, err := collectVMTruth(ctx, vm, distribution)
	if err != nil {
		return nil, err
	}
	if err := stableVMTruth(before, actual); err != nil {
		return nil, err
	}
	return evidence, nil
}

func readGuestAgentStatus(ctx context.Context, vm *guestVM) (*agentv1.AgentStatus, error) {
	data, err := vm.run(ctx, "sudo -n "+packaging.BinaryPath+" status", nil, 64<<10, 15*time.Second)
	if err != nil {
		return nil, err
	}
	status := new(agentv1.AgentStatus)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, status); err != nil {
		return nil, errors.New("guest status is not strict AgentStatus protobuf JSON")
	}
	if err := protovalidate.Validate(status); err != nil {
		return nil, errors.New("guest status does not satisfy its protobuf contract")
	}
	return status, nil
}

func sameGuestIdentity(ctx context.Context, vm *guestVM, expected *agentv1.StatusResponse) error {
	status, err := readGuestAgentStatus(ctx, vm)
	if err != nil {
		return err
	}
	actual := status.GetExecutor()
	if actual.GetLifecycle() != agentv1.Lifecycle_LIFECYCLE_ENROLLED || actual.GetInstallationId() != expected.GetInstallationId() || actual.GetDeviceId() != expected.GetDeviceId() || actual.GetEnrollmentGeneration() != expected.GetEnrollmentGeneration() || actual.GetCommittedSessionEpoch() < expected.GetCommittedSessionEpoch() {
		return errors.New("native lifecycle replaced or rewound protected identity")
	}
	return nil
}
