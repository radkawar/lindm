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
	"net"
	"net/url"
	"os"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/recoveryboot"
	"lindm/internal/devlab"
	"lindm/internal/rpcreason"
	"lindm/internal/trust"
)

type actionSignedHandoffEvidence struct {
	ImageID              string                            `json:"original_image_id"`
	DeviceID             string                            `json:"original_device_id"`
	EnrollmentGeneration string                            `json:"original_enrollment_generation"`
	Runtime              *vmRuntimeEvidence                `json:"runtime"`
	Boot                 *actionOwnedBootEvidence          `json:"owned_ordinary_boot"`
	RecoveryImageSHA256  string                            `json:"recovery_image_sha256"`
	RecoveryImageSize    int64                             `json:"recovery_image_size"`
	RecoverySizeEvidence *recoveryboot.SizeEvidence        `json:"recovery_size_evidence,omitempty"`
	ClosureSHA256        string                            `json:"signed_closure_sha256"`
	PredictedPCR11SHA256 string                            `json:"predicted_pcr11_sha256"`
	ActionID             string                            `json:"action_id"`
	ApprovalID           string                            `json:"approval_id"`
	RequesterID          string                            `json:"requester_id"`
	ApproverID           string                            `json:"approver_id"`
	Method               string                            `json:"method"`
	NVMeScope            *agentv1.NVMeSanitizeScope        `json:"approved_nvme_scope,omitempty"`
	RecoveryReadiness    *adminv1.RecoveryReadiness        `json:"preapproval_recovery_readiness,omitempty"`
	ReadinessRefresh     *actionDispatchEvidence           `json:"readiness_inventory_refresh,omitempty"`
	ServerState          string                            `json:"server_state"`
	Verification         *agentv1.DeviceActionVerification `json:"server_verified_scoped_result"`
	PoweroffObservedAt   time.Time                         `json:"recovery_poweroff_observed_at"`
	StoppedDiskSamples   *StoppedDiskSampleEvidence        `json:"host_read_only_samples"`
	Boundary             string                            `json:"boundary"`
	BootMode             string                            `json:"recovery_boot_mode"`
	StockBoot            *actionStockBootEvidence          `json:"stock_measured_boot,omitempty"`
	RecoveryKernelSHA256 string                            `json:"recovery_vendor_kernel_sha256,omitempty"`
	// Present only for the TPM-less capability refusal phase.
	AttestationRefusal *actionAttestationRefusal `json:"attestation_refusal,omitempty"`
	// ServerStorageTargets is the server's public candidate list, retained only
	// when it refuses the requested target so the identity difference is visible.
	ServerStorageTargets json.RawMessage `json:"server_storage_targets_at_refusal,omitempty"`
}

type actionAttestationRefusal struct {
	ReadinessReason      string `json:"readiness_reason"`
	DeviceReason         string `json:"device_observation_reason"`
	ApprovalReason       string `json:"approval_refusal_reason"`
	ApprovalCode         string `json:"approval_refusal_code"`
	ActionCreated        bool   `json:"action_created"`
	StagedBootFilesFound bool   `json:"staged_boot_files_found"`
}

func nativeOriginalRecoveryScenario(ctx context.Context, options VMDeviceActionsOptions, packages *actionNativePackage, fixture *devlab.AuthorityFixture, control *vmControlPlane, approver *devlab.OwnerSession, delegation *agentv1.UpdateExecutionTrustRequest, bus string) (_ *actionSignedHandoffEvidence, err error) {
	evidence := &actionSignedHandoffEvidence{ImageID: options.RecoveryManifest.GetId(), BootMode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI.String(), Boundary: "Original device identity and generation, vendor-derived disposable cloud disk, owned signer in private emulated firmware db, actual signed systemd-boot UKI and off-target ext4 one-action custody. No separately enrolled recovery identity or host boot modification. NVMe format is emulated controller qualification; SATA overwrite is explicitly a rotational emulation method, not ATA secure erase or physical flash sanitization."}
	measured := options.RecoveryBootMode == recoveryBootMeasured
	refusal := options.WipePhase == "recovery-attestation-refusal"
	if measured {
		evidence.BootMode = agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB.String()
		evidence.Boundary = "Original device identity and generation, unmodified vendor cloud disk booting the firmware-enrolled Microsoft-signed vendor shim, vendor-signed GRUB and the vendor-signed kernel, unsigned lindm initramfs on /boot proven only by a fresh swtpm quote and event-log replay verified by the server, and off-target ext4 one-action custody. No firmware key, ESP, loader or kernel change. NVMe format is emulated controller qualification; SATA overwrite is explicitly a rotational emulation method, not ATA secure erase or physical flash sanitization. Software TPM, not a physical TPM or EK-certified attestation key."
	}
	if !options.Encrypted.Firmware.SecureBoot {
		return evidence, errors.New("original signed recovery requires explicitly selected Secure Boot firmware")
	}
	workDir, err := os.MkdirTemp(options.Encrypted.WorkDir, "lindm-native-recovery-build-")
	if err != nil {
		return evidence, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(workDir)) }()
	var signer *actionBootSigner
	firmware := options.Encrypted.Firmware
	if !measured {
		signer, err = newActionBootSigner(options.Encrypted.WorkDir)
		if err != nil {
			return evidence, err
		}
		defer func() { err = errors.Join(err, signer.Close()) }()
		firmware.OwnedDBCertificate = signer.certificate
	}
	hardware := *options.Encrypted.Hardware
	hardware.StorageBus, hardware.ExtraDisks, hardware.Desktop, hardware.Firmware = bus, 1, false, &firmware
	if refusal {
		hardware.TPM = false
	} else if measured && !hardware.TPM {
		return evidence, errors.New("measured GRUB recovery qualification requires a TPM")
	}
	vm, _, err := newVerifiedGuestWithHardware(ctx, options.RecoveryManifest, options.Encrypted.CacheDir, options.Encrypted.WorkDir, true, &hardware)
	if err != nil {
		return evidence, err
	}
	poweredOff := false
	defer func() {
		if poweredOff {
			err = errors.Join(err, vm.closeAfterExpectedExit())
		} else {
			err = errors.Join(err, vm.close())
		}
	}()
	defer func() { err = diagnoseActionFailure(ctx, vm, err) }()
	bootContext, cancelBoot := context.WithTimeout(ctx, 8*time.Minute)
	defer cancelBoot()
	if err := vm.connect(bootContext); err != nil {
		return evidence, err
	}
	if _, err := vm.run(ctx, "sudo -n cloud-init status --wait --format=json", nil, 64<<10, 5*time.Minute); err != nil {
		return evidence, err
	}
	finishBootDiagnostics, err := observeActionGuest(ctx, vm)
	if err != nil {
		return evidence, err
	}
	entitlement := actionOwnedBootEntitlement{LabBinary: options.LabBinary, RedHatTokenFile: options.RedHatTokenFile}
	if measured {
		evidence.Boot, evidence.StockBoot, err = provisionActionStockBoot(ctx, vm, options.RecoveryManifest, entitlement)
	} else {
		evidence.Boot, err = provisionActionOwnedBoot(ctx, vm, options.RecoveryManifest, signer, entitlement)
	}
	err = finishBootDiagnostics(err)
	if err != nil {
		return evidence, err
	}
	evidence.Runtime, err = vm.runtimeEvidence(ctx)
	if err != nil {
		return evidence, err
	}
	if err := packages.Install(ctx, vm, options.LabBinary); err != nil {
		return evidence, err
	}
	qualification := &agentv1.QualifiedActionTarget{Target: evidence.Boot.OriginalTarget.Identity, QualificationId: "owned-original-signed-recovery-" + bus}
	method := agentv1.SanitizeMethod_SANITIZE_METHOD_OVERWRITE
	switch bus {
	case "nvme":
		method = agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_USER_DATA
		qualification.NativeSanitizeMethods = []agentv1.SanitizeMethod{method}
	case "sata":
		qualification.AllowOverwrite = true
	default:
		return evidence, errors.New("original native recovery requires a qualified NVMe or SATA controller")
	}
	evidence.Method = method.String()
	provider := &agentv1.DeviceActionProviderConfig{ProtectedStateDirectory: "/var/lib/lindm/executor"}
	if err := configureActionGuest(ctx, vm, provider, nil); err != nil {
		return evidence, err
	}
	connection, err := connectActionGuest(ctx, vm, fixture)
	if err != nil {
		return evidence, err
	}
	defer func() {
		if connection != nil {
			err = errors.Join(err, connection.Close())
		}
	}()
	issued, material, err := enrollActionGuest(ctx, vm, control, delegation)
	if err != nil {
		return evidence, err
	}
	evidence.DeviceID, evidence.EnrollmentGeneration = issued.GetDeviceId(), issued.GetEnrollmentGeneration()
	authority, err := trust.New()
	if err != nil {
		return evidence, err
	}
	bootstrapVerifiedAt := time.Now()
	bootstrap, err := authority.VerifyBootstrap(ctx, material.ExecutionRootJSON, material.BootstrapEnvelope, bootstrapVerifiedAt)
	if err != nil {
		return evidence, err
	}
	origin, err := url.Parse(bootstrap.Bundle.GetEnrollmentOrigin())
	if err != nil {
		return evidence, err
	}
	_, fixturePort, err := net.SplitHostPort(fixture.AdminAddress)
	if err != nil {
		return evidence, err
	}
	if origin.Scheme != "https" || origin.Hostname() != "localhost" || origin.Port() != fixturePort {
		return evidence, errors.New("signed recovery bootstrap origin must bind this isolated fixture's actual admin listener")
	}
	recoveryProvider := &agentv1.DeviceActionProviderConfig{RecoveryEnvironment: true, ProtectedStateDirectory: "/run/lindm-recovery", Targets: []*agentv1.QualifiedActionTarget{proto.CloneOf(qualification)}}
	runtime := &agentv1.RecoveryRuntimeConfig{StateDirectory: "/run/lindm-recovery", KeyFile: "/run/lindm-recovery/action.key", ServerUrl: origin.String(), ServerCaFile: "/etc/lindm/server-ca.pem", Provider: recoveryProvider, RootFile: "/etc/lindm/execution-root.json", BootstrapFile: "/etc/lindm/bootstrap-envelope.pb", Custody: agentv1.RecoveryCustody_RECOVERY_CUSTODY_OFF_TARGET, BootMode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB}
	if !measured {
		runtime.CertificateSha256, runtime.BootMode = signer.certificateSHA256, agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI
	}
	runtime.BootstrapVerifiedAt = timestamppb.New(bootstrapVerifiedAt)
	artifact, err := buildActionRecoveryArtifact(ctx, vm, workDir, signer, evidence.Boot, runtime, material.ExecutionRootJSON, material.BootstrapEnvelope, bootstrap.Bundle.GetTransportCaPem())
	if err != nil {
		return evidence, err
	}
	evidence.RecoveryImageSHA256, evidence.RecoveryImageSize = hex.EncodeToString(artifact.SHA256), artifact.Size
	evidence.RecoverySizeEvidence = artifact.SizeEvidence
	if measured {
		evidence.RecoveryKernelSHA256 = hex.EncodeToString(artifact.KernelSHA256)
		err = fixture.PublishMeasuredRecoveryArtifact(ctx, artifact.Path, artifact.SHA256, actionVendorKernel(workDir))
	} else {
		err = fixture.PublishRecoveryArtifact(ctx, artifact.Path, artifact.SHA256)
	}
	if err != nil {
		return evidence, fmt.Errorf("publish exact recovery release: %w", err)
	}
	evidence.PredictedPCR11SHA256 = hex.EncodeToString(artifact.PCR11SHA256)
	evidence.ClosureSHA256, err = dispatchFileDigest(artifact.ClosurePath)
	if err != nil {
		return evidence, err
	}
	provider.AllowRecoveryHandoff = true
	provider.Targets = []*agentv1.QualifiedActionTarget{qualification}
	var recoveryConfig *agentv1.RecoveryBootConfig
	if measured {
		imagePath := "/var/lib/lindm/executor/native-recovery.initrd"
		if err := uploadActionBootFile(ctx, vm, artifact.Path, imagePath); err != nil {
			return evidence, err
		}
		_, serialConsole, err := encryptedInstallerArchitecture(vm.hardware.Architecture)
		if err != nil {
			return evidence, err
		}
		recoveryConfig = &agentv1.RecoveryBootConfig{ImageFile: imagePath, ImageSha256: artifact.SHA256, ImageSize: uint64(artifact.Size), EspDirectory: "/boot", StateDirectory: "/var/lib/lindm-recovery", Custody: agentv1.RecoveryCustody_RECOVERY_CUSTODY_OFF_TARGET, BootMode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB, KernelSha256: artifact.KernelSHA256, SerialConsole: serialConsole}
	} else {
		imagePath, certificatePath := "/var/lib/lindm/executor/native-recovery.efi", "/var/lib/lindm/executor/native-recovery-signing.pem"
		if err := uploadActionBootFile(ctx, vm, artifact.Path, imagePath); err != nil {
			return evidence, err
		}
		if err := uploadActionBootFile(ctx, vm, signer.certificate, certificatePath); err != nil {
			return evidence, err
		}
		recoveryConfig = &agentv1.RecoveryBootConfig{ImageFile: imagePath, ImageSha256: artifact.SHA256, ImageSize: uint64(artifact.Size), SignerCertificateFile: certificatePath, SignerCertificateSha256: signer.certificateSHA256, EspDirectory: "/boot/efi", StateDirectory: "/var/lib/lindm-recovery", Custody: agentv1.RecoveryCustody_RECOVERY_CUSTODY_OFF_TARGET, BootMode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI}
	}
	if err := configureActionGuest(ctx, vm, provider, recoveryConfig); err != nil {
		return evidence, err
	}
	if _, err := waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED); err != nil {
		return evidence, err
	}
	if err := lifecycleCommand(ctx, vm, "verify reconfigured recovery relay", "systemctl is-active --quiet lindm-agent.service"); err != nil {
		return evidence, err
	}
	if err := waitNativeActionPresence(ctx, control.session, evidence.DeviceID); err != nil {
		return evidence, err
	}
	// A service restart can resume the previous immutable inventory spool.
	// Request a real signed refresh after changing local recovery configuration;
	// do not confuse fresh contact with a new root readiness observation.
	refresh := actionRequestFor(evidence.DeviceID, evidence.EnrollmentGeneration, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_RefreshInventory{RefreshInventory: &agentv1.RefreshInventoryAction{}}})
	evidence.ReadinessRefresh, _, err = dispatchNativeAction(ctx, vm, control.session, refresh, nil, false)
	if err != nil {
		return evidence, fmt.Errorf("publish reconfigured recovery readiness: %w", err)
	}
	media, err := trust.DeviceActionDigest(qualification.GetTarget())
	if err != nil {
		return evidence, err
	}
	sanitize := &agentv1.SanitizeAction{Target: qualification.GetTarget(), Method: method, Recovery: &agentv1.RecoveryBootSpec{ImageSha256: artifact.SHA256, BootMode: recoveryConfig.GetBootMode(), MediaSha256: media[:]}}
	if bus == "nvme" {
		topology, err := vm.run(ctx, "lsblk --json --tree --bytes --output PATH,TYPE,SIZE,WWN,SERIAL,UUID,FSTYPE", nil, 1<<20, 15*time.Second)
		if err != nil {
			return evidence, err
		}
		currentPath, err := actionWholeDiskPath(topology, qualification.GetTarget())
		if err != nil {
			return evidence, err
		}
		targetJSON, err := protojson.Marshal(qualification.GetTarget())
		if err != nil {
			return evidence, err
		}
		observed, err := vm.runResult(ctx, "sudo -n "+guestLifecycleProbe+" guest nvme-identity "+nativeQuote(currentPath), bytes.NewReader(targetJSON), 16<<10, 90*time.Second)
		if err != nil {
			return evidence, fmt.Errorf("observe approved native NVMe identity: %w", err)
		}
		if observed.ExitCode != 0 || len(observed.Stderr) != 0 {
			// This read-only identity probe carries no key material.
			return evidence, fmt.Errorf("observe approved native NVMe identity: exit=%d stderr=%q", observed.ExitCode, observed.Stderr)
		}
		scope := new(agentv1.NVMeSanitizeScope)
		if err := protojson.Unmarshal(observed.Stdout, scope); err != nil {
			return evidence, err
		}
		if err := protovalidate.Validate(scope); err != nil {
			return evidence, err
		}
		sanitize.NvmeScope = scope
		evidence.NVMeScope = proto.CloneOf(scope)
	}
	request := actionRequestFor(evidence.DeviceID, evidence.EnrollmentGeneration, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Sanitize{Sanitize: sanitize}})
	evidence.RecoveryReadiness, err = waitRecoveryReadiness(ctx, control.session, evidence.DeviceID, artifact.SHA256)
	if refusal {
		evidence.AttestationRefusal, err = nativeAttestationRefusal(ctx, vm, control.session, approver, request, evidence.RecoveryReadiness, err)
		return evidence, err
	}
	if err != nil {
		return evidence, err
	}
	finishDiagnostics, err := observeActionGuest(ctx, vm)
	if err != nil {
		return evidence, err
	}
	defer func() { err = finishDiagnostics(err) }()
	if err := approveNativeAction(ctx, control.session, approver, request); err != nil {
		return evidence, err
	}
	evidence.ApprovalID, evidence.RequesterID, evidence.ApproverID = request.ApprovalId, control.session.AccountID, approver.AccountID
	created, err := control.session.Admin.CreateDeviceAction(ctx, connect.NewRequest(request))
	if err != nil {
		if rpcreason.Get(err) == "device_action_storage_target_mismatch" {
			evidence.ServerStorageTargets, err = actionServerStorageTargets(ctx, control.session, evidence.DeviceID, err)
		}
		return evidence, err
	}
	evidence.ActionID = created.Msg.GetAction().GetActionId()
	defer func() { err = diagnoseNativeAction(ctx, vm, evidence.ActionID, err) }()
	if err := lifecycleCommand(ctx, vm, "verify signed recovery dispatch relay", "systemctl is-active --quiet lindm-agent.service"); err != nil {
		return evidence, err
	}
	status, err := waitOriginalRecoveryResult(ctx, control.session, evidence.ActionID)
	if err != nil {
		return evidence, err
	}
	verification := status.GetVerification()
	if !verification.GetVerified() || !verification.GetAfter().GetRecoveryEnvironment() || !verification.GetAfter().GetOffTargetJournal() || !proto.Equal(verification.GetAfter().GetTarget(), qualification.GetTarget()) {
		return evidence, errors.New("server result did not prove exact original media from off-target recovery")
	}
	if bus == "nvme" {
		native := verification.GetNvmeSanitize()
		if !native.GetNativeCommandCompleted() || native.GetSamplesRead() != 257 || len(native.GetSampleSha256()) != 32 {
			return evidence, errors.New("original NVMe format lacked native completion and deterministic samples")
		}
	}
	evidence.Verification, evidence.ServerState = verification, status.GetState().String()
	shutdown, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	select {
	case <-vm.done:
		poweredOff = true
		evidence.PoweroffObservedAt = time.Now().UTC()
	case <-shutdown.Done():
		return evidence, errors.New("closed signed recovery image did not power off after its terminal result")
	}
	if err := connection.Close(); err != nil {
		return evidence, err
	}
	connection = nil
	evidence.StoppedDiskSamples, err = vm.stoppedDiskSamples(ctx)
	if err != nil {
		return evidence, err
	}
	zero := sha256.Sum256(make([]byte, 4096))
	for _, sample := range evidence.StoppedDiskSamples.Samples {
		if sample.SHA256 != hex.EncodeToString(zero[:]) {
			return evidence, errors.New("independent powered-off original disk sample retained nonzero data")
		}
	}
	return evidence, nil
}

func waitOriginalRecoveryResult(ctx context.Context, owner *devlab.OwnerSession, actionID string) (*agentv1.DeviceActionStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		response, err := owner.Admin.GetDeviceAction(ctx, connect.NewRequest(&adminv1.GetDeviceActionRequest{ActionId: actionID}))
		if err != nil {
			return nil, err
		}
		status := response.Msg.GetAction().GetStatus()
		switch status.GetState() {
		case agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED:
			return status, nil
		case agentv1.DeviceActionState_DEVICE_ACTION_STATE_FAILED, agentv1.DeviceActionState_DEVICE_ACTION_STATE_EXPIRED:
			return nil, fmt.Errorf("original signed recovery action ended %s/%s", status.GetState(), status.GetFailure())
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("original signed recovery action deadline at %s/%s", status.GetState(), status.GetFailure())
		case <-ticker.C:
		}
	}
}

// A native observation plus authenticated release size must precede asking the
// two humans to approve. Poll only read-only inventory publication, never an
// approval or action mutation.
func waitRecoveryReadiness(ctx context.Context, owner *devlab.OwnerSession, deviceID string, image []byte) (*adminv1.RecoveryReadiness, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var last *adminv1.RecoveryReadiness
	for {
		response, err := owner.Admin.ListDeviceStorageTargets(ctx, connect.NewRequest(&adminv1.ListDeviceStorageTargetsRequest{DeviceId: deviceID, ActionKind: "sanitize", RecoveryImageSha256: image}))
		if err != nil {
			return last, fmt.Errorf("read recovery readiness after %s: %w", last.GetReason(), err)
		}
		last = response.Msg.GetRecoveryReadiness()
		if last.GetReady() && bytes.Equal(last.GetObservation().GetConfiguredImageSha256(), image) {
			return last, nil
		}
		if last.GetReason() == "device_action_esp_insufficient" {
			return last, fmt.Errorf("recovery preapproval: %s needed=%d available=%d", last.GetReason(), last.GetNeededBytes(), last.GetAvailableBytes())
		}
		// A fresh configured observation of the capability gate is terminal.
		if last.GetReason() == "device_action_recovery_attestation_unavailable" && bytes.Equal(last.GetObservation().GetConfiguredImageSha256(), image) {
			return last, fmt.Errorf("recovery preapproval: %s", last.GetReason())
		}
		select {
		case <-ctx.Done():
			return last, fmt.Errorf("recovery readiness publication deadline: %s: %w", last.GetReason(), ctx.Err())
		case <-ticker.C:
		}
	}
}

// nativeAttestationRefusal requires the TPM-less device's own readiness gate,
// then a real two-human approval attempt that the server refuses before any
// approval, action, staging or boot-entry change exists.
func nativeAttestationRefusal(ctx context.Context, vm *guestVM, owner, approver *devlab.OwnerSession, request *adminv1.CreateDeviceActionRequest, readiness *adminv1.RecoveryReadiness, readinessErr error) (*actionAttestationRefusal, error) {
	evidence := &actionAttestationRefusal{ReadinessReason: readiness.GetReason(), DeviceReason: readiness.GetObservation().GetReason()}
	if readinessErr == nil || evidence.ReadinessReason != "device_action_recovery_attestation_unavailable" || evidence.DeviceReason != "recovery_readiness_tpm_attestation_unavailable" || readiness.GetReady() {
		return evidence, fmt.Errorf("TPM-less measured recovery readiness was not the capability refusal: %s/%s: %v", evidence.ReadinessReason, evidence.DeviceReason, readinessErr)
	}
	err := approveNativeAction(ctx, owner, approver, request)
	var failure *connect.Error
	if err == nil || !errors.As(err, &failure) {
		evidence.ActionCreated = err == nil
		return evidence, fmt.Errorf("TPM-less measured recovery approval was not refused: %v", err)
	}
	evidence.ApprovalCode, evidence.ApprovalReason = failure.Code().String(), rpcreason.Get(err)
	if failure.Code() != connect.CodeFailedPrecondition || evidence.ApprovalReason != "device_action_recovery_attestation_unavailable" {
		return evidence, fmt.Errorf("TPM-less measured recovery approval refused for another reason: %s/%s", evidence.ApprovalCode, evidence.ApprovalReason)
	}
	listed, err := owner.Admin.GetDeviceActions(ctx, connect.NewRequest(&adminv1.GetDeviceActionsRequest{DeviceId: request.GetDeviceId(), PageSize: 200}))
	if err != nil {
		return evidence, err
	}
	for _, action := range listed.Msg.GetActions() {
		if action.GetSpec().GetSanitize() != nil {
			evidence.ActionCreated = true
		}
	}
	staged, err := vm.runResult(ctx, "sudo -n sh -c "+nativeQuote("ls /boot/loader/entries | grep -q '^~lindm-recovery-' || ls /boot | grep -q '^lindm-recovery-' || grub2-editenv - list | grep -q '^next_entry=.'"), nil, 4096, 15*time.Second)
	if err != nil {
		return evidence, err
	}
	evidence.StagedBootFilesFound = staged.ExitCode == 0
	if evidence.ActionCreated || evidence.StagedBootFilesFound {
		return evidence, errors.New("TPM-less measured recovery left an action or staged boot state")
	}
	return evidence, nil
}

// actionServerStorageTargets reads the server's public sanitize candidates
// (identity, size and NVMe scope; no key material) after a target refusal.
func actionServerStorageTargets(ctx context.Context, owner *devlab.OwnerSession, deviceID string, refusal error) (json.RawMessage, error) {
	response, err := owner.Admin.ListDeviceStorageTargets(ctx, connect.NewRequest(&adminv1.ListDeviceStorageTargetsRequest{DeviceId: deviceID, ActionKind: "sanitize"}))
	if err != nil {
		return nil, errors.Join(refusal, fmt.Errorf("read server storage targets after refusal: %w", err))
	}
	data, err := protojson.Marshal(response.Msg)
	return data, errors.Join(refusal, err)
}
