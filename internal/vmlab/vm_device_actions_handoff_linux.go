//go:build linux

package vmlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/devlab"
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
	ClosureSHA256        string                            `json:"signed_closure_sha256"`
	PredictedPCR11SHA256 string                            `json:"predicted_pcr11_sha256"`
	ActionID             string                            `json:"action_id"`
	ApprovalID           string                            `json:"approval_id"`
	RequesterID          string                            `json:"requester_id"`
	ApproverID           string                            `json:"approver_id"`
	Method               string                            `json:"method"`
	ServerState          string                            `json:"server_state"`
	Verification         *agentv1.DeviceActionVerification `json:"server_verified_scoped_result"`
	PoweroffObservedAt   time.Time                         `json:"recovery_poweroff_observed_at"`
	StoppedDiskSamples   *StoppedDiskSampleEvidence        `json:"host_read_only_samples"`
	Boundary             string                            `json:"boundary"`
}

func nativeOriginalRecoveryScenario(ctx context.Context, options VMDeviceActionsOptions, packages *actionNativePackage, fixture *devlab.AuthorityFixture, control *vmControlPlane, approver *devlab.OwnerSession, delegation *agentv1.UpdateExecutionTrustRequest, bus string) (_ *actionSignedHandoffEvidence, err error) {
	evidence := &actionSignedHandoffEvidence{ImageID: options.RecoveryManifest.GetId(), Boundary: "Original device identity and generation, vendor-derived disposable cloud disk, owned signer in private emulated firmware db, actual signed systemd-boot UKI and off-target ext4 one-action custody. No separately enrolled recovery identity or host boot modification. NVMe format is emulated controller qualification; SATA overwrite is explicitly a rotational emulation method, not ATA secure erase or physical flash sanitization."}
	if !options.Encrypted.Firmware.SecureBoot {
		return evidence, errors.New("original signed recovery requires explicitly selected Secure Boot firmware")
	}
	signer, err := newActionBootSigner(options.Encrypted.WorkDir)
	if err != nil {
		return evidence, err
	}
	defer func() { err = errors.Join(err, signer.Close()) }()
	firmware := options.Encrypted.Firmware
	firmware.OwnedDBCertificate = signer.certificate
	hardware := *options.Encrypted.Hardware
	hardware.StorageBus, hardware.ExtraDisks, hardware.Desktop, hardware.Firmware = bus, 1, false, &firmware
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
	evidence.Boot, err = provisionActionOwnedBoot(ctx, vm, options.RecoveryManifest.GetDistribution(), signer)
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
	runtime := &agentv1.RecoveryRuntimeConfig{StateDirectory: "/run/lindm-recovery", KeyFile: "/run/lindm-recovery/action.key", ServerUrl: origin.String(), ServerCaFile: "/etc/lindm/server-ca.pem", Provider: recoveryProvider, RootFile: "/etc/lindm/execution-root.json", BootstrapFile: "/etc/lindm/bootstrap-envelope.pb", CertificateSha256: signer.certificateSHA256, Custody: agentv1.RecoveryCustody_RECOVERY_CUSTODY_OFF_TARGET}
	runtime.BootstrapVerifiedAt = timestamppb.New(bootstrapVerifiedAt)
	artifact, err := buildActionRecoveryArtifact(ctx, vm, signer, evidence.Boot, runtime, material.ExecutionRootJSON, material.BootstrapEnvelope, bootstrap.Bundle.GetTransportCaPem())
	if err != nil {
		return evidence, err
	}
	evidence.RecoveryImageSHA256, evidence.RecoveryImageSize = hex.EncodeToString(artifact.SHA256), artifact.Size
	evidence.PredictedPCR11SHA256 = hex.EncodeToString(artifact.PCR11SHA256)
	evidence.ClosureSHA256, err = dispatchFileDigest(artifact.ClosurePath)
	if err != nil {
		return evidence, err
	}
	imagePath, certificatePath := "/var/lib/lindm/executor/native-recovery.efi", "/var/lib/lindm/executor/native-recovery-signing.pem"
	if err := uploadActionBootFile(ctx, vm, artifact.Path, imagePath); err != nil {
		return evidence, err
	}
	if err := uploadActionBootFile(ctx, vm, signer.certificate, certificatePath); err != nil {
		return evidence, err
	}
	provider.AllowRecoveryHandoff = true
	provider.Targets = []*agentv1.QualifiedActionTarget{qualification}
	recoveryConfig := &agentv1.RecoveryBootConfig{ImageFile: imagePath, ImageSha256: artifact.SHA256, ImageSize: uint64(artifact.Size), SignerCertificateFile: certificatePath, SignerCertificateSha256: signer.certificateSHA256, EspDirectory: "/boot/efi", StateDirectory: "/var/lib/lindm-recovery", Custody: agentv1.RecoveryCustody_RECOVERY_CUSTODY_OFF_TARGET}
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
	media, err := trust.DeviceActionDigest(qualification.GetTarget())
	if err != nil {
		return evidence, err
	}
	sanitize := &agentv1.SanitizeAction{Target: qualification.GetTarget(), Method: method, Recovery: &agentv1.RecoveryBootSpec{ImageSha256: artifact.SHA256, BootMode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI, MediaSha256: media[:]}}
	if bus == "nvme" {
		sanitize.NvmeScope = &agentv1.NVMeSanitizeScope{NamespaceId: 1, ControllerWide: false}
	}
	request := actionRequestFor(evidence.DeviceID, evidence.EnrollmentGeneration, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Sanitize{Sanitize: sanitize}})
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
		return evidence, err
	}
	evidence.ActionID = created.Msg.GetAction().GetActionId()
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
			return nil, errors.New("original signed recovery action failed or expired")
		}
		select {
		case <-ctx.Done():
			return nil, errors.New("original signed recovery action did not produce a verified terminal result")
		case <-ticker.C:
		}
	}
}
