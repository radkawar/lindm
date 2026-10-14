// SPDX-License-Identifier: Apache-2.0

package dispatch

import (
	"bytes"
	"context"
	"log/slog"
	"path"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	recoveryv1 "lindm/gen/lindm/recovery/v1"
	"lindm/internal/measuredboot"
	"lindm/internal/rpcreason"
)

// admitMeasuredHandoff checks a device-signed measured-BLS binding against the
// offline-signed release pair before any recovery credential exists. It is
// admission only; the fresh quote is verified at start authorization.
func (s *Service) AdmitMeasuredHandoff(ctx context.Context, handoff *agentv1.DeviceActionRecoveryHandoff) error {
	measured := handoff.GetMeasuredBoot()
	mode := handoff.GetIntent().GetSpec().GetSanitize().GetRecovery().GetBootMode()
	if mode != agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB {
		if measured != nil {
			return rpcreason.Error(connect.CodePermissionDenied, "recovery_handoff_binding_rejected")
		}
		return nil
	}
	if measured == nil || handoff.GetCustody() != agentv1.RecoveryCustody_RECOVERY_CUSTODY_OFF_TARGET {
		return rpcreason.Error(connect.CodePermissionDenied, "recovery_handoff_binding_rejected")
	}
	if _, err := measuredboot.ValidateAttestationKey(measured.GetAttestationKeyPublic()); err != nil {
		return rpcreason.Error(connect.CodePermissionDenied, "recovery_attestation_key_rejected")
	}
	actionID := handoff.GetIntent().GetActionId()
	if action, err := measuredboot.ActionFromKernelOptions(measured.GetKernelOptions()); err != nil || action != actionID {
		return rpcreason.Error(connect.CodePermissionDenied, "recovery_handoff_binding_rejected")
	}
	if path.Base(measured.GetInitrdPath()) != "lindm-recovery-"+actionID+".initrd" {
		return rpcreason.Error(connect.CodePermissionDenied, "recovery_handoff_binding_rejected")
	}
	artifact, err := s.inventory.RecoveryArtifact(ctx, handoff.GetRecoveryImageSha256())
	if err != nil {
		return core.MapErr(err)
	}
	if artifact == nil || artifact.Mode != agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB || !bytes.Equal(artifact.KernelSHA256, measured.GetKernelSha256()) {
		return rpcreason.Error(connect.CodeFailedPrecondition, "device_action_recovery_kernel_mismatch")
	}
	return nil
}

// verifyRecoveryAttestation runs inside start authorization before any
// approval is consumed or grant signed. The qualifying data binds the stored,
// server-signed BOOTED checkpoint receipt and this exact start challenge.
func (s *Service) VerifyRecoveryAttestation(ctx context.Context, handoff *agentv1.DeviceActionRecoveryHandoff, receiptEnvelope []byte, challenge *agentv1.DeviceActionChallenge, attestation *recoveryv1.RecoveryAttestation) error {
	measured := handoff.GetMeasuredBoot()
	if measured == nil {
		if attestation != nil {
			return rpcreason.Error(connect.CodeInvalidArgument, "recovery_attestation_unexpected")
		}
		return nil
	}
	if attestation == nil {
		return rpcreason.Error(connect.CodePermissionDenied, "recovery_attestation_required")
	}
	if len(receiptEnvelope) == 0 {
		return rpcreason.Error(connect.CodeFailedPrecondition, "recovery_boot_checkpoint_required")
	}
	artifact, err := s.inventory.RecoveryArtifact(ctx, handoff.GetRecoveryImageSha256())
	if err != nil {
		return core.MapErr(err)
	}
	if artifact == nil || artifact.Mode != agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB || !bytes.Equal(artifact.KernelSHA256, measured.GetKernelSha256()) {
		return rpcreason.Error(connect.CodePermissionDenied, "recovery_attestation_rejected")
	}
	document, err := (proto.MarshalOptions{Deterministic: true}).Marshal(challenge)
	if err != nil {
		return core.MapErr(err)
	}
	expected := measuredboot.Expected{
		AttestationKeyPublic: measured.GetAttestationKeyPublic(),
		QualifyingData:       measuredboot.QualifyingData(receiptEnvelope, document),
		KernelSHA256:         artifact.KernelSHA256,
		InitrdSHA256:         handoff.GetRecoveryImageSha256(),
		KernelPath:           measured.GetKernelPath(),
		InitrdPath:           measured.GetInitrdPath(),
		KernelOptions:        measured.GetKernelOptions(),
	}
	evidence := measuredboot.Evidence{Quote: attestation.GetQuote(), Signature: attestation.GetSignature(), EventLog: attestation.GetEventLog()}
	if err := measuredboot.Verify(expected, evidence); err != nil {
		slog.WarnContext(ctx, "recovery attestation rejected", "action_id", handoff.GetIntent().GetActionId(), "cause", err.Error())
		return rpcreason.Error(connect.CodePermissionDenied, "recovery_attestation_rejected")
	}
	return nil
}
