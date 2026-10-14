// SPDX-License-Identifier: Apache-2.0

package device

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"lindm/internal/device/core"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	recoveryv1 "lindm/gen/lindm/recovery/v1"
	"lindm/internal/measuredboot"
	"lindm/internal/rpcreason"
)

func attestationKeyPublic(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	public := measuredboot.AttestationKeyTemplate()
	public.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{X: tpm2.TPM2BECCParameter{Buffer: encoded[1:33]}, Y: tpm2.TPM2BECCParameter{Buffer: encoded[33:]}})
	return tpm2.Marshal(public)
}

func measuredHandoffFixture(t *testing.T, initrd, kernel []byte) *agentv1.DeviceActionRecoveryHandoff {
	t.Helper()
	action := uuid.NewString()
	options, err := measuredboot.KernelOptions(action, "")
	if err != nil {
		t.Fatal(err)
	}
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Sanitize{Sanitize: &agentv1.SanitizeAction{Recovery: &agentv1.RecoveryBootSpec{ImageSha256: initrd, BootMode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB}}}}
	return &agentv1.DeviceActionRecoveryHandoff{
		Intent: &agentv1.DeviceActionIntent{ActionId: action, Spec: spec}, RecoveryImageSha256: initrd, Custody: agentv1.RecoveryCustody_RECOVERY_CUSTODY_OFF_TARGET,
		MeasuredBoot: &agentv1.RecoveryMeasuredBoot{AttestationKeyPublic: attestationKeyPublic(t), KernelSha256: kernel, KernelPath: "/boot/vmlinuz-6.19.10-300.fc44.x86_64", KernelOptions: options, InitrdPath: "/boot/lindm-recovery-" + action + ".initrd"},
	}
}

func TestMeasuredHandoffAdmissionBindsReleaseAndKey(t *testing.T) {
	client, initrd, kernel := recoveryArtifactRepository(t, bytes.Repeat([]byte{0x1d}, 4097), bytes.Repeat([]byte{0x4b}, 5000))
	s := composed(t, &core.Service{RecoveryArtifacts: client})
	if err := s.AdmitMeasuredHandoff(t.Context(), measuredHandoffFixture(t, initrd, kernel)); err != nil {
		t.Fatalf("exact measured handoff refused: %v", err)
	}
	for name, change := range map[string]func(*agentv1.DeviceActionRecoveryHandoff){
		"other_kernel": func(h *agentv1.DeviceActionRecoveryHandoff) {
			h.MeasuredBoot.KernelSha256 = bytes.Repeat([]byte{1}, 32)
		},
		"software_key": func(h *agentv1.DeviceActionRecoveryHandoff) { h.MeasuredBoot.AttestationKeyPublic = []byte{1, 2, 3} },
		"other_action": func(h *agentv1.DeviceActionRecoveryHandoff) {
			h.MeasuredBoot.KernelOptions = "rdinit=/init panic=10 quiet lindm.recovery.action=" + uuid.NewString()
		},
		"foreign_initrd": func(h *agentv1.DeviceActionRecoveryHandoff) { h.MeasuredBoot.InitrdPath = "/boot/initramfs.img" },
		"tpm_custody":    func(h *agentv1.DeviceActionRecoveryHandoff) { h.Custody = agentv1.RecoveryCustody_RECOVERY_CUSTODY_TPM },
		"missing":        func(h *agentv1.DeviceActionRecoveryHandoff) { h.MeasuredBoot = nil },
	} {
		t.Run(name, func(t *testing.T) {
			handoff := measuredHandoffFixture(t, initrd, kernel)
			change(handoff)
			if err := s.AdmitMeasuredHandoff(t.Context(), handoff); err == nil {
				t.Fatal("changed measured handoff admitted")
			}
		})
	}
	uki := measuredHandoffFixture(t, initrd, kernel)
	uki.Intent.Spec.GetSanitize().Recovery.BootMode = agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI
	if err := s.AdmitMeasuredHandoff(t.Context(), uki); err == nil {
		t.Fatal("UKI handoff carried a measured binding")
	}
}

func TestRecoveryStartAttestationGate(t *testing.T) {
	client, initrd, kernel := recoveryArtifactRepository(t, bytes.Repeat([]byte{0x1d}, 4097), bytes.Repeat([]byte{0x4b}, 5000))
	s := composed(t, &core.Service{RecoveryArtifacts: client})
	handoff := measuredHandoffFixture(t, initrd, kernel)
	challenge := &agentv1.DeviceActionChallenge{ActionId: handoff.GetIntent().GetActionId(), Nonce: bytes.Repeat([]byte{3}, 32)}
	receipt := []byte("server-signed BOOTED receipt")
	if err := s.VerifyRecoveryAttestation(t.Context(), handoff, receipt, challenge, nil); rpcreason.Get(err) != "recovery_attestation_required" {
		t.Fatalf("measured start without quote: %v", err)
	}
	forged := &recoveryv1.RecoveryAttestation{Quote: []byte{1}, Signature: []byte{2}, EventLog: []byte{3}}
	if err := s.VerifyRecoveryAttestation(t.Context(), handoff, receipt, challenge, forged); rpcreason.Get(err) != "recovery_attestation_rejected" {
		t.Fatalf("forged quote: %v", err)
	}
	if err := s.VerifyRecoveryAttestation(t.Context(), handoff, nil, challenge, forged); rpcreason.Get(err) != "recovery_boot_checkpoint_required" {
		t.Fatalf("quote without BOOTED receipt: %v", err)
	}
	changed := proto.CloneOf(handoff)
	changed.MeasuredBoot.KernelSha256 = bytes.Repeat([]byte{9}, 32)
	if err := s.VerifyRecoveryAttestation(t.Context(), changed, receipt, challenge, forged); rpcreason.Get(err) != "recovery_attestation_rejected" {
		t.Fatalf("unreleased kernel: %v", err)
	}
	uki := proto.CloneOf(handoff)
	uki.MeasuredBoot = nil
	if err := s.VerifyRecoveryAttestation(t.Context(), uki, receipt, challenge, nil); err != nil {
		t.Fatalf("UKI start required a quote: %v", err)
	}
	if err := s.VerifyRecoveryAttestation(t.Context(), uki, receipt, challenge, forged); rpcreason.Get(err) != "recovery_attestation_unexpected" {
		t.Fatalf("UKI start accepted a quote: %v", err)
	}
}
