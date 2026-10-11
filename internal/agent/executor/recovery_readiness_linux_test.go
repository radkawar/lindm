//go:build linux

package executor

import (
	"context"
	"errors"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"

	"lindm/internal/agent/recoveryboot"
)

func TestRecoveryReadinessUnavailableIsExplicit(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	const boot = "25eec0a2-bb9f-42bc-b6cc-0508320c960e"
	for _, tc := range []struct {
		name   string
		config *RecoveryBootConfig
		facts  recoveryboot.Readiness
		err    error
		reason string
	}{
		{name: "unconfigured", reason: "recovery_readiness_not_configured"},
		{name: "unreadable", config: &RecoveryBootConfig{ESPPath: "/boot/efi"}, err: errors.New("recovery_readiness_esp_unreadable"), reason: "recovery_readiness_esp_unreadable"},
		{name: "unsupported", config: &RecoveryBootConfig{ESPPath: "/boot/efi"}, facts: recoveryboot.Readiness{ESPUUID: "1234-5678", AllocationUnitBytes: 4096}, reason: "recovery_readiness_unsupported"},
		{name: "native_failure_redacted", config: &RecoveryBootConfig{ESPPath: "/boot/efi"}, err: errors.New("private-config-path: credential contents"), reason: "recovery_readiness_observation_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{clock: func() time.Time { return now }, bootID: func() (string, error) { return boot, nil }, recoveryConfig: tc.config}
			calls := 0
			got := s.observeRecoveryReadiness(t.Context(), func(_ context.Context, path string) (recoveryboot.Readiness, error) {
				calls++
				if tc.config == nil || path != tc.config.ESPPath {
					t.Fatal("observer did not use protected ESP configuration")
				}
				return tc.facts, tc.err
			})
			if got.GetAvailable() || got.GetReason() != tc.reason || got.GetBootId() != boot || !got.GetObservedAt().AsTime().Equal(now) {
				t.Fatalf("failure became readiness or lost provenance: %v", got)
			}
			if tc.config == nil && calls != 0 {
				t.Fatal("unconfigured startup probed a guessed ESP")
			}
			if err := protovalidate.Validate(got); err != nil {
				t.Fatalf("failure cannot be published: %v", err)
			}
		})
	}
}

func TestMeasuredRecoveryReadinessExportsKernelAndTPMGate(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	kernel := make([]byte, 32)
	kernel[0] = 0x4b
	cfg := &RecoveryBootConfig{ESPPath: "/boot", BootMode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB}
	s := &Service{clock: func() time.Time { return now }, bootID: func() (string, error) { return "25eec0a2-bb9f-42bc-b6cc-0508320c960e", nil }, recoveryConfig: cfg}
	ready := s.observeRecoveryReadiness(t.Context(), func(context.Context, string) (recoveryboot.Readiness, error) {
		return recoveryboot.Readiness{FreeBytes: 1 << 20, AllocationUnitBytes: 4096, SecureBoot: true, BootMode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB, MeasuredKernelSHA256: kernel}, nil
	})
	if !ready.GetAvailable() || ready.GetBootMode() != agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB || ready.GetMeasuredKernelSha256()[0] != 0x4b || ready.GetUkiCapable() {
		t.Fatalf("measured readiness: %v", ready)
	}
	if err := protovalidate.Validate(ready); err != nil {
		t.Fatal(err)
	}
	gated := s.observeRecoveryReadiness(t.Context(), func(context.Context, string) (recoveryboot.Readiness, error) {
		return recoveryboot.Readiness{FreeBytes: 1 << 20, AllocationUnitBytes: 4096, SecureBoot: true, BootMode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB}, errors.New("recovery_readiness_tpm_attestation_unavailable")
	})
	if gated.GetAvailable() || gated.GetReason() != "recovery_readiness_tpm_attestation_unavailable" || len(gated.GetMeasuredKernelSha256()) != 0 {
		t.Fatalf("TPM-less device reported measured readiness: %v", gated)
	}
	if err := protovalidate.Validate(gated); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryReadinessIsFreshAndDetachedFromConfiguration(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	cfg := &RecoveryBootConfig{ESPPath: "/boot/efi", ImageSHA256: make([]byte, 32), ImageSize: 8193}
	s := &Service{clock: func() time.Time { return now }, bootID: func() (string, error) { return "25eec0a2-bb9f-42bc-b6cc-0508320c960e", nil }, recoveryConfig: cfg}
	free := uint64(16384)
	observe := func(context.Context, string) (recoveryboot.Readiness, error) {
		return recoveryboot.Readiness{ESPUUID: "1234-5678", FreeBytes: free, AllocationUnitBytes: 4096, SecureBoot: true, UKICapable: true, BootMode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI}, nil
	}
	first := s.observeRecoveryReadiness(t.Context(), observe)
	cfg.ImageSHA256[0] = 1
	free = 0
	now = now.Add(time.Second)
	second := s.observeRecoveryReadiness(t.Context(), observe)
	if !first.GetAvailable() || first.GetFreeBytes() != 16384 || first.GetConfiguredImageSha256()[0] != 0 || second.GetFreeBytes() != 0 || !second.GetObservedAt().AsTime().After(first.GetObservedAt().AsTime()) {
		t.Fatal("readiness reused native facts or aliased protected configuration")
	}
	// Zero free bytes is still a successful observation, never artifact readiness.
	if !second.GetAvailable() || second.GetConfiguredImageSize() != 8193 {
		t.Fatal("observer incorrectly derived artifact admission")
	}
	if err := protovalidate.Validate(first); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryReadinessBootFailureDoesNotProbeNativeState(t *testing.T) {
	s := &Service{clock: time.Now, bootID: func() (string, error) { return "", errors.New("unreadable") }}
	got := s.observeRecoveryReadiness(t.Context(), func(context.Context, string) (recoveryboot.Readiness, error) {
		t.Fatal("missing boot identity probed native state")
		return recoveryboot.Readiness{}, nil
	})
	if got.GetAvailable() || got.GetReason() != "recovery_readiness_boot_id_unavailable" {
		t.Fatalf("boot failure implied readiness: %v", got)
	}
	if err := protovalidate.Validate(got); err != nil {
		t.Fatal(err)
	}
}

func TestExecutorAdmitsCompleteRootProjectionWithPrecompiledValidation(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	s := openExecutor(t, now)
	const unavailable = inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE
	root := &inventoryv1.RootObservation{
		StartedAt: timestamppb.New(now), FinishedAt: timestamppb.New(now),
		BootId:         "25eec0a2-bb9f-42bc-b6cc-0508320c960e",
		HardwareSerial: &inventoryv1.ObservedString{Status: unavailable},
		Firmware: &inventoryv1.FirmwareDetails{
			Mode:       &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: "bios"},
			SecureBoot: &inventoryv1.ObservedString{Status: unavailable},
		},
		Storage: &inventoryv1.StorageDetails{Status: unavailable},
		Cpu: &inventoryv1.CpuDetails{
			Model:         &inventoryv1.ObservedString{Status: unavailable},
			ModelSource:   &inventoryv1.ObservedString{Status: unavailable},
			LogicalCores:  &inventoryv1.ObservedUint64{Status: unavailable},
			PhysicalCores: &inventoryv1.ObservedUint64{Status: unavailable},
			X86_64Level:   &inventoryv1.ObservedString{Status: unavailable},
		},
	}
	if err := s.admit(root); err != nil {
		t.Fatalf("root projection rules were not precompiled: %v", err)
	}
	for name, mutate := range map[string]func(*inventoryv1.RootObservation){
		"missing_serial":    func(r *inventoryv1.RootObservation) { r.HardwareSerial = nil },
		"missing_firmware":  func(r *inventoryv1.RootObservation) { r.Firmware = nil },
		"missing_storage":   func(r *inventoryv1.RootObservation) { r.Storage = nil },
		"missing_cpu":       func(r *inventoryv1.RootObservation) { r.Cpu = nil },
		"missing_cpu_model": func(r *inventoryv1.RootObservation) { r.Cpu.Model = nil },
		"invalid_boot":      func(r *inventoryv1.RootObservation) { r.BootId = "" },
		"reversed_times":    func(r *inventoryv1.RootObservation) { r.FinishedAt = timestamppb.New(now.Add(-time.Second)) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := proto.CloneOf(root)
			mutate(changed)
			if err := s.admit(changed); err == nil {
				t.Fatal("executor admitted incomplete or unbound root evidence")
			}
		})
	}
}
