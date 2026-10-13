package device

import (
	"bytes"
	"crypto/sha256"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"lindm/internal/device/inventory"

	"lindm/internal/device/core"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/releaseupdate"
)

func recoveryObservationFixture(now time.Time) *agentv1.RecoveryReadinessObservation {
	return &agentv1.RecoveryReadinessObservation{ObservedAt: timestamppb.New(now), BootId: uuid.NewString(), Available: true, EspUuid: "1234-ABCD", EspPath: "/boot/efi", FreeBytes: 8192, AllocationUnitBytes: 4096, SecureBoot: true, UkiCapable: true, BootMode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI}
}

func measuredObservationFixture(now time.Time, kernel []byte) *agentv1.RecoveryReadinessObservation {
	return &agentv1.RecoveryReadinessObservation{ObservedAt: timestamppb.New(now), BootId: uuid.NewString(), Available: true, EspPath: "/boot", FreeBytes: 1 << 20, AllocationUnitBytes: 4096, SecureBoot: true, BootMode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB, MeasuredKernelSha256: kernel}
}

func publishRecoveryTarget(t *testing.T, publisher *releaseupdate.Publisher, directory, name string, payload []byte) {
	t.Helper()
	source := filepath.Join(directory, filepath.Base(name))
	if err := os.WriteFile(source, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := publisher.PublishArtifact(t.Context(), name, source); err != nil {
		t.Fatal(err)
	}
}

// The same real signed-repository setup is used by RPC integration regressions.
func recoveryArtifactFixture(t *testing.T, payload []byte) (*releaseupdate.Client, []byte) {
	t.Helper()
	client, digest, _ := recoveryArtifactRepository(t, payload, nil)
	return client, digest
}

// A nil kernel publishes a UKI; otherwise payload is a measured-BLS initramfs
// with its companion kernel descriptor.
func recoveryArtifactRepository(t *testing.T, payload, kernel []byte) (*releaseupdate.Client, []byte, []byte) {
	t.Helper()
	directory := t.TempDir()
	keys := filepath.Join(directory, "keys")
	if err := releaseupdate.GenerateDevelopmentKeys(keys); err != nil {
		t.Fatal(err)
	}
	signers, err := releaseupdate.LoadRoleSigners(keys, true)
	if err != nil {
		t.Fatal(err)
	}
	repository := filepath.Join(directory, "repository")
	publisher, err := releaseupdate.CreateRepository(t.Context(), releaseupdate.PublisherConfig{Directory: repository, Signers: signers})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	var kernelDigest []byte
	if kernel == nil {
		name, err := releaseupdate.RecoveryTargetPath(digest[:])
		if err != nil {
			t.Fatal(err)
		}
		publishRecoveryTarget(t, publisher, directory, name, payload)
	} else {
		name, err := releaseupdate.RecoveryInitrdTargetPath(digest[:])
		if err != nil {
			t.Fatal(err)
		}
		publishRecoveryTarget(t, publisher, directory, name, payload)
		if name, err = releaseupdate.RecoveryKernelTargetPath(digest[:]); err != nil {
			t.Fatal(err)
		}
		publishRecoveryTarget(t, publisher, directory, name, kernel)
		sum := sha256.Sum256(kernel)
		kernelDigest = sum[:]
	}
	root, err := os.ReadFile(filepath.Join(repository, "metadata/1.root.json"))
	if err != nil {
		t.Fatal(err)
	}
	client, err := releaseupdate.NewClient(releaseupdate.ClientConfig{StateDir: filepath.Join(directory, "verified"), BootstrapRoot: root, Fetch: releaseupdate.DirectoryFetch(repository)})
	if err != nil {
		t.Fatal(err)
	}
	return client, digest[:], kernelDigest
}

func TestRecoveryObservationAdmissionBoundaries(t *testing.T) {
	now := time.Now().UTC()
	valid := recoveryObservationFixture(now)
	host := devicedb.GetHostObservationRow{ReceivedAt: core.Timestamptz(now), BootIDStatus: int16(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS), BootIDValue: valid.GetBootId()}
	cases := []struct {
		name   string
		change func(*agentv1.RecoveryReadinessObservation, *devicedb.GetHostObservationRow)
		reason string
	}{
		{"current", func(*agentv1.RecoveryReadinessObservation, *devicedb.GetHostObservationRow) {}, ""},
		{"exact_five_minutes", func(o *agentv1.RecoveryReadinessObservation, _ *devicedb.GetHostObservationRow) {
			o.ObservedAt = timestamppb.New(now.Add(-5 * time.Minute))
		}, ""},
		{"stale", func(o *agentv1.RecoveryReadinessObservation, _ *devicedb.GetHostObservationRow) {
			o.ObservedAt = timestamppb.New(now.Add(-5*time.Minute - time.Nanosecond))
		}, "device_action_recovery_readiness_stale"},
		{"future", func(o *agentv1.RecoveryReadinessObservation, _ *devicedb.GetHostObservationRow) {
			o.ObservedAt = timestamppb.New(now.Add(time.Nanosecond))
		}, "device_action_recovery_readiness_stale"},
		{"changed_boot", func(o *agentv1.RecoveryReadinessObservation, _ *devicedb.GetHostObservationRow) {
			o.BootId = uuid.NewString()
		}, "device_action_recovery_readiness_stale"},
		{"stale_host", func(_ *agentv1.RecoveryReadinessObservation, h *devicedb.GetHostObservationRow) {
			h.ReceivedAt = core.Timestamptz(now.Add(-6 * time.Minute))
		}, "device_action_recovery_readiness_stale"},
		{"unavailable", func(o *agentv1.RecoveryReadinessObservation, _ *devicedb.GetHostObservationRow) { o.Available = false }, "device_action_recovery_readiness_unsupported"},
		{"secure_boot_disabled", func(o *agentv1.RecoveryReadinessObservation, _ *devicedb.GetHostObservationRow) { o.SecureBoot = false }, "device_action_recovery_readiness_unsupported"},
		{"no_uki", func(o *agentv1.RecoveryReadinessObservation, _ *devicedb.GetHostObservationRow) { o.UkiCapable = false }, "device_action_recovery_boot_mode_mismatch"},
		{"measured_observation_for_uki", func(o *agentv1.RecoveryReadinessObservation, _ *devicedb.GetHostObservationRow) {
			o.BootMode = agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB
		}, "device_action_recovery_boot_mode_mismatch"},
		{"tpm_attestation_unavailable", func(o *agentv1.RecoveryReadinessObservation, _ *devicedb.GetHostObservationRow) {
			o.Available, o.Reason = false, "recovery_readiness_tpm_attestation_unavailable"
		}, "device_action_recovery_attestation_unavailable"},
		{"owner_key_required", func(o *agentv1.RecoveryReadinessObservation, _ *devicedb.GetHostObservationRow) {
			o.Available, o.SecureBoot, o.Reason = false, false, "recovery_readiness_owner_key_required"
		}, "device_action_recovery_owner_key_required"},
		{"stale_owner_key_reason", func(o *agentv1.RecoveryReadinessObservation, _ *devicedb.GetHostObservationRow) {
			o.Available, o.Reason = false, "recovery_readiness_owner_key_required"
			o.ObservedAt = timestamppb.New(now.Add(-6 * time.Minute))
		}, "device_action_recovery_readiness_stale"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			observation, row := proto.CloneOf(valid), host
			tc.change(observation, &row)
			if got := inventory.RecoveryObservationReason(row, observation, agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI, nil, now); got != tc.reason {
				t.Fatalf("reason=%q want %q", got, tc.reason)
			}
		})
	}
	if got := inventory.RecoveryObservationReason(host, nil, agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI, nil, now); got != "device_action_recovery_readiness_missing" {
		t.Fatalf("missing observation: %q", got)
	}
}

func TestRecoveryCapacityRounding(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		size, unit, available, needed uint64
		reason                        string
	}{
		{"exact", 4096, 4096, 4096, 4096, ""},
		{"rounded", 4097, 4096, 8192, 8192, ""},
		{"one_byte_short", 4097, 4096, 8191, 8192, "device_action_esp_insufficient"},
		{"empty_esp", 1, 4096, 0, 4096, "device_action_esp_insufficient"},
		{"overflow", math.MaxUint64, 4096, math.MaxUint64, 0, "device_action_recovery_readiness_unsupported"},
		{"zero_unit", 1, 0, 4096, 0, "device_action_recovery_readiness_unsupported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := inventory.EvaluateRecoveryCapacity(&adminv1.RecoveryReadiness{Observation: &agentv1.RecoveryReadinessObservation{AllocationUnitBytes: tc.unit}, ImageSize: tc.size, AvailableBytes: tc.available})
			if got.GetNeededBytes() != tc.needed || got.GetReason() != tc.reason || got.GetReady() != (tc.reason == "") {
				t.Fatalf("capacity: %v", got)
			}
		})
	}
}

func TestRecoveryReadinessIgnoresCallerImageSize(t *testing.T) {
	client, digest := recoveryArtifactFixture(t, bytes.Repeat([]byte{0x5a}, 8193))
	now := time.Now().UTC()
	observation := recoveryObservationFixture(now)
	observation.ConfiguredImageSha256 = digest
	observation.ConfiguredImageSize = proto.Uint64(1)
	host := devicedb.GetHostObservationRow{ReceivedAt: core.Timestamptz(now), BootIDStatus: int16(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS), BootIDValue: observation.GetBootId()}
	s := composed(t, &core.Service{RecoveryArtifacts: client})
	details := &inventoryv1.NativeDetails{RecoveryReadiness: observation}
	got, err := s.RecoveryReadiness(t.Context(), host, details, digest, now)
	if err != nil || got.GetReady() || got.GetImageSize() != 8193 || got.GetNeededBytes() != 12288 || got.GetReason() != "device_action_esp_insufficient" {
		t.Fatalf("forged local size overrode signed size: %v %v", got, err)
	}
	observation.FreeBytes = 12288
	got, err = s.RecoveryReadiness(t.Context(), host, details, digest, now)
	if err != nil || !got.GetReady() || !bytes.Equal(got.GetImageSha256(), digest) {
		t.Fatalf("current exact signed artifact refused: %v %v", got, err)
	}
	unknown := sha256.Sum256([]byte("unregistered image"))
	got, err = s.RecoveryReadiness(t.Context(), host, details, unknown[:], now)
	if err != nil || got.GetReady() || got.GetReason() != "device_action_recovery_artifact_unavailable" {
		t.Fatalf("unregistered image admitted: %v %v", got, err)
	}
}

func TestMeasuredRecoveryReadinessBindsSignedKernel(t *testing.T) {
	kernel := bytes.Repeat([]byte{0x4b}, 5000)
	client, digest, kernelDigest := recoveryArtifactRepository(t, bytes.Repeat([]byte{0x1d}, 4097), kernel)
	now := time.Now().UTC()
	observation := measuredObservationFixture(now, kernelDigest)
	host := devicedb.GetHostObservationRow{ReceivedAt: core.Timestamptz(now), BootIDStatus: int16(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS), BootIDValue: observation.GetBootId()}
	s := composed(t, &core.Service{RecoveryArtifacts: client})
	details := &inventoryv1.NativeDetails{RecoveryReadiness: observation}
	got, err := s.RecoveryReadiness(t.Context(), host, details, digest, now)
	if err != nil || !got.GetReady() || got.GetBootMode() != agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB || got.GetImageSize() != 4097 || got.GetNeededBytes() != 8192 {
		t.Fatalf("signed measured initramfs refused: %v %v", got, err)
	}
	other := sha256.Sum256([]byte("another vendor kernel"))
	observation.MeasuredKernelSha256 = other[:]
	if got, err = s.RecoveryReadiness(t.Context(), host, details, digest, now); err != nil || got.GetReady() || got.GetReason() != "device_action_recovery_kernel_mismatch" {
		t.Fatalf("unsigned kernel admitted: %v %v", got, err)
	}
	observation.MeasuredKernelSha256 = kernelDigest
	observation.BootMode = agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI
	observation.UkiCapable, observation.EspUuid = true, "1234-ABCD"
	if got, err = s.RecoveryReadiness(t.Context(), host, details, digest, now); err != nil || got.GetReady() || got.GetReason() != "device_action_recovery_boot_mode_mismatch" {
		t.Fatalf("UKI-capable device admitted an initramfs artifact: %v %v", got, err)
	}
	observation.BootMode, observation.Available, observation.Reason = agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB, false, "recovery_readiness_tpm_attestation_unavailable"
	if got, err = s.RecoveryReadiness(t.Context(), host, details, digest, now); err != nil || got.GetReady() || got.GetReason() != "device_action_recovery_attestation_unavailable" {
		t.Fatalf("TPM-less device admitted measured recovery: %v %v", got, err)
	}
}
