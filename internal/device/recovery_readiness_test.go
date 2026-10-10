package device

import (
	"bytes"
	"crypto/sha256"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	return &agentv1.RecoveryReadinessObservation{ObservedAt: timestamppb.New(now), BootId: uuid.NewString(), Available: true, EspUuid: "1234-ABCD", EspPath: "/boot/efi", FreeBytes: 8192, AllocationUnitBytes: 4096, SecureBoot: true, UkiCapable: true}
}

// The same real signed-repository setup is used by RPC integration regressions.
func recoveryArtifactFixture(t *testing.T, payload []byte) (*releaseupdate.Client, []byte) {
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
	name, err := releaseupdate.RecoveryTargetPath(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(directory, "recovery.efi")
	if err := os.WriteFile(source, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := publisher.PublishArtifact(t.Context(), name, source); err != nil {
		t.Fatal(err)
	}
	root, err := os.ReadFile(filepath.Join(repository, "metadata/1.root.json"))
	if err != nil {
		t.Fatal(err)
	}
	client, err := releaseupdate.NewClient(releaseupdate.ClientConfig{StateDir: filepath.Join(directory, "verified"), BootstrapRoot: root, Fetch: releaseupdate.DirectoryFetch(repository)})
	if err != nil {
		t.Fatal(err)
	}
	return client, digest[:]
}

func TestRecoveryObservationAdmissionBoundaries(t *testing.T) {
	now := time.Now().UTC()
	valid := recoveryObservationFixture(now)
	host := devicedb.GetHostObservationRow{ReceivedAt: timestamptz(now), BootIDStatus: int16(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS), BootIDValue: valid.GetBootId()}
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
			h.ReceivedAt = timestamptz(now.Add(-6 * time.Minute))
		}, "device_action_recovery_readiness_stale"},
		{"unavailable", func(o *agentv1.RecoveryReadinessObservation, _ *devicedb.GetHostObservationRow) { o.Available = false }, "device_action_recovery_readiness_unsupported"},
		{"secure_boot_disabled", func(o *agentv1.RecoveryReadinessObservation, _ *devicedb.GetHostObservationRow) { o.SecureBoot = false }, "device_action_recovery_readiness_unsupported"},
		{"no_uki", func(o *agentv1.RecoveryReadinessObservation, _ *devicedb.GetHostObservationRow) { o.UkiCapable = false }, "device_action_recovery_readiness_unsupported"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			observation, row := proto.CloneOf(valid), host
			tc.change(observation, &row)
			if got := recoveryObservationReason(row, observation, now); got != tc.reason {
				t.Fatalf("reason=%q want %q", got, tc.reason)
			}
		})
	}
	if got := recoveryObservationReason(host, nil, now); got != "device_action_recovery_readiness_missing" {
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
			got := evaluateRecoveryCapacity(&adminv1.RecoveryReadiness{Observation: &agentv1.RecoveryReadinessObservation{AllocationUnitBytes: tc.unit}, ImageSize: tc.size, AvailableBytes: tc.available})
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
	host := devicedb.GetHostObservationRow{ReceivedAt: timestamptz(now), BootIDStatus: int16(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS), BootIDValue: observation.GetBootId()}
	s := &Service{recoveryArtifacts: client}
	details := &inventoryv1.NativeDetails{RecoveryReadiness: observation}
	got, err := s.recoveryReadiness(t.Context(), host, details, digest, now)
	if err != nil || got.GetReady() || got.GetImageSize() != 8193 || got.GetNeededBytes() != 12288 || got.GetReason() != "device_action_esp_insufficient" {
		t.Fatalf("forged local size overrode signed size: %v %v", got, err)
	}
	observation.FreeBytes = 12288
	got, err = s.recoveryReadiness(t.Context(), host, details, digest, now)
	if err != nil || !got.GetReady() || !bytes.Equal(got.GetImageSha256(), digest) {
		t.Fatalf("current exact signed artifact refused: %v %v", got, err)
	}
	unknown := sha256.Sum256([]byte("unregistered image"))
	got, err = s.recoveryReadiness(t.Context(), host, details, unknown[:], now)
	if err != nil || got.GetReady() || got.GetReason() != "device_action_recovery_artifact_unavailable" {
		t.Fatalf("unregistered image admitted: %v %v", got, err)
	}
}
