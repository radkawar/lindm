package inventory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"time"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/releaseupdate"
	"lindm/internal/rpcreason"
)

// recoveryReadinessApprovalScope runs after identity's fresh authorization and scoped
// device lock, inside the transaction that would insert the approval. It never
// makes private inventory visible to an unauthorized requester.
func (s *Service) RecoveryReadinessApprovalScope(request *adminv1.CreateDeviceActionRequest) identity.ApprovalScope {
	if request.GetSpec().GetSanitize().GetRecovery() == nil {
		return s.ApprovalScope
	}
	return func(ctx context.Context, tx pgx.Tx, principal identity.Principal, permission identity.Permission, target uuid.UUID) error {
		if err := s.ApprovalScope(ctx, tx, principal, permission, target); err != nil {
			return err
		}
		q := devicedb.New(tx)
		device, err := q.GetDeviceDetail(ctx, target)
		if err != nil {
			return err
		}
		generation, err := uuid.Parse(request.GetEnrollmentGeneration())
		if err != nil || device.State != core.StateActive || device.CurrentGenerationID == nil || *device.CurrentGenerationID != generation {
			return rpcreason.Error(connect.CodeFailedPrecondition, "device_action_generation_rejected")
		}
		now, err := core.DispatchClock(ctx, q)
		if err != nil {
			return err
		}
		return s.RequireRecoveryReadiness(ctx, q, generation, request.GetSpec(), now)
	}
}

func (s *Service) RequireRecoveryReadiness(ctx context.Context, q *devicedb.Queries, generation uuid.UUID, spec *agentv1.DeviceActionSpec, now time.Time) error {
	recovery := spec.GetSanitize().GetRecovery()
	if recovery == nil {
		return nil
	}
	host, err := q.GetHostObservation(ctx, generation)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	details := new(inventoryv1.NativeDetails)
	if len(host.Details) > 0 {
		if err := proto.Unmarshal(host.Details, details); err != nil {
			return core.ErrInternalState
		}
	}
	readiness, err := s.RecoveryReadiness(ctx, host, details, recovery.GetImageSha256(), now)
	if err != nil {
		return err
	}
	if readiness.GetReady() && readiness.GetBootMode() != recovery.GetBootMode() {
		readiness.Ready = false
		readiness.Reason = "device_action_recovery_boot_mode_mismatch"
	}
	if readiness.GetReady() {
		return nil
	}
	message := readiness.GetReason()
	if message == "device_action_esp_insufficient" {
		message = fmt.Sprintf("%s needed=%d available=%d", message, readiness.GetNeededBytes(), readiness.GetAvailableBytes())
	}
	failure := connect.NewError(connect.CodeFailedPrecondition, errors.New(message))
	rpcreason.Set(failure, readiness.GetReason())
	detail, err := connect.NewErrorDetail(readiness)
	if err != nil {
		return err
	}
	failure.AddDetail(detail)
	return failure
}

// recoveryArtifact resolves the offline-signed release descriptor kind. A UKI is
// `recovery/<sha>.efi`; a measured-BLS initramfs is `recovery/<sha>.initrd`
// with its companion kernel descriptor. Absence is not an error: callers report
// the artifact as unavailable without trusting any client-supplied size.
type recoveryArtifact struct {
	Mode         agentv1.RecoveryBootMode
	size         int64
	KernelSHA256 []byte
}

func (s *Service) RecoveryArtifact(ctx context.Context, digest []byte) (*recoveryArtifact, error) {
	if s.RecoveryArtifacts == nil {
		return nil, nil
	}
	lookup := func(name string, err error) (*releaseupdate.ArtifactMetadata, error) {
		if err != nil {
			return nil, nil
		}
		artifact, lookupErr := s.RecoveryArtifacts.Artifact(ctx, name)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if lookupErr != nil || artifact.Length <= 0 || len(artifact.SHA256) != sha256.Size {
			return nil, nil
		}
		return artifact, nil
	}
	uki, err := lookup(releaseupdate.RecoveryTargetPath(digest))
	if err != nil {
		return nil, err
	}
	if uki != nil && bytes.Equal(uki.SHA256, digest) {
		return &recoveryArtifact{Mode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI, size: uki.Length}, nil
	}
	initrd, err := lookup(releaseupdate.RecoveryInitrdTargetPath(digest))
	if err != nil || initrd == nil || !bytes.Equal(initrd.SHA256, digest) {
		return nil, err
	}
	kernel, err := lookup(releaseupdate.RecoveryKernelTargetPath(digest))
	if err != nil || kernel == nil {
		return nil, err
	}
	return &recoveryArtifact{Mode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB, size: initrd.Length, KernelSHA256: bytes.Clone(kernel.SHA256)}, nil
}

// recoveryReadiness uses inventory only for local facts. Even a matching local
// configured image size is never accepted as release authority.
func (s *Service) RecoveryReadiness(ctx context.Context, host devicedb.GetHostObservationRow, details *inventoryv1.NativeDetails, digest []byte, now time.Time) (*adminv1.RecoveryReadiness, error) {
	observation := details.GetRecoveryReadiness()
	result := &adminv1.RecoveryReadiness{Observation: observation, ImageSha256: digest, AvailableBytes: observation.GetFreeBytes()}
	artifactReason := "device_action_recovery_artifact_required"
	var artifact *recoveryArtifact
	if len(digest) != 0 {
		artifactReason = "device_action_recovery_artifact_unavailable"
		var err error
		if artifact, err = s.RecoveryArtifact(ctx, digest); err != nil {
			return nil, err
		}
	}
	if artifact == nil {
		result.Reason = RecoveryObservationReason(host, observation, agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UNSPECIFIED, nil, now)
		if result.Reason == "" {
			result.Reason = artifactReason
		}
		return result, nil
	}
	result.BootMode, result.ImageSize = artifact.Mode, uint64(artifact.size)
	observationReason := RecoveryObservationReason(host, observation, artifact.Mode, artifact.KernelSHA256, now)
	EvaluateRecoveryCapacity(result)
	if observationReason != "" {
		result.Ready = false
		result.Reason = observationReason
	}
	return result, nil
}

// recoveryObservationReason evaluates the device facts for one method. An
// unspecified mode only checks freshness and generic availability.
func RecoveryObservationReason(host devicedb.GetHostObservationRow, observation *agentv1.RecoveryReadinessObservation, mode agentv1.RecoveryBootMode, kernelSHA256 []byte, now time.Time) string {
	if observation == nil || observation.GetObservedAt() == nil {
		return "device_action_recovery_readiness_missing"
	}
	observed := observation.GetObservedAt()
	if observed.CheckValid() != nil || !ActionInventoryFresh(host, now) || observed.AsTime().After(now) || now.Sub(observed.AsTime()) > 5*time.Minute || host.BootIDStatus != int16(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS) || observation.GetBootId() == "" || observation.GetBootId() != host.BootIDValue {
		return "device_action_recovery_readiness_stale"
	}
	if !observation.GetAvailable() && observation.GetReason() == "recovery_readiness_owner_key_required" {
		return "device_action_recovery_owner_key_required"
	}
	if !observation.GetAvailable() && observation.GetReason() == "recovery_readiness_tpm_attestation_unavailable" {
		return "device_action_recovery_attestation_unavailable"
	}
	if !observation.GetAvailable() || !observation.GetSecureBoot() || observation.GetEspPath() == "" || observation.GetAllocationUnitBytes() == 0 {
		return "device_action_recovery_readiness_unsupported"
	}
	switch mode {
	case agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UNSPECIFIED:
		return ""
	case agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI:
		if observation.GetBootMode() != mode || !observation.GetUkiCapable() || observation.GetEspUuid() == "" {
			return "device_action_recovery_boot_mode_mismatch"
		}
		return ""
	case agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB:
		if observation.GetBootMode() != mode {
			return "device_action_recovery_boot_mode_mismatch"
		}
		if len(kernelSHA256) != sha256.Size || !bytes.Equal(observation.GetMeasuredKernelSha256(), kernelSHA256) {
			return "device_action_recovery_kernel_mismatch"
		}
		return ""
	default:
		return "device_action_recovery_readiness_unsupported"
	}
}

func EvaluateRecoveryCapacity(result *adminv1.RecoveryReadiness) *adminv1.RecoveryReadiness {
	unit, size := result.GetObservation().GetAllocationUnitBytes(), result.GetImageSize()
	if unit == 0 || size == 0 {
		result.Reason = "device_action_recovery_readiness_unsupported"
		return result
	}
	blocks := size / unit
	if size%unit != 0 {
		blocks++
	}
	if blocks > math.MaxUint64/unit {
		result.Reason = "device_action_recovery_readiness_unsupported"
		return result
	}
	result.NeededBytes = blocks * unit
	if result.GetNeededBytes() > result.GetAvailableBytes() {
		result.Reason = "device_action_esp_insufficient"
		return result
	}
	result.Ready = true
	return result
}
