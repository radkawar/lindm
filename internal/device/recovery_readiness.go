package device

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"time"

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
)

// recoveryReadinessApprovalScope runs after identity's fresh authorization and scoped
// device lock, inside the transaction that would insert the approval. It never
// makes private inventory visible to an unauthorized requester.
func (s *Service) recoveryReadinessApprovalScope(request *adminv1.CreateDeviceActionRequest) identity.ApprovalScope {
	if request.GetSpec().GetSanitize().GetRecovery() == nil {
		return s.approvalScope
	}
	return func(ctx context.Context, tx pgx.Tx, principal identity.Principal, permission identity.Permission, target uuid.UUID) error {
		if err := s.approvalScope(ctx, tx, principal, permission, target); err != nil {
			return err
		}
		q := devicedb.New(tx)
		device, err := q.GetDeviceDetail(ctx, target)
		if err != nil {
			return err
		}
		generation, err := uuid.Parse(request.GetEnrollmentGeneration())
		if err != nil || device.State != stateActive || device.CurrentGenerationID == nil || *device.CurrentGenerationID != generation {
			return rpcError(connect.CodeFailedPrecondition, "device_action_generation_rejected")
		}
		now, err := dispatchClock(ctx, q)
		if err != nil {
			return err
		}
		return s.requireRecoveryReadiness(ctx, q, generation, request.GetSpec(), now)
	}
}

func (s *Service) requireRecoveryReadiness(ctx context.Context, q *devicedb.Queries, generation uuid.UUID, spec *agentv1.DeviceActionSpec, now time.Time) error {
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
			return errInternalState
		}
	}
	readiness, err := s.recoveryReadiness(ctx, host, details, recovery.GetImageSha256(), now)
	if err != nil {
		return err
	}
	if readiness.GetReady() {
		return nil
	}
	message := readiness.GetReason()
	if message == "device_action_esp_insufficient" {
		message = fmt.Sprintf("%s needed=%d available=%d", message, readiness.GetNeededBytes(), readiness.GetAvailableBytes())
	}
	failure := connect.NewError(connect.CodeFailedPrecondition, errors.New(message))
	failure.Meta().Set("Lindm-Reason", readiness.GetReason())
	detail, err := connect.NewErrorDetail(readiness)
	if err != nil {
		return err
	}
	failure.AddDetail(detail)
	return failure
}

// recoveryReadiness uses inventory only for local facts. Even a matching local
// configured image size is never accepted as release authority.
func (s *Service) recoveryReadiness(ctx context.Context, host devicedb.GetHostObservationRow, details *inventoryv1.NativeDetails, digest []byte, now time.Time) (*adminv1.RecoveryReadiness, error) {
	observation := details.GetRecoveryReadiness()
	result := &adminv1.RecoveryReadiness{Observation: observation, ImageSha256: digest, AvailableBytes: observation.GetFreeBytes()}
	result.Reason = recoveryObservationReason(host, observation, now)
	artifactReason := "device_action_recovery_artifact_required"
	if len(digest) != 0 {
		artifactReason = "device_action_recovery_artifact_unavailable"
		if s.recoveryArtifacts != nil {
			name, err := releaseupdate.RecoveryTargetPath(digest)
			if err == nil {
				artifact, lookupErr := s.recoveryArtifacts.Artifact(ctx, name)
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				if lookupErr == nil && artifact.Length > 0 && bytes.Equal(artifact.SHA256, digest) {
					result.ImageSize = uint64(artifact.Length)
					artifactReason = ""
				}
			}
		}
	}
	if result.GetImageSize() > 0 {
		observationReason := result.Reason
		evaluateRecoveryCapacity(result)
		if observationReason != "" {
			result.Ready = false
			result.Reason = observationReason
		}
	} else if result.Reason == "" {
		result.Reason = artifactReason
	}
	return result, nil
}

func recoveryObservationReason(host devicedb.GetHostObservationRow, observation *agentv1.RecoveryReadinessObservation, now time.Time) string {
	if observation == nil || observation.GetObservedAt() == nil {
		return "device_action_recovery_readiness_missing"
	}
	observed := observation.GetObservedAt()
	if observed.CheckValid() != nil || !actionInventoryFresh(host, now) || observed.AsTime().After(now) || now.Sub(observed.AsTime()) > 5*time.Minute || host.BootIDStatus != int16(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS) || observation.GetBootId() == "" || observation.GetBootId() != host.BootIDValue {
		return "device_action_recovery_readiness_stale"
	}
	if !observation.GetAvailable() || !observation.GetSecureBoot() || !observation.GetUkiCapable() || observation.GetEspUuid() == "" || observation.GetEspPath() == "" || observation.GetAllocationUnitBytes() == 0 {
		return "device_action_recovery_readiness_unsupported"
	}
	return ""
}

func evaluateRecoveryCapacity(result *adminv1.RecoveryReadiness) *adminv1.RecoveryReadiness {
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
