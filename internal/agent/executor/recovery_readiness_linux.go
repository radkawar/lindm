//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/recoveryboot"
)

// GetRecoveryReadiness reads public native facts using protected configuration.
// It neither needs enrollment nor stages an image, provisions keys or grants work.
func (s *Service) GetRecoveryReadiness(ctx context.Context, req *connect.Request[agentv1.GetRecoveryReadinessRequest]) (*connect.Response[agentv1.GetRecoveryReadinessResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil || req.Msg == nil {
		return nil, mapError(errInvalid)
	}
	if err := s.admit(req.Msg); err != nil {
		return nil, mapError(err)
	}
	if err := s.lock(ctx); err != nil {
		return nil, mapError(err)
	}
	defer s.mu.Unlock()
	observation := s.observeRecoveryReadiness(ctx, recoveryboot.ObserveReadiness)
	if observation.GetBootId() == "" {
		return nil, mapError(errInternal)
	}
	root, err := s.observeRootInventory(ctx)
	if err != nil {
		return nil, mapError(errInternal)
	}
	boot, err := s.bootID()
	if err != nil || boot != root.GetBootId() || boot != observation.GetBootId() || ctx.Err() != nil ||
		root.GetStartedAt().AsTime().Before(observation.GetObservedAt().AsTime()) {
		return nil, mapError(errInternal)
	}
	if err := s.admit(root); err != nil {
		return nil, mapError(errInternal)
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(root)
	if err != nil {
		return nil, mapError(errInternal)
	}
	response := &agentv1.GetRecoveryReadinessResponse{Observation: observation, RootObservation: encoded}
	if err := s.admit(response); err != nil {
		return nil, mapError(errInternal)
	}
	return noStore(response), nil
}

func (s *Service) observeRecoveryReadiness(ctx context.Context, observe func(context.Context, string) (recoveryboot.Readiness, error)) *agentv1.RecoveryReadinessObservation {
	result := &agentv1.RecoveryReadinessObservation{ObservedAt: timestamppb.New(s.now())}
	boot, err := s.bootID()
	if _, parseErr := uuid.Parse(boot); err != nil || parseErr != nil {
		result.Reason = "recovery_readiness_boot_id_unavailable"
		return result
	}
	result.BootId = boot
	cfg := s.recoveryConfig
	if cfg == nil || cfg.ESPPath == "" {
		result.Reason = "recovery_readiness_not_configured"
		return result
	}
	result.EspPath = cfg.ESPPath
	if len(cfg.ImageSHA256) == sha256.Size {
		result.ConfiguredImageSha256 = bytes.Clone(cfg.ImageSHA256)
	}
	if cfg.ImageSize > 0 {
		result.ConfiguredImageSize = proto.Uint64(uint64(cfg.ImageSize))
	}
	facts, err := observe(ctx, cfg.ESPPath)
	result.EspUuid = facts.ESPUUID
	result.FreeBytes = facts.FreeBytes
	result.AllocationUnitBytes = facts.AllocationUnitBytes
	result.SecureBoot = facts.SecureBoot
	result.UkiCapable = facts.UKICapable
	if err != nil {
		// Export only classified native reasons, never paths or raw tool output.
		switch err.Error() {
		case "recovery_readiness_root_required", "recovery_readiness_esp_unreadable",
			"recovery_readiness_esp_unsupported", "recovery_readiness_esp_capacity_invalid",
			"recovery_readiness_esp_uuid_unavailable", "recovery_readiness_secure_boot_unavailable",
			"recovery_readiness_secure_boot_required", "recovery_readiness_systemd_boot_required",
			"recovery_readiness_loader_esp_unavailable", "recovery_readiness_loader_esp_mismatch":
			result.Reason = err.Error()
		default:
			result.Reason = "recovery_readiness_observation_failed"
		}
		return result
	}
	if !facts.SecureBoot || !facts.UKICapable || facts.ESPUUID == "" || facts.AllocationUnitBytes == 0 {
		result.Reason = "recovery_readiness_unsupported"
		return result
	}
	result.Available = true
	return result
}
