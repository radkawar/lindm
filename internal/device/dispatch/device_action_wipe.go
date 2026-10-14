// SPDX-License-Identifier: Apache-2.0

package dispatch

import (
	"context"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/rpcreason"
)

func actionLUKSUUIDs(spec *agentv1.DeviceActionSpec) ([]uuid.UUID, error) {
	var targets []*agentv1.StorageTarget
	var single *agentv1.StorageTarget
	switch {
	case spec.GetEscrowRotate() != nil:
		single = spec.GetEscrowRotate().GetTarget()
	case spec.GetTpm2Bind() != nil:
		single = spec.GetTpm2Bind().GetTarget()
	case core.LiveRootAction(spec):
		targets = spec.GetCryptoErase().GetTargets()
	case spec.GetCryptoErase() != nil:
		single = spec.GetCryptoErase().GetTarget()
	}
	if single != nil {
		id, err := uuid.Parse(single.GetLuksUuid())
		if err != nil {
			return nil, core.Invalid("invalid_device_action")
		}
		return []uuid.UUID{id}, nil
	}
	ids := make([]uuid.UUID, 0, len(targets))
	for _, target := range targets {
		id, err := uuid.Parse(target.GetLuksUuid())
		if err != nil {
			return nil, core.Invalid("invalid_device_action")
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// Historical escrow is still usable after reenrollment. The signed aggregate,
// not the server, must explicitly select every retained encrypted volume.
func requireLiveRootEscrow(ctx context.Context, q *devicedb.Queries, deviceID uuid.UUID, spec *agentv1.DeviceActionSpec) error {
	if !core.LiveRootAction(spec) {
		return nil
	}
	volumes, err := q.ListDeviceEscrowedVolumes(ctx, deviceID)
	if err != nil {
		return err
	}
	for _, volume := range volumes {
		included := false
		for _, target := range spec.GetCryptoErase().GetTargets() {
			if target.GetLuksUuid() == volume.String() {
				included = true
				break
			}
		}
		if !included {
			return rpcreason.Error(connect.CodeFailedPrecondition, "device_action_escrow_scope_incomplete")
		}
	}
	return nil
}

func validateLiveRootPlan(spec *agentv1.DeviceActionSpec, plan *agentv1.DeviceActionPlan) error {
	if !core.LiveRootAction(spec) {
		return nil
	}
	targets := spec.GetCryptoErase().GetTargets()
	frozen := plan.GetCryptoEraseTargets()
	if len(targets) == 0 || len(targets) != len(frozen) || len(frozen) != len(plan.GetBefore().GetCryptoEraseTargets()) {
		return rpcreason.Error(connect.CodePermissionDenied, "device_action_aggregate_plan_rejected")
	}
	rootBacking := false
	for i, target := range frozen {
		if target.GetRootBacking() {
			rootBacking = true
		}
		if !proto.Equal(target, plan.GetBefore().GetCryptoEraseTargets()[i]) || len(target.GetMetadataSha256()) != 32 || len(target.GetRootMappingSha256()) != 32 || target.GetLuksHeaderBytes() == 0 {
			return rpcreason.Error(connect.CodePermissionDenied, "device_action_aggregate_plan_rejected")
		}
		matches := 0
		for _, expected := range targets {
			if proto.Equal(expected, target.GetTarget()) {
				matches++
			}
		}
		for j := range i {
			if proto.Equal(frozen[j].GetTarget(), target.GetTarget()) {
				matches++
			}
		}
		if matches != 1 {
			return rpcreason.Error(connect.CodePermissionDenied, "device_action_aggregate_plan_rejected")
		}
	}
	if !rootBacking {
		return rpcreason.Error(connect.CodePermissionDenied, "device_action_root_backing_missing")
	}
	return nil
}

func validateLiveRootResult(spec *agentv1.DeviceActionSpec, challenge *agentv1.DeviceActionChallenge, status *agentv1.DeviceActionStatus) error {
	if !core.LiveRootAction(spec) {
		if status.GetVolatileResult() {
			return rpcreason.Error(connect.CodePermissionDenied, "device_action_volatile_result_rejected")
		}
		return nil
	}
	if status.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED {
		return nil
	}
	plan := challenge.GetNativePlan()
	if err := validateLiveRootPlan(spec, plan); err != nil {
		return err
	}
	results := status.GetVerification().GetCryptoEraseResults()
	if !status.GetVolatileResult() || status.GetStartedAt() == nil || !status.GetVerification().GetVerified() || len(results) != len(plan.GetCryptoEraseTargets()) {
		return rpcreason.Error(connect.CodePermissionDenied, "device_action_aggregate_result_rejected")
	}
	for i, result := range results {
		if !result.GetNativeLuksErase() || !result.GetRawZeroVerified() || !result.GetMetadataAbsent() {
			return rpcreason.Error(connect.CodePermissionDenied, "device_action_aggregate_result_rejected")
		}
		matches := 0
		for _, frozen := range plan.GetCryptoEraseTargets() {
			if proto.Equal(frozen.GetTarget(), result.GetTarget()) && frozen.GetLuksHeaderBytes() == result.GetHeaderBytes() {
				matches++
			}
		}
		for j := range i {
			if proto.Equal(results[j].GetTarget(), result.GetTarget()) {
				matches++
			}
		}
		if matches != 1 {
			return rpcreason.Error(connect.CodePermissionDenied, "device_action_aggregate_result_rejected")
		}
	}
	return nil
}
