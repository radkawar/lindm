//go:build linux

package transport

import (
	"context"
	"time"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/agent/inventory"
	"lindm/internal/protodata"
)

// collectNativeObservation attaches root-only public evidence before ownership
// passes to the immutable spool. Direct inventory.Collect remains unprivileged
// and never claims recovery readiness. Both publication paths use this boundary.
func (r *runner) collectNativeObservation(ctx context.Context) (*inventoryv1.NativeObservation, error) {
	collect := r.collectInventory
	if collect == nil {
		collect = inventory.CollectForUpload
	}
	observation, err := collect(ctx)
	if err != nil {
		return nil, err
	}
	host := observation.GetHost()
	if host.GetDetails() == nil {
		// Historical/partial host observations do not acquire invented details.
		return observation, nil
	}
	failed := func(reason string) {
		boot := host.GetBootId().GetValue()
		if _, err := uuid.Parse(boot); err != nil {
			boot = ""
		}
		host.Details.RecoveryReadiness = &agentv1.RecoveryReadinessObservation{
			ObservedAt: timestamppb.Now(), BootId: boot, Reason: reason,
		}
		host.Details.Storage = &inventoryv1.StorageDetails{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE}
	}
	defer func() { host.FinishedAt = timestamppb.Now() }()
	response, err := rpc(ctx, r.executor.GetRecoveryReadiness, &agentv1.GetRecoveryReadinessRequest{})
	if err != nil {
		failed("recovery_readiness_executor_unavailable")
		return observation, nil
	}
	if response == nil || protodata.ValidateClosed(response.ProtoReflect()) != nil || protovalidate.Validate(response) != nil {
		failed("recovery_readiness_executor_invalid")
		return observation, nil
	}
	readiness := response.GetObservation()
	now, started := time.Now(), host.GetStartedAt().AsTime()
	if (readiness.GetBootId() != "" && readiness.GetBootId() != host.GetBootId().GetValue()) ||
		readiness.GetObservedAt().AsTime().Before(started) || readiness.GetObservedAt().AsTime().After(now) ||
		response.GetStorageObservedAt().AsTime().Before(started) || response.GetStorageObservedAt().AsTime().After(now) {
		failed("recovery_readiness_executor_stale")
		return observation, nil
	}
	storage := new(inventoryv1.StorageDetails)
	if err := proto.Unmarshal(response.GetStorageDetails(), storage); err != nil || protodata.ValidateClosed(storage.ProtoReflect()) != nil || protovalidate.Validate(storage) != nil {
		failed("recovery_readiness_executor_invalid")
		return observation, nil
	}
	host.Details.RecoveryReadiness = readiness
	host.Details.Storage = storage
	return observation, nil
}
