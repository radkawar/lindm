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
// passes to the immutable spool. Direct inventory.Collect retains caller
// privileges and never claims recovery readiness or patch status. Both
// publication paths use this boundary; invalid root projections are discarded
// in their entirety. A failed root observation is recorded only as the
// readiness reason: other categories keep their independent unprivileged
// collection status. Patch status is attached independently of readiness.
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
		if cpu := host.Details.Cpu; cpu.GetModelSource().GetValue() == "smbios_type4" {
			// Never retain a previous privileged model after a failed current
			// observation. Public procfs/sysfs facts and historical evidence
			// without source metadata remain independent of this projection.
			cpu.Model = &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE}
			cpu.ModelSource = &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE}
		}
		// Serial and firmware are privileged-only facts: never keep them
		// without a current root projection. Storage is not privileged-only;
		// its unprivileged collection status stands on its own.
		host.HardwareSerial = &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE}
		host.Details.Firmware = &inventoryv1.FirmwareDetails{
			Mode:       &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE},
			SecureBoot: &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE},
		}
	}
	defer func() { host.FinishedAt = timestamppb.Now() }()
	r.attachPatchStatus(ctx, host)
	response, err := rpc(ctx, r.executor.GetRecoveryReadiness, &agentv1.GetRecoveryReadinessRequest{})
	if err != nil {
		failed("recovery_readiness_executor_unavailable")
		return observation, nil
	}
	if response == nil || protodata.ValidateClosed(response.ProtoReflect()) != nil || protovalidate.Validate(response) != nil {
		failed("recovery_readiness_executor_invalid")
		return observation, nil
	}
	root := new(inventoryv1.RootObservation)
	if err := proto.Unmarshal(response.GetRootObservation(), root); err != nil || protodata.ValidateClosed(root.ProtoReflect()) != nil || protovalidate.Validate(root) != nil {
		failed("recovery_readiness_executor_invalid")
		return observation, nil
	}
	readiness := response.GetObservation()
	now, started := time.Now(), host.GetStartedAt().AsTime()
	if host.GetBootId().GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS ||
		root.GetBootId() != host.GetBootId().GetValue() || readiness.GetBootId() != root.GetBootId() ||
		readiness.GetObservedAt().AsTime().Before(started) || readiness.GetObservedAt().AsTime().After(now) ||
		root.GetStartedAt().AsTime().Before(readiness.GetObservedAt().AsTime()) || root.GetFinishedAt().AsTime().After(now) {
		failed("recovery_readiness_executor_stale")
		return observation, nil
	}
	host.Details.RecoveryReadiness = readiness
	host.Details.Storage = root.GetStorage()
	host.Details.Cpu = root.GetCpu()
	host.HardwareSerial = root.GetHardwareSerial()
	host.Details.Firmware = root.GetFirmware()
	return observation, nil
}
