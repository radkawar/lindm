// SPDX-License-Identifier: Apache-2.0

//go:build linux

package transport

import (
	"context"
	"time"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/protodata"
)

// patchStatusTimeout bounds the executor read; the executor never waits for
// native package tools or the refresh job it may start.
const patchStatusTimeout = 10 * time.Second

// attachPatchStatus publishes the executor's offline patch status unmodified.
// An unreachable executor or an invalid response becomes an explicit
// unavailable status and never blocks the rest of the inventory.
func (r *runner) attachPatchStatus(ctx context.Context, host *inventoryv1.HostObservation) {
	ctx, cancel := context.WithTimeout(ctx, patchStatusTimeout)
	defer cancel()
	failed := func(reason string) {
		boot := host.GetBootId().GetValue()
		if _, err := uuid.Parse(boot); err != nil || host.GetBootId().GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS {
			boot = ""
		}
		host.Details.PatchStatus = &agentv1.PatchStatusObservation{ObservedAt: timestamppb.Now(), BootId: boot, Reason: reason}
	}
	response, err := rpc(ctx, r.executor.GetPatchStatus, &agentv1.GetPatchStatusRequest{})
	if err != nil {
		failed("executor_unavailable")
		return
	}
	if response == nil || protodata.ValidateClosed(response.ProtoReflect()) != nil || protovalidate.Validate(response) != nil {
		failed("patch_status_invalid")
		return
	}
	host.Details.PatchStatus = response.GetObservation()
}
