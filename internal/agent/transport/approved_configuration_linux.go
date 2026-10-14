// SPDX-License-Identifier: Apache-2.0

//go:build linux

package transport

import (
	"context"
	"log/slog"
	"time"

	"buf.build/go/protovalidate"

	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/protodata"
)

// approvedConfigurationTimeout bounds the executor read of its local approvals.
const approvedConfigurationTimeout = 10 * time.Second

// attachApprovedConfiguration publishes the executor's approved home roots and
// package sources unmodified. An unreachable executor or invalid response
// leaves the field absent, which the server records as no current report; it
// never blocks the rest of the inventory.
func (r *runner) attachApprovedConfiguration(ctx context.Context, host *inventoryv1.HostObservation) {
	ctx, cancel := context.WithTimeout(ctx, approvedConfigurationTimeout)
	defer cancel()
	response, err := rpc(ctx, r.executor.GetApprovedConfiguration, &agentv1.GetApprovedConfigurationRequest{})
	if err != nil {
		slog.Warn("approved configuration unavailable", "error", err)
		return
	}
	if response == nil || protodata.ValidateClosed(response.ProtoReflect()) != nil || protovalidate.Validate(response) != nil {
		slog.Warn("approved configuration invalid")
		return
	}
	host.Details.ApprovedConfiguration = response.GetObservation()
}
