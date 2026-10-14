// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"bytes"
	"context"
	"errors"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// VerifyDeviceActionInventoryReceipt authenticates publication, never another
// collection start. Current authority admits new receipts; journal recovery uses
// the retained trust snapshot and original receipt acceptance time.
func (v *ExecutionVerifier) VerifyDeviceActionInventoryReceipt(ctx context.Context, root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation, envelope []byte, record *agentv1.DeviceActionRecord, now time.Time) (*agentv1.DeviceActionInventoryReceipt, error) {
	if record.GetIntent().GetSpec().GetRefreshInventory() == nil || record.GetStartedAt() == nil || len(record.GetStartGrantSha256()) != 32 {
		return nil, errors.New("missing consumed inventory refresh")
	}
	keys, err := v.capabilityKeys(root, delegation, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, "device.refresh-inventory.v1", now)
	if err != nil {
		return nil, err
	}
	if len(envelope) == 0 || len(envelope) > 16384 {
		return nil, errors.New("invalid inventory receipt size")
	}
	receipt := new(agentv1.DeviceActionInventoryReceipt)
	if err := v.authority.Verify(ctx, envelope, receipt, 1, keys...); err != nil {
		return nil, err
	}
	i := record.GetIntent()
	if receipt.GetDeploymentId() != v.deploymentID || receipt.GetDeploymentId() != i.GetDeploymentId() || receipt.GetDeviceId() != i.GetDeviceId() || receipt.GetEnrollmentGeneration() != i.GetEnrollmentGeneration() || receipt.GetActionId() != i.GetActionId() || !bytes.Equal(receipt.GetIntentSha256(), record.GetIntentSha256()) || !bytes.Equal(receipt.GetStartGrantSha256(), record.GetStartGrantSha256()) || receipt.GetRootVersion() != root.GetVersion() || receipt.GetDelegationVersion() != delegation.GetVersion() {
		return nil, errors.New("inventory receipt binding rejected")
	}
	if receipt.GetPublishedAt().AsTime().Before(record.GetStartedAt().AsTime()) || receipt.GetPublishedAt().AsTime().After(now) {
		return nil, errors.New("inventory receipt publication time rejected")
	}
	return receipt, nil
}
