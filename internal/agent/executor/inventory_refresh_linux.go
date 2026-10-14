// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

var errInventoryPublicationPending = errors.New("inventory_publication_pending")

// beginInventoryRefresh consumes the signed fresh grant before the transport may
// collect. Only a verified server publication receipt completes this operation.
func (s *Service) beginInventoryRefresh(ctx context.Context, record *agentv1.DeviceActionRecord, gate func(context.Context) error) (*agentv1.DeviceActionVerification, error) {
	if record.GetIntent().GetSpec().GetRefreshInventory() == nil {
		return nil, errResourceRejected
	}
	if err := gate(ctx); err != nil {
		return nil, err
	}
	return nil, errInventoryPublicationPending
}

func (s *Service) ConfirmDeviceActionInventory(ctx context.Context, req *connect.Request[agentv1.ConfirmDeviceActionInventoryRequest]) (*connect.Response[agentv1.ConfirmDeviceActionInventoryResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil || s.admit(req.Msg) != nil {
		return nil, mapError(errInvalid)
	}
	if err := s.lock(ctx); err != nil {
		return nil, mapError(err)
	}
	defer s.mu.Unlock()
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	record, revision, err := s.loadDeviceAction(ctx, loaded, req.Msg.GetActionId())
	if err != nil {
		return nil, mapError(err)
	}
	if len(record.GetInventoryReceiptEnvelope()) != 0 {
		if !bytes.Equal(record.GetInventoryReceiptEnvelope(), req.Msg.GetReceiptEnvelope()) {
			return nil, mapError(errIdempotencyConflict)
		}
		return noStore(&agentv1.ConfirmDeviceActionInventoryResponse{Status: deviceActionStatus(record)}), nil
	}
	if record.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING && record.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN {
		return nil, mapError(errResourceRejected)
	}
	if loaded.execution.delegation == nil {
		return nil, mapError(errResourceRejected)
	}
	receipt, err := loaded.execution.verifier.VerifyDeviceActionInventoryReceipt(ctx, loaded.execution.root, loaded.execution.delegation, req.Msg.GetReceiptEnvelope(), record, s.now())
	if err != nil {
		return nil, mapError(signedAuthorityError(ctx))
	}
	next := proto.CloneOf(record)
	next.InventoryReceiptEnvelope = bytes.Clone(req.Msg.GetReceiptEnvelope())
	next.InventoryReceiptRoot = proto.CloneOf(loaded.execution.root)
	next.InventoryReceiptDelegationEnvelope = bytes.Clone(loaded.execution.state.GetDelegationEnvelope())
	next.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED
	next.Failure = agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_NONE
	next.CompletedAt = protoTimestamp(s.now())
	next.Verification = &agentv1.DeviceActionVerification{Verified: true, After: proto.CloneOf(record.GetNativePlan().GetBefore()), InventorySequence: receipt.GetPackageSequence(), Evidence: "server-signed full inventory publication"}
	if err := s.updateDeviceAction(ctx, loaded, revision, next); err != nil {
		return nil, mapError(err)
	}
	return noStore(&agentv1.ConfirmDeviceActionInventoryResponse{Status: deviceActionStatus(next)}), nil
}

func (s *Service) verifyInventoryRefreshHistory(ctx context.Context, loaded *bound, record *agentv1.DeviceActionRecord) error {
	if len(record.GetInventoryReceiptEnvelope()) == 0 {
		if record.GetIntent().GetSpec().GetRefreshInventory() != nil && record.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED {
			return errRecoveryHold
		}
		return nil
	}
	if record.GetCompletedAt() == nil || record.GetInventoryReceiptRoot() == nil || record.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED {
		return errRecoveryHold
	}
	at := record.GetCompletedAt().AsTime()
	delegation, err := loaded.execution.verifier.VerifyDelegation(ctx, record.GetInventoryReceiptRoot(), record.GetInventoryReceiptDelegationEnvelope(), 0, 0, at)
	if err != nil {
		return historicalResourceError(ctx)
	}
	receipt, err := loaded.execution.verifier.VerifyDeviceActionInventoryReceipt(ctx, record.GetInventoryReceiptRoot(), delegation, record.GetInventoryReceiptEnvelope(), record, at)
	if err != nil || receipt.GetPackageSequence() != record.GetVerification().GetInventorySequence() {
		return historicalResourceError(ctx)
	}
	return nil
}
