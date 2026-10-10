package device

import (
	"context"
	"crypto/sha256"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/device/devicedb"
)

// ConfirmRefreshInventoryPublication attests the exact collections bound during
// admission, not a new collection grant. Exact retries retain the original receipt.
func (s *Service) ConfirmRefreshInventoryPublication(ctx context.Context, req *connect.Request[devicev1.ConfirmRefreshInventoryPublicationRequest]) (*connect.Response[devicev1.ConfirmRefreshInventoryPublicationResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	principal, ok := devicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcError(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_inventory_publication")
	}
	if s.signing == nil || s.execution == nil {
		return nil, rpcError(connect.CodeFailedPrecondition, "execution_signing_unconfigured")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	authority, verifier, err := s.execution.CurrentInTransaction(ctx, tx)
	if err != nil {
		return nil, executionError(err)
	}
	q := devicedb.New(tx)
	device, err := s.lockAuthority(ctx, q, principal)
	if err != nil {
		return nil, mapErr(err)
	}
	if uint64(device.generation.SessionEpoch) != req.Msg.GetSessionEpoch() {
		return nil, mapErr(errSessionFenced)
	}
	id, _ := uuid.Parse(req.Msg.GetActionId())
	action, err := q.LockDeviceAction(ctx, id)
	if err != nil {
		return nil, mapErr(notFoundIfMissing(err))
	}
	if action.DeviceID != principal.DeviceID || action.GenerationID != principal.GenerationID {
		return nil, rpcError(connect.CodePermissionDenied, "device_action_binding_rejected")
	}
	intent, err := actionIntent(action)
	if err != nil {
		return nil, mapErr(err)
	}
	if intent.GetSpec().GetRefreshInventory() == nil || !action.StartAuthorizedAt.Valid || len(action.StartGrantEnvelope) == 0 {
		return nil, rpcError(connect.CodeFailedPrecondition, "inventory_refresh_not_started")
	}
	if len(action.InventoryReceiptEnvelope) != 0 {
		if err := tx.Commit(ctx); err != nil {
			return nil, mapErr(err)
		}
		return noStore(&devicev1.ConfirmRefreshInventoryPublicationResponse{ReceiptEnvelope: action.InventoryReceiptEnvelope}), nil
	}
	if action.ClosedAt.Valid {
		return nil, rpcError(connect.CodeFailedPrecondition, "device_action_closed")
	}
	published, err := q.GetDeviceActionInventoryPublication(ctx, action.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, rpcError(connect.CodeFailedPrecondition, "inventory_refresh_not_published")
	}
	if err != nil {
		return nil, mapErr(err)
	}
	if authority.Delegation == nil {
		return nil, rpcError(connect.CodeFailedPrecondition, "execution_authority_unconfigured")
	}
	if !deviceActionSignerDelegated(authority.Delegation, s.signing.StartKey, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, "device.refresh-inventory.v1") {
		return nil, deviceActionCapabilityError("device.refresh-inventory.v1", "start")
	}
	publishedAt, ok := finiteTime(published.PublishedAt)
	if !ok {
		return nil, mapErr(errInternalState)
	}
	intentDigest := sha256.Sum256(action.IntentEnvelope)
	grantDigest := sha256.Sum256(action.StartGrantEnvelope)
	receipt := &agentv1.DeviceActionInventoryReceipt{DeploymentId: s.deploymentID.String(), DeviceId: principal.DeviceID.String(), EnrollmentGeneration: principal.GenerationID.String(), ActionId: id.String(), IntentSha256: intentDigest[:], StartGrantSha256: grantDigest[:], PackageSequence: uint64(published.PackageSequence), HostSequence: uint64(published.HostSequence), SnapshotId: published.SnapshotID.String(), PublishedAt: timestamppb.New(publishedAt), RootVersion: authority.Root.GetVersion(), DelegationVersion: authority.Delegation.GetVersion()}
	envelope, err := s.authority.Sign(ctx, receipt, s.signing.StartKey)
	if err != nil {
		return nil, executionError(err)
	}
	now, err := dispatchClock(ctx, q)
	if err != nil {
		return nil, mapErr(err)
	}
	record := &agentv1.DeviceActionRecord{Intent: intent, IntentSha256: intentDigest[:], StartGrantSha256: grantDigest[:], StartedAt: timestamppb.New(action.StartAuthorizedAt.Time)}
	if _, err := verifier.VerifyDeviceActionInventoryReceipt(ctx, authority.Root, authority.Delegation, envelope, record, now); err != nil {
		return nil, executionError(err)
	}
	document, err := proto.MarshalOptions{Deterministic: true}.Marshal(receipt)
	if err != nil {
		return nil, mapErr(err)
	}
	if err := q.SetDeviceActionInventoryReceipt(ctx, devicedb.SetDeviceActionInventoryReceiptParams{ID: id, InventoryReceiptEnvelope: envelope, InventoryReceiptDocument: document}); err != nil {
		return nil, mapErr(err)
	}
	if err := dispatchAudit(ctx, q, nil, "device_action.inventory_published", id, "full_inventory_published"); err != nil {
		return nil, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return noStore(&devicev1.ConfirmRefreshInventoryPublicationResponse{ReceiptEnvelope: envelope}), nil
}
