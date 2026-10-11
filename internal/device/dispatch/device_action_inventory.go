package dispatch

import (
	"context"
	"crypto/sha256"
	"errors"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/rpcreason"
)

// ConfirmRefreshInventoryPublication attests the exact collections bound during
// admission, not a new collection grant. Exact retries retain the original receipt.
func (s *Service) ConfirmRefreshInventoryPublication(ctx context.Context, req *connect.Request[devicev1.ConfirmRefreshInventoryPublicationRequest]) (*connect.Response[devicev1.ConfirmRefreshInventoryPublicationResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	principal, ok := core.DevicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_inventory_publication")
	}
	if s.Signing == nil || s.Execution == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "execution_signing_unconfigured")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	authority, verifier, err := s.Execution.CurrentInTransaction(ctx, tx)
	if err != nil {
		return nil, core.ExecutionError(err)
	}
	q := devicedb.New(tx)
	device, err := s.LockAuthority(ctx, q, principal)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if uint64(device.Generation.SessionEpoch) != req.Msg.GetSessionEpoch() {
		return nil, core.MapErr(core.ErrSessionFenced)
	}
	id, _ := uuid.Parse(req.Msg.GetActionId())
	action, err := q.LockDeviceAction(ctx, id)
	if err != nil {
		return nil, core.MapErr(core.NotFoundIfMissing(err))
	}
	if action.DeviceID != principal.DeviceID || action.GenerationID != principal.GenerationID {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "device_action_binding_rejected")
	}
	intent, err := core.ActionIntent(action)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if intent.GetSpec().GetRefreshInventory() == nil || !action.StartAuthorizedAt.Valid || len(action.StartGrantEnvelope) == 0 {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "inventory_refresh_not_started")
	}
	if len(action.InventoryReceiptEnvelope) != 0 {
		if err := tx.Commit(ctx); err != nil {
			return nil, core.MapErr(err)
		}
		return core.NoStore(&devicev1.ConfirmRefreshInventoryPublicationResponse{ReceiptEnvelope: action.InventoryReceiptEnvelope}), nil
	}
	if action.ClosedAt.Valid {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "device_action_closed")
	}
	published, err := q.GetDeviceActionInventoryPublication(ctx, action.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "inventory_refresh_not_published")
	}
	if err != nil {
		return nil, core.MapErr(err)
	}
	if authority.Delegation == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "execution_authority_unconfigured")
	}
	if !core.DeviceActionSignerDelegated(authority.Delegation, s.Signing.StartKey, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, "device.refresh-inventory.v1") {
		return nil, core.DeviceActionCapabilityError("device.refresh-inventory.v1", "start")
	}
	publishedAt, ok := core.FiniteTime(published.PublishedAt)
	if !ok {
		return nil, core.MapErr(core.ErrInternalState)
	}
	intentDigest := sha256.Sum256(action.IntentEnvelope)
	grantDigest := sha256.Sum256(action.StartGrantEnvelope)
	receipt := &agentv1.DeviceActionInventoryReceipt{DeploymentId: s.DeploymentID.String(), DeviceId: principal.DeviceID.String(), EnrollmentGeneration: principal.GenerationID.String(), ActionId: id.String(), IntentSha256: intentDigest[:], StartGrantSha256: grantDigest[:], PackageSequence: uint64(published.PackageSequence), HostSequence: uint64(published.HostSequence), SnapshotId: published.SnapshotID.String(), PublishedAt: timestamppb.New(publishedAt), RootVersion: authority.Root.GetVersion(), DelegationVersion: authority.Delegation.GetVersion()}
	envelope, err := s.Authority.Sign(ctx, receipt, s.Signing.StartKey)
	if err != nil {
		return nil, core.ExecutionError(err)
	}
	now, err := core.DispatchClock(ctx, q)
	if err != nil {
		return nil, core.MapErr(err)
	}
	record := &agentv1.DeviceActionRecord{Intent: intent, IntentSha256: intentDigest[:], StartGrantSha256: grantDigest[:], StartedAt: timestamppb.New(action.StartAuthorizedAt.Time)}
	if _, err := verifier.VerifyDeviceActionInventoryReceipt(ctx, authority.Root, authority.Delegation, envelope, record, now); err != nil {
		return nil, core.ExecutionError(err)
	}
	document, err := proto.MarshalOptions{Deterministic: true}.Marshal(receipt)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if err := q.SetDeviceActionInventoryReceipt(ctx, devicedb.SetDeviceActionInventoryReceiptParams{ID: id, InventoryReceiptEnvelope: envelope, InventoryReceiptDocument: document}); err != nil {
		return nil, core.MapErr(err)
	}
	if err := core.DispatchSystemAudit(ctx, q, nil, "device_action.inventory_published", id, "status", "full_inventory_published"); err != nil {
		return nil, core.MapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	return core.NoStore(&devicev1.ConfirmRefreshInventoryPublicationResponse{ReceiptEnvelope: envelope}), nil
}
