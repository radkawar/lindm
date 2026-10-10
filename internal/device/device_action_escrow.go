package device

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/escrow"
	"lindm/internal/identity"
)

// deviceActionReceipt observes committed escrow in a fresh transaction before
// signing. A crash between custody and receipt leaves both device keyslots intact;
// the exact receipt is persisted for transport replay, never new start authority.
func (s *Service) deviceActionReceipt(ctx context.Context, principal devicePrincipal, epoch uint64, id uuid.UUID) ([]byte, error) {
	stored, err := devicedb.New(s.pool).GetDeviceActionEscrow(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, mapErr(err)
	}
	if s.signing == nil || s.execution == nil {
		return nil, rpcError(connect.CodeFailedPrecondition, "execution_signing_unconfigured")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	snapshot, verifier, err := s.execution.CurrentInTransaction(ctx, tx)
	if err != nil {
		return nil, executionError(err)
	}
	q := devicedb.New(tx)
	device, err := s.lockAuthority(ctx, q, principal)
	if err != nil {
		return nil, mapErr(err)
	}
	if uint64(device.generation.SessionEpoch) != epoch {
		return nil, mapErr(errSessionFenced)
	}
	action, err := q.LockDeviceAction(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	if action.DeviceID != principal.DeviceID || action.GenerationID != principal.GenerationID {
		return nil, rpcError(connect.CodePermissionDenied, "device_action_binding_rejected")
	}
	if len(action.EscrowReceiptEnvelope) > 0 {
		if err := tx.Commit(ctx); err != nil {
			return nil, mapErr(err)
		}
		return action.EscrowReceiptEnvelope, nil
	}
	status := new(agentv1.DeviceActionStatus)
	if proto.Unmarshal(action.StatusDocument, status) != nil {
		return nil, mapErr(errInternalState)
	}
	recovery := status.GetVerification().GetEscrow()
	if recovery == nil || !bytes.Equal(recovery.GetRecoveryKeySha256(), stored.SecretSha256) {
		return nil, mapErr(errInternalState)
	}
	intentDigest := sha256.Sum256(action.IntentEnvelope)
	escrowDigest, err := actionDigest(recovery)
	if err != nil {
		return nil, mapErr(err)
	}
	if snapshot.Delegation == nil {
		return nil, rpcError(connect.CodeFailedPrecondition, "execution_authority_unconfigured")
	}
	receipt := &agentv1.DeviceActionEscrowReceipt{DeploymentId: s.deploymentID.String(), DeviceId: principal.DeviceID.String(), EnrollmentGeneration: principal.GenerationID.String(), ActionId: id.String(), IntentSha256: intentDigest[:], EscrowSha256: escrowDigest, RecoveryKeySha256: stored.SecretSha256, NewKeyslot: recovery.GetNewKeyslot(), LuksUuid: recovery.GetLuksUuid(), EscrowKeyId: recovery.GetEscrowKeyId(), StoredAt: timestamppb.New(stored.CommittedAt.Time), RootVersion: snapshot.Root.GetVersion(), DelegationVersion: snapshot.Delegation.GetVersion()}
	envelope, err := s.authority.Sign(ctx, receipt, s.signing.StartKey)
	if err != nil {
		return nil, executionError(err)
	}
	intent, err := actionIntent(action)
	if err != nil {
		return nil, mapErr(err)
	}
	now, err := dispatchClock(ctx, q)
	if err != nil {
		return nil, mapErr(err)
	}
	record := &agentv1.DeviceActionRecord{Intent: intent, IntentSha256: intentDigest[:], Verification: status.GetVerification(), StartedAt: status.GetStartedAt()}
	if _, err := verifier.VerifyDeviceActionEscrowReceipt(ctx, snapshot.Root, snapshot.Delegation, envelope, record, now); err != nil {
		return nil, executionError(err)
	}
	if err := q.SetDeviceActionEscrowReceipt(ctx, devicedb.SetDeviceActionEscrowReceiptParams{ID: id, EscrowReceiptEnvelope: envelope}); err != nil {
		return nil, mapErr(err)
	}
	if err := dispatchAudit(ctx, q, nil, "device_action.escrow_receipt", id, "durable_escrow_committed"); err != nil {
		return nil, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return envelope, nil
}

func (s *Service) GetDeviceEncryption(ctx context.Context, req *connect.Request[adminv1.GetDeviceEncryptionRequest]) (*connect.Response[adminv1.GetDeviceEncryptionResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_device_encryption")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	id, _ := uuid.Parse(req.Msg.GetDeviceId())
	var luksUUID *uuid.UUID
	if req.Msg.GetLuksUuid() != "" {
		parsed, err := uuid.Parse(req.Msg.GetLuksUuid())
		if err != nil {
			return nil, invalid("invalid_luks_uuid")
		}
		luksUUID = &parsed
	}
	q := devicedb.New(tx)
	if err := requireDeviceScope(ctx, q, actor, identity.PermissionReadFleet, id); err != nil {
		return nil, mapErr(err)
	}
	response := &adminv1.GetDeviceEncryptionResponse{}
	if s.escrow != nil {
		response.EscrowKeyId = s.escrow.KeyID()
		response.EscrowPublicKey = s.escrow.PublicKey()
	}
	row, err := q.LatestDeviceActionObservation(ctx, devicedb.LatestDeviceActionObservationParams{DeviceID: id, LuksUuid: luksUUID})
	if err == nil {
		status := new(agentv1.DeviceActionStatus)
		if proto.Unmarshal(row.StatusDocument, status) != nil {
			return nil, mapErr(errInternalState)
		}
		response.Observation = encryptionObservation(status, req.Msg.GetLuksUuid())
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, mapErr(err)
	}
	row, err = q.LatestDeviceActionEscrow(ctx, devicedb.LatestDeviceActionEscrowParams{DeviceID: id, LuksUuid: luksUUID})
	if err == nil {
		stored, err := q.GetDeviceActionEscrow(ctx, row.ID)
		if err != nil {
			return nil, mapErr(err)
		}
		binding := new(agentv1.RecoveryKeyBinding)
		if proto.Unmarshal(stored.BindingDocument, binding) != nil {
			return nil, mapErr(errInternalState)
		}
		status := new(agentv1.DeviceActionStatus)
		if proto.Unmarshal(row.StatusDocument, status) != nil {
			return nil, mapErr(errInternalState)
		}
		response.Escrow = &adminv1.DeviceRecoveryEscrow{ActionId: row.ID.String(), LuksUuid: binding.GetLuksUuid(), Keyslot: binding.GetNewKeyslot(), StoredAt: timestamppb.New(stored.CommittedAt.Time), RetirementConfirmed: status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return noStore(response), nil
}

func (s *Service) RevealRecoveryKey(ctx context.Context, req *connect.Request[adminv1.RevealRecoveryKeyRequest]) (*connect.Response[adminv1.RevealRecoveryKeyResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.require(ctx, identity.PermissionReadRecoveryKeys)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil || hasNUL(req.Msg.GetReason()) {
		return nil, invalid("invalid_recovery_key_reveal")
	}
	if s.identity == nil || s.escrow == nil {
		return nil, rpcError(connect.CodeFailedPrecondition, "escrow_unconfigured")
	}
	if err := s.identity.RequireRecentStepUp(ctx, 5*time.Minute); err != nil {
		return nil, rpcError(connect.CodePermissionDenied, "recent_step_up_required")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	authorization, err := s.identity.AuthorizeFresh(ctx, actor.ID, identity.PermissionReadRecoveryKeys)
	if err != nil {
		return nil, executionError(err)
	}
	if s.revealApproval && req.Msg.GetApprovalId() == "" {
		return nil, approvalError(identity.ErrApprovalRequired)
	}
	consumption, err := s.prepareActionApproval(ctx, actor, identity.PermissionReadRecoveryKeys, req.Msg.GetApprovalId(), req.Msg)
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.lockActionApproval(ctx, tx, consumption, authorization, identity.PermissionReadRecoveryKeys); err != nil {
		return nil, approvalError(err)
	}
	deviceID, _ := uuid.Parse(req.Msg.GetDeviceId())
	id, _ := uuid.Parse(req.Msg.GetActionId())
	q := devicedb.New(tx)
	if _, err := lockDeviceScope(ctx, q, authorization.Principal(), identity.PermissionReadRecoveryKeys, deviceID); err != nil {
		return nil, mapErr(err)
	}
	action, err := q.GetDeviceAction(ctx, id)
	if err != nil {
		return nil, mapErr(notFoundIfMissing(err))
	}
	if action.DeviceID != deviceID {
		return nil, mapErr(errNotFound)
	}
	stored, err := q.GetDeviceActionEscrow(ctx, id)
	if err != nil {
		return nil, mapErr(notFoundIfMissing(err))
	}
	// Audit admission commits before plaintext is released, including every replay.
	if err := dispatchAudit(ctx, q, &actor.ID, "recovery_key.reveal", id, req.Msg.GetReason()); err != nil {
		return nil, mapErr(err)
	}
	if err := s.lockActionApproval(ctx, tx, consumption, authorization, identity.PermissionReadRecoveryKeys); err != nil {
		return nil, approvalError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	secret, err := s.escrow.Reveal(stored.BindingDocument, &escrow.Record{KeyID: stored.KeyID, WrappedKey: stored.WrappedKey, Ciphertext: stored.Ciphertext, SecretSHA256: stored.SecretSha256})
	if err != nil {
		return nil, rpcError(connect.CodeFailedPrecondition, "escrow_custody_rejected")
	}
	return noStore(&adminv1.RevealRecoveryKeyResponse{RecoveryKey: secret}), nil
}
