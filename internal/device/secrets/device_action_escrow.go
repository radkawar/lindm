// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"lindm/internal/auditkind"
	"lindm/internal/device/core"

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
	"lindm/internal/rpcreason"
)

// deviceActionReceipt observes committed escrow in a fresh transaction before
// signing. A crash between custody and receipt leaves both device keyslots intact;
// the exact receipt is persisted for transport replay, never new start authority.
func (s *Service) DeviceActionReceipt(ctx context.Context, principal core.DevicePrincipal, epoch uint64, id uuid.UUID) ([]byte, error) {
	stored, err := devicedb.New(s.Pool).GetDeviceActionEscrow(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, core.MapErr(err)
	}
	if s.Signing == nil || s.Execution == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "execution_signing_unconfigured")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	snapshot, verifier, err := s.Execution.CurrentInTransaction(ctx, tx)
	if err != nil {
		return nil, core.ExecutionError(err)
	}
	q := devicedb.New(tx)
	device, err := s.LockAuthority(ctx, q, principal)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if uint64(device.Generation.SessionEpoch) != epoch {
		return nil, core.MapErr(core.ErrSessionFenced)
	}
	action, err := q.LockDeviceAction(ctx, id)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if action.DeviceID != principal.DeviceID || action.GenerationID != principal.GenerationID {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "device_action_binding_rejected")
	}
	if len(action.EscrowReceiptEnvelope) > 0 {
		if err := tx.Commit(ctx); err != nil {
			return nil, core.MapErr(err)
		}
		return action.EscrowReceiptEnvelope, nil
	}
	status := new(agentv1.DeviceActionStatus)
	if proto.Unmarshal(action.StatusDocument, status) != nil {
		return nil, core.MapErr(core.ErrInternalState)
	}
	recovery := status.GetVerification().GetEscrow()
	if recovery == nil || !bytes.Equal(recovery.GetRecoveryKeySha256(), stored.SecretSha256) {
		return nil, core.MapErr(core.ErrInternalState)
	}
	intentDigest := sha256.Sum256(action.IntentEnvelope)
	escrowDigest, err := core.ActionDigest(recovery)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if snapshot.Delegation == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "execution_authority_unconfigured")
	}
	receipt := &agentv1.DeviceActionEscrowReceipt{DeploymentId: s.DeploymentID.String(), DeviceId: principal.DeviceID.String(), EnrollmentGeneration: principal.GenerationID.String(), ActionId: id.String(), IntentSha256: intentDigest[:], EscrowSha256: escrowDigest, RecoveryKeySha256: stored.SecretSha256, NewKeyslot: recovery.GetNewKeyslot(), LuksUuid: recovery.GetLuksUuid(), EscrowKeyId: recovery.GetEscrowKeyId(), StoredAt: timestamppb.New(stored.CommittedAt.Time), RootVersion: snapshot.Root.GetVersion(), DelegationVersion: snapshot.Delegation.GetVersion(), LocalAdmin: recovery.GetLocalAdmin()}
	envelope, err := s.Authority.Sign(ctx, receipt, s.Signing.StartKey)
	if err != nil {
		return nil, core.ExecutionError(err)
	}
	intent, err := core.ActionIntent(action)
	if err != nil {
		return nil, core.MapErr(err)
	}
	now, err := core.DispatchClock(ctx, q)
	if err != nil {
		return nil, core.MapErr(err)
	}
	record := &agentv1.DeviceActionRecord{Intent: intent, IntentSha256: intentDigest[:], Verification: status.GetVerification(), StartedAt: status.GetStartedAt()}
	if _, err := verifier.VerifyDeviceActionEscrowReceipt(ctx, snapshot.Root, snapshot.Delegation, envelope, record, now); err != nil {
		return nil, core.ExecutionError(err)
	}
	if err := q.SetDeviceActionEscrowReceipt(ctx, devicedb.SetDeviceActionEscrowReceiptParams{ID: id, EscrowReceiptEnvelope: envelope}); err != nil {
		return nil, core.MapErr(err)
	}
	if err := core.DispatchSystemAudit(ctx, q, nil, auditkind.DeviceActionEscrowReceipt, id, "status", "durable_escrow_committed"); err != nil {
		return nil, core.MapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	return envelope, nil
}

func (s *Service) GetDeviceEncryption(ctx context.Context, req *connect.Request[adminv1.GetDeviceEncryptionRequest]) (*connect.Response[adminv1.GetDeviceEncryptionResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_device_encryption")
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	id, _ := uuid.Parse(req.Msg.GetDeviceId())
	var luksUUID *uuid.UUID
	if req.Msg.GetLuksUuid() != "" {
		parsed, err := uuid.Parse(req.Msg.GetLuksUuid())
		if err != nil {
			return nil, core.Invalid("invalid_luks_uuid")
		}
		luksUUID = &parsed
	}
	q := devicedb.New(tx)
	if err := core.RequireDeviceScope(ctx, q, actor, identity.PermissionReadFleet, id); err != nil {
		return nil, core.MapErr(err)
	}
	response := &adminv1.GetDeviceEncryptionResponse{}
	if response.RecoveryKeyRevealApproval, err = s.CallerRevealApproval(ctx, q, actor, identity.PermissionReadRecoveryKeys, id); err != nil {
		return nil, err
	}
	if s.Escrow != nil {
		response.EscrowKeyId = s.Escrow.KeyID()
		response.EscrowPublicKey = s.Escrow.PublicKey()
	}
	row, err := q.LatestDeviceActionObservation(ctx, devicedb.LatestDeviceActionObservationParams{DeviceID: id, LuksUuid: luksUUID})
	if err == nil {
		status := new(agentv1.DeviceActionStatus)
		if proto.Unmarshal(row.StatusDocument, status) != nil {
			return nil, core.MapErr(core.ErrInternalState)
		}
		response.Observation = core.EncryptionObservation(status, req.Msg.GetLuksUuid())
		response.Tpm2TokenReferences = core.TPM2TokenReferences(response.Observation)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, core.MapErr(err)
	}
	if response.GetTpm2TokenReferences() > 0 {
		device, err := q.GetDeviceDetail(ctx, id)
		if err != nil {
			return nil, core.MapErr(err)
		}
		if device.CurrentGenerationID != nil {
			host, err := q.GetHostObservation(ctx, *device.CurrentGenerationID)
			if err == nil {
				response.Tpm2TokenReferencesRequired = core.TPM2TokenReferencesRequired(host)
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return nil, core.MapErr(err)
			}
		}
	}
	row, err = q.LatestDeviceActionEscrow(ctx, devicedb.LatestDeviceActionEscrowParams{DeviceID: id, LuksUuid: luksUUID})
	if err == nil {
		stored, err := q.GetDeviceActionEscrow(ctx, row.ID)
		if err != nil {
			return nil, core.MapErr(err)
		}
		binding := new(agentv1.RecoveryKeyBinding)
		if proto.Unmarshal(stored.BindingDocument, binding) != nil {
			return nil, core.MapErr(core.ErrInternalState)
		}
		status := new(agentv1.DeviceActionStatus)
		if proto.Unmarshal(row.StatusDocument, status) != nil {
			return nil, core.MapErr(core.ErrInternalState)
		}
		response.Escrow = &adminv1.DeviceRecoveryEscrow{ActionId: row.ID.String(), LuksUuid: binding.GetLuksUuid(), Keyslot: binding.GetNewKeyslot(), StoredAt: timestamppb.New(stored.CommittedAt.Time), RetirementConfirmed: status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, core.MapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	return core.NoStore(response), nil
}

func (s *Service) RevealRecoveryKey(ctx context.Context, req *connect.Request[adminv1.RevealRecoveryKeyRequest]) (*connect.Response[adminv1.RevealRecoveryKeyResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionReadRecoveryKeys)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil || core.HasNUL(req.Msg.GetReason()) {
		return nil, core.Invalid("invalid_recovery_key_reveal")
	}
	if s.Identity == nil || s.Escrow == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "escrow_unconfigured")
	}
	if err := s.Identity.RequireRecentStepUp(ctx, 5*time.Minute); err != nil {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "recent_step_up_required")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	authorization, err := s.Identity.AuthorizeFresh(ctx, actor.ID, identity.PermissionReadRecoveryKeys)
	if err != nil {
		return nil, core.ExecutionError(err)
	}
	deviceID, _ := uuid.Parse(req.Msg.GetDeviceId())
	if err := s.RequireRevealApproval(ctx, authorization.Principal(), identity.PermissionReadRecoveryKeys, deviceID, req.Msg.GetApprovalId()); err != nil {
		return nil, err
	}
	consumption, err := s.PrepareActionApproval(ctx, actor, identity.PermissionReadRecoveryKeys, req.Msg.GetApprovalId(), req.Msg)
	if err != nil {
		return nil, err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.LockActionApproval(ctx, tx, consumption, authorization, identity.PermissionReadRecoveryKeys); err != nil {
		return nil, core.ApprovalError(err)
	}
	id, _ := uuid.Parse(req.Msg.GetActionId())
	q := devicedb.New(tx)
	if _, err := core.LockDeviceScope(ctx, q, authorization.Principal(), identity.PermissionReadRecoveryKeys, deviceID); err != nil {
		return nil, core.MapErr(err)
	}
	action, err := q.GetDeviceAction(ctx, id)
	if err != nil {
		return nil, core.MapErr(core.NotFoundIfMissing(err))
	}
	if action.DeviceID != deviceID || action.Capability != "device.escrow-rotate.v1" {
		return nil, core.MapErr(core.ErrNotFound)
	}
	stored, err := q.GetDeviceActionEscrow(ctx, id)
	if err != nil {
		return nil, core.MapErr(core.NotFoundIfMissing(err))
	}
	// Audit admission commits before plaintext is released, including every replay.
	if err := core.DispatchAudit(ctx, q, &actor.ID, auditkind.RecoveryKeyReveal, id, req.Msg.GetReason()); err != nil {
		return nil, core.MapErr(err)
	}
	if err := s.LockActionApproval(ctx, tx, consumption, authorization, identity.PermissionReadRecoveryKeys); err != nil {
		return nil, core.ApprovalError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	secret, err := s.Escrow.Reveal(stored.BindingDocument, &escrow.Record{KeyID: stored.KeyID, WrappedKey: stored.WrappedKey, Ciphertext: stored.Ciphertext, SecretSHA256: stored.SecretSha256})
	if err != nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "escrow_custody_rejected")
	}
	return core.NoStore(&adminv1.RevealRecoveryKeyResponse{RecoveryKey: secret}), nil
}
