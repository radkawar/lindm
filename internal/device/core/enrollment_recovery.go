package core

import (
	"context"
	"crypto"
	"strconv"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/auditkind"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

const methodCreateRecoveryGrant = "CreateRecoveryEnrollmentGrant"

func (s *Service) CreateRecoveryEnrollmentGrant(ctx context.Context, req *connect.Request[adminv1.CreateRecoveryEnrollmentGrantRequest]) (*connect.Response[adminv1.CreateRecoveryEnrollmentGrantResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionRevokeDevice)
	if err != nil {
		return nil, err
	}
	if req.Msg == nil || HasNUL(req.Msg.GetReason()) {
		return nil, Invalid("invalid_text")
	}
	requestID, err := ParseUUID(req.Msg.GetRequestId())
	if err != nil {
		return nil, Invalid("invalid_id")
	}
	deviceID, err := ParseUUID(req.Msg.GetDeviceId())
	if err != nil {
		return nil, Invalid("invalid_id")
	}
	generation, err := ParseUUID(req.Msg.GetExpectedGenerationId())
	if err != nil {
		return nil, Invalid("invalid_id")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
	prepared, err := s.PrepareActionApproval(ctx, actor, identity.PermissionRevokeDevice, req.Msg.GetApprovalId(), req.Msg)
	if err != nil {
		return nil, err
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.Identity.LockAndConsumeApproval(ctx, tx, prepared, s.ApprovalScope); err != nil {
		return nil, ApprovalError(err)
	}
	q := devicedb.New(tx)
	digest := MutationDigest(methodCreateRecoveryGrant, deviceID.String(), generation.String(), strconv.FormatBool(req.Msg.GetExpectedRevoked()), strconv.FormatUint(uint64(req.Msg.GetLifetimeSeconds()), 10), req.Msg.GetReason())
	prior, owned, err := s.BeginAdminRequest(ctx, q, actor.ID, methodCreateRecoveryGrant, requestID, digest)
	if err != nil {
		return nil, MapErr(err)
	}
	response := &adminv1.CreateRecoveryEnrollmentGrantResponse{}
	if !owned {
		expires, valid := FiniteTime(prior.ExpiresAt)
		if !valid || prior.GrantID == uuid.Nil || prior.DeviceID != deviceID {
			return nil, ErrInternalState
		}
		response.GrantId, response.ExpiresAt, response.SecretDeliveryUnknown = prior.GrantID.String(), timestamppb.New(expires), true
	} else {
		device, err := q.GetDeviceForUpdate(ctx, deviceID)
		if err != nil {
			return nil, MapErr(NotFoundIfMissing(err))
		}
		if device.CurrentGenerationID == nil || *device.CurrentGenerationID != generation {
			return nil, ErrGenerationMismatch
		}
		if (device.State == StateRevoked) != req.Msg.GetExpectedRevoked() {
			return nil, rpcreason.Error(connect.CodeFailedPrecondition, "recovery_state_changed")
		}
		secret, hash, err := NewGrantSecret()
		if err != nil {
			return nil, MapErr(err)
		}
		grantID, now := uuid.New(), s.Now()
		expires := now.Add(time.Duration(req.Msg.GetLifetimeSeconds()) * time.Second)
		if err := q.InsertEnrollmentGrant(ctx, devicedb.InsertEnrollmentGrantParams{ID: grantID, TokenHash: hash, CreatedBy: actor.ID, CreatedAt: Timestamptz(now), ExpiresAt: Timestamptz(expires), Reason: req.Msg.GetReason()}); err != nil {
			return nil, MapErr(err)
		}
		if err := q.InsertRecoveryEnrollmentGrant(ctx, devicedb.InsertRecoveryEnrollmentGrantParams{GrantID: grantID, DeviceID: deviceID, ExpectedGenerationID: generation, ExpectedRevokedAt: device.RevokedAt}); err != nil {
			return nil, MapErr(err)
		}
		if err := InsertAudit(ctx, q, &actor.ID, auditkind.DeviceRecoveryAuthorized, deviceID.String(), req.Msg.GetReason()); err != nil {
			return nil, MapErr(err)
		}
		if err := CompleteAdmin(ctx, q, actor.ID, methodCreateRecoveryGrant, requestID, grantID, deviceID, expires); err != nil {
			return nil, MapErr(err)
		}
		response.GrantId, response.Secret, response.ExpiresAt = grantID.String(), secret, timestamppb.New(expires)
	}
	if err := s.Identity.LockAndConsumeApproval(ctx, tx, prepared, s.ApprovalScope); err != nil {
		return nil, ApprovalError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, MapErr(err)
	}
	return NoStore(response), nil
}

// recoverEnrollment replaces authority only after a bound one-use grant is
// consumed by a newly generated device key. Inventory similarity is never read.
func (s *Service) recoverEnrollment(ctx context.Context, q *devicedb.Queries, grant devicedb.GetGrantByHashForUpdateRow, binding devicedb.GetRecoveryEnrollmentGrantRow, pub crypto.PublicKey, transactionID uuid.UUID, pubHash []byte) (*issuedCert, uuid.UUID, uuid.UUID, error) {
	device, err := q.GetDeviceForUpdate(ctx, binding.DeviceID)
	if err != nil {
		return nil, uuid.Nil, uuid.Nil, err
	}
	if device.CurrentGenerationID == nil || *device.CurrentGenerationID != binding.ExpectedGenerationID {
		return nil, uuid.Nil, uuid.Nil, ErrGenerationMismatch
	}
	if device.RevokedAt.Valid != binding.ExpectedRevokedAt.Valid || device.RevokedAt.Valid && !device.RevokedAt.Time.Equal(binding.ExpectedRevokedAt.Time) {
		return nil, uuid.Nil, uuid.Nil, rpcreason.Error(connect.CodeFailedPrecondition, "recovery_state_changed")
	}
	reused, err := q.RecoveryKeyAlreadyUsed(ctx, devicedb.RecoveryKeyAlreadyUsedParams{DeviceID: binding.DeviceID, PublicKeyFingerprint: pubHash})
	if err != nil {
		return nil, uuid.Nil, uuid.Nil, err
	}
	if reused {
		return nil, uuid.Nil, uuid.Nil, rpcreason.Error(connect.CodeFailedPrecondition, "recovery_key_reused")
	}
	now := s.Now()
	// Retire all old credentials and generations, including already-held ones.
	if err := q.RevokeDeviceCertificates(ctx, devicedb.RevokeDeviceCertificatesParams{DeviceID: binding.DeviceID, RevokedAt: Timestamptz(now), RevokeReason: grant.Reason}); err != nil {
		return nil, uuid.Nil, uuid.Nil, err
	}
	if err := q.RevokeGenerations(ctx, binding.DeviceID); err != nil {
		return nil, uuid.Nil, uuid.Nil, err
	}
	generation := uuid.New()
	if err := q.InsertEnrollmentGeneration(ctx, devicedb.InsertEnrollmentGenerationParams{ID: generation, DeviceID: binding.DeviceID, CreatedAt: Timestamptz(now)}); err != nil {
		return nil, uuid.Nil, uuid.Nil, err
	}
	if err := q.ResetDeviceForEnrollmentRecovery(ctx, devicedb.ResetDeviceForEnrollmentRecoveryParams{GenerationID: &generation, DeviceID: binding.DeviceID}); err != nil {
		return nil, uuid.Nil, uuid.Nil, err
	}
	issued, err := s.storeCertificate(ctx, q, binding.DeviceID, generation, pub, now)
	if err != nil {
		return nil, uuid.Nil, uuid.Nil, err
	}
	consumed, err := q.ConsumeEnrollmentGrant(ctx, devicedb.ConsumeEnrollmentGrantParams{ID: grant.ID, ConsumedAt: Timestamptz(now), DeviceID: &binding.DeviceID, TransactionID: &transactionID, PublicKeyFingerprint: pubHash, CertificateID: &issued.ID})
	if err != nil {
		return nil, uuid.Nil, uuid.Nil, err
	}
	if consumed != 1 {
		return nil, uuid.Nil, uuid.Nil, ErrInternalState
	}
	if err := InsertAudit(ctx, q, &grant.CreatedBy, auditkind.DeviceRecovered, binding.DeviceID.String(), grant.Reason); err != nil {
		return nil, uuid.Nil, uuid.Nil, err
	}
	return issued, binding.DeviceID, generation, nil
}
