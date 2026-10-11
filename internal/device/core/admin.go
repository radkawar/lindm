package core

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

func DeviceState(state string) (adminv1.DeviceState, error) {
	switch state {
	case StatePending:
		return adminv1.DeviceState_DEVICE_STATE_PENDING, nil
	case StateActive:
		return adminv1.DeviceState_DEVICE_STATE_ACTIVE, nil
	case StateRevoked:
		return adminv1.DeviceState_DEVICE_STATE_REVOKED, nil
	case StateRecoveryHold:
		return adminv1.DeviceState_DEVICE_STATE_RECOVERY_HOLD, nil
	default:
		return adminv1.DeviceState_DEVICE_STATE_UNSPECIFIED, ErrInternalState
	}
}

func (s *Service) CreateEnrollmentGrant(ctx context.Context, req *connect.Request[adminv1.CreateEnrollmentGrantRequest]) (*connect.Response[adminv1.CreateEnrollmentGrantResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	actor, err := s.RequireUnrestricted(ctx, identity.PermissionManageEnrollment)
	if err != nil {
		return nil, err
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
	if req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, Invalid("invalid_text")
	}
	requestID, err := ParseUUID(req.Msg.GetRequestId())
	if err != nil {
		return nil, Invalid("invalid_id")
	}
	digest := MutationDigest(methodCreateGrant, strconv.FormatUint(uint64(req.Msg.GetLifetimeSeconds()), 10), req.Msg.GetReason())
	if req.Msg.GetName() != "" {
		digest = MutationDigest(methodCreateGrant, strconv.FormatUint(uint64(req.Msg.GetLifetimeSeconds()), 10), req.Msg.GetReason(), req.Msg.GetName())
	}
	var (
		secret    string
		grantID   uuid.UUID
		expiresAt time.Time
		unknown   bool
	)
	err = s.WithinUnrestrictedAuthorization(ctx, actor, identity.PermissionManageEnrollment, func(ctx context.Context, q *devicedb.Queries) error {
		row, owned, err := s.BeginAdminRequest(ctx, q, actor.ID, methodCreateGrant, requestID, digest)
		if err != nil {
			return err
		}
		if !owned {
			expires, ok := FiniteTime(row.ExpiresAt)
			if !ok || row.GrantID == uuid.Nil {
				return ErrInternalState
			}
			grantID = row.GrantID
			expiresAt = expires
			unknown = true
			return nil
		}
		now := s.Now()
		issuedSecret, hash, genErr := NewGrantSecret()
		if genErr != nil {
			return genErr
		}
		secret = issuedSecret
		grantID = uuid.New()
		expiresAt = now.Add(time.Duration(req.Msg.GetLifetimeSeconds()) * time.Second)
		if err := q.InsertEnrollmentGrant(ctx, devicedb.InsertEnrollmentGrantParams{
			ID:        grantID,
			TokenHash: hash,
			CreatedBy: actor.ID,
			CreatedAt: Timestamptz(now),
			ExpiresAt: Timestamptz(expiresAt),
			Reason:    req.Msg.GetReason(),
			Name:      req.Msg.GetName(),
		}); err != nil {
			return err
		}
		if err := InsertAudit(ctx, q, &actor.ID, actionGrantCreate, grantID.String(), req.Msg.GetReason()); err != nil {
			return err
		}
		return CompleteAdmin(ctx, q, actor.ID, methodCreateGrant, requestID, grantID, uuid.Nil, expiresAt)
	})
	if err != nil {
		return nil, MapErr(err)
	}
	resp := &adminv1.CreateEnrollmentGrantResponse{
		GrantId:               grantID.String(),
		ExpiresAt:             timestamppb.New(expiresAt),
		SecretDeliveryUnknown: unknown,
	}
	if !unknown {
		resp.Secret = secret
	}
	return NoStore(resp), nil
}

func (s *Service) RevokeEnrollmentGrant(ctx context.Context, req *connect.Request[adminv1.RevokeEnrollmentGrantRequest]) (*connect.Response[adminv1.RevokeEnrollmentGrantResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	actor, err := s.RequireUnrestricted(ctx, identity.PermissionManageEnrollment)
	if err != nil {
		return nil, err
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
	if req.Msg == nil || HasNUL(req.Msg.GetReason()) {
		return nil, Invalid("invalid_text")
	}
	requestID, err := ParseUUID(req.Msg.GetRequestId())
	if err != nil {
		return nil, Invalid("invalid_id")
	}
	grantID, err := ParseUUID(req.Msg.GetGrantId())
	if err != nil {
		return nil, Invalid("invalid_id")
	}
	digest := MutationDigest(methodRevokeGrant, grantID.String(), req.Msg.GetReason())
	err = s.WithinUnrestrictedAuthorization(ctx, actor, identity.PermissionManageEnrollment, func(ctx context.Context, q *devicedb.Queries) error {
		_, owned, err := s.BeginAdminRequest(ctx, q, actor.ID, methodRevokeGrant, requestID, digest)
		if err != nil {
			return err
		}
		if !owned {
			return nil
		}
		now := s.Now()
		grant, err := q.GetGrantForUpdate(ctx, grantID)
		if err != nil {
			return NotFoundIfMissing(err)
		}
		deviceID := uuid.Nil
		if grant.DeviceID != nil {
			deviceID = *grant.DeviceID
		}
		if !grant.RevokedAt.Valid {
			revoked, err := q.RevokeEnrollmentGrant(ctx, devicedb.RevokeEnrollmentGrantParams{
				RevokedAt:    Timestamptz(now),
				RevokedBy:    &actor.ID,
				RevokeReason: req.Msg.GetReason(),
				ID:           grantID,
			})
			if err != nil {
				return err
			}
			if revoked != 1 {
				return ErrInternalState
			}
			if err := InsertAudit(ctx, q, &actor.ID, actionGrantRevoke, grantID.String(), req.Msg.GetReason()); err != nil {
				return err
			}
		}
		if deviceID != uuid.Nil {
			row, err := q.GetDeviceForUpdate(ctx, deviceID)
			if err != nil {
				return err
			}
			if row.State == StatePending {
				if _, err := s.revokeLockedDevice(ctx, q, deviceID, actor.ID, req.Msg.GetReason(), now); err != nil {
					return err
				}
			}
		}
		return CompleteAdmin(ctx, q, actor.ID, methodRevokeGrant, requestID, grantID, deviceID, time.Unix(0, 0).UTC())
	})
	if err != nil {
		return nil, MapErr(err)
	}
	return connect.NewResponse(&adminv1.RevokeEnrollmentGrantResponse{}), nil
}

func (s *Service) RevokeDevice(ctx context.Context, req *connect.Request[adminv1.RevokeDeviceRequest]) (*connect.Response[adminv1.RevokeDeviceResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionRevokeDevice)
	if err != nil {
		return nil, err
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
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
	digest := MutationDigest(methodRevokeDevice, deviceID.String(), req.Msg.GetReason())
	prepared, err := s.prepareRevokeApproval(ctx, actor, req.Msg)
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
	_, owned, err := s.BeginAdminRequest(ctx, q, actor.ID, methodRevokeDevice, requestID, digest)
	if err != nil {
		return nil, MapErr(err)
	}
	if owned {
		if _, err := s.revokeLockedDevice(ctx, q, deviceID, actor.ID, req.Msg.GetReason(), s.Now()); err != nil {
			return nil, MapErr(err)
		}
		if err := CompleteAdmin(ctx, q, actor.ID, methodRevokeDevice, requestID, uuid.Nil, deviceID, time.Unix(0, 0).UTC()); err != nil {
			return nil, MapErr(err)
		}
	}
	if err := s.Identity.LockAndConsumeApproval(ctx, tx, prepared, s.ApprovalScope); err != nil {
		return nil, ApprovalError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, MapErr(err)
	}
	return connect.NewResponse(&adminv1.RevokeDeviceResponse{}), nil
}

func (s *Service) ListAuditEvents(ctx context.Context, req *connect.Request[adminv1.ListAuditEventsRequest]) (*connect.Response[adminv1.ListAuditEventsResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	if _, err := s.RequireUnrestricted(ctx, identity.PermissionReadAudit); err != nil {
		return nil, err
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
	if req.Msg == nil {
		return nil, Invalid("invalid_argument")
	}
	limit := PageLimit(req.Msg.GetPageSize())
	q := devicedb.New(s.Pool)
	params := devicedb.ListAuditEventsParams{RowLimit: limit + 1}
	if req.Msg.GetPageToken() != "" {
		var when time.Time
		var id uuid.UUID
		var err error
		when, id, err = DecodeCursor(req.Msg.GetPageToken())
		if err != nil {
			return nil, MapErr(err)
		}
		params.CursorOccurredAt = Timestamptz(when)
		params.CursorID = &id
	}
	rows, err := q.ListAuditEvents(ctx, params)
	if err != nil {
		return nil, MapErr(err)
	}
	next := ""
	if int32(len(rows)) > limit {
		occurred, ok := FiniteTime(rows[limit-1].OccurredAt)
		if !ok {
			return nil, ErrInternalState
		}
		token, err := EncodeCursor(occurred, rows[limit-1].ID)
		if err != nil {
			return nil, MapErr(err)
		}
		next = token
		rows = rows[:limit]
	}
	events := make([]*adminv1.AuditEvent, 0, len(rows))
	for _, row := range rows {
		occurred, ok := FiniteTime(row.OccurredAt)
		if !ok {
			return nil, ErrInternalState
		}
		var details map[string]string
		if err := json.Unmarshal(row.Details, &details); err != nil {
			return nil, ErrInternalState
		}
		var targetDeviceID *string
		if row.TargetDeviceID != nil {
			targetDeviceID = new(row.TargetDeviceID.String())
		}
		events = append(events, &adminv1.AuditEvent{
			Id:             row.ID.String(),
			OccurredAt:     timestamppb.New(occurred),
			ActorId:        GenerationString(row.ActorID),
			Action:         row.Action,
			ResourceId:     row.ResourceID,
			Reason:         row.Reason,
			TargetDeviceId: targetDeviceID,
			DeviceHostname: row.DeviceHostname,
			Details:        details,
		})
	}
	return connect.NewResponse(&adminv1.ListAuditEventsResponse{Events: events, NextPageToken: next}), nil
}

func GenerationString(id *uuid.UUID) string {
	if id == nil || *id == uuid.Nil {
		return ""
	}
	return id.String()
}
