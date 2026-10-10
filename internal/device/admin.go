package device

import (
	"context"
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

func deviceState(state string) (adminv1.DeviceState, error) {
	switch state {
	case statePending:
		return adminv1.DeviceState_DEVICE_STATE_PENDING, nil
	case stateActive:
		return adminv1.DeviceState_DEVICE_STATE_ACTIVE, nil
	case stateRevoked:
		return adminv1.DeviceState_DEVICE_STATE_REVOKED, nil
	case stateRecoveryHold:
		return adminv1.DeviceState_DEVICE_STATE_RECOVERY_HOLD, nil
	default:
		return adminv1.DeviceState_DEVICE_STATE_UNSPECIFIED, errInternalState
	}
}

func (s *Service) CreateEnrollmentGrant(ctx context.Context, req *connect.Request[adminv1.CreateEnrollmentGrantRequest]) (*connect.Response[adminv1.CreateEnrollmentGrantResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.requireUnrestricted(ctx, identity.PermissionManageEnrollment)
	if err != nil {
		return nil, err
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	if req.Msg == nil || hasNUL(req.Msg.GetReason()) {
		return nil, invalid("invalid_text")
	}
	requestID, err := parseUUID(req.Msg.GetRequestId())
	if err != nil {
		return nil, invalid("invalid_id")
	}
	digest := mutationDigest(methodCreateGrant, strconv.FormatUint(uint64(req.Msg.GetLifetimeSeconds()), 10), req.Msg.GetReason())
	var (
		secret    string
		grantID   uuid.UUID
		expiresAt time.Time
		unknown   bool
	)
	err = s.withinUnrestrictedAuthorization(ctx, actor, identity.PermissionManageEnrollment, func(ctx context.Context, q *devicedb.Queries) error {
		row, owned, err := s.beginAdminRequest(ctx, q, actor.ID, methodCreateGrant, requestID, digest)
		if err != nil {
			return err
		}
		if !owned {
			expires, ok := finiteTime(row.ExpiresAt)
			if !ok || row.GrantID == uuid.Nil {
				return errInternalState
			}
			grantID = row.GrantID
			expiresAt = expires
			unknown = true
			return nil
		}
		now := s.now()
		issuedSecret, hash, genErr := newGrantSecret()
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
			CreatedAt: timestamptz(now),
			ExpiresAt: timestamptz(expiresAt),
			Reason:    req.Msg.GetReason(),
		}); err != nil {
			return err
		}
		if err := insertAudit(ctx, q, &actor.ID, actionGrantCreate, grantID.String(), req.Msg.GetReason()); err != nil {
			return err
		}
		return completeAdmin(ctx, q, actor.ID, methodCreateGrant, requestID, grantID, uuid.Nil, expiresAt)
	})
	if err != nil {
		return nil, mapErr(err)
	}
	resp := &adminv1.CreateEnrollmentGrantResponse{
		GrantId:               grantID.String(),
		ExpiresAt:             timestamppb.New(expiresAt),
		SecretDeliveryUnknown: unknown,
	}
	if !unknown {
		resp.Secret = secret
	}
	return noStore(resp), nil
}

func (s *Service) RevokeEnrollmentGrant(ctx context.Context, req *connect.Request[adminv1.RevokeEnrollmentGrantRequest]) (*connect.Response[adminv1.RevokeEnrollmentGrantResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.requireUnrestricted(ctx, identity.PermissionManageEnrollment)
	if err != nil {
		return nil, err
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	if req.Msg == nil || hasNUL(req.Msg.GetReason()) {
		return nil, invalid("invalid_text")
	}
	requestID, err := parseUUID(req.Msg.GetRequestId())
	if err != nil {
		return nil, invalid("invalid_id")
	}
	grantID, err := parseUUID(req.Msg.GetGrantId())
	if err != nil {
		return nil, invalid("invalid_id")
	}
	digest := mutationDigest(methodRevokeGrant, grantID.String(), req.Msg.GetReason())
	err = s.withinUnrestrictedAuthorization(ctx, actor, identity.PermissionManageEnrollment, func(ctx context.Context, q *devicedb.Queries) error {
		_, owned, err := s.beginAdminRequest(ctx, q, actor.ID, methodRevokeGrant, requestID, digest)
		if err != nil {
			return err
		}
		if !owned {
			return nil
		}
		now := s.now()
		grant, err := q.GetGrantForUpdate(ctx, grantID)
		if err != nil {
			return notFoundIfMissing(err)
		}
		deviceID := uuid.Nil
		if grant.DeviceID != nil {
			deviceID = *grant.DeviceID
		}
		if !grant.RevokedAt.Valid {
			revoked, err := q.RevokeEnrollmentGrant(ctx, devicedb.RevokeEnrollmentGrantParams{
				RevokedAt:    timestamptz(now),
				RevokedBy:    &actor.ID,
				RevokeReason: req.Msg.GetReason(),
				ID:           grantID,
			})
			if err != nil {
				return err
			}
			if revoked != 1 {
				return errInternalState
			}
			if err := insertAudit(ctx, q, &actor.ID, actionGrantRevoke, grantID.String(), req.Msg.GetReason()); err != nil {
				return err
			}
		}
		if deviceID != uuid.Nil {
			row, err := q.GetDeviceForUpdate(ctx, deviceID)
			if err != nil {
				return err
			}
			if row.State == statePending {
				if _, err := s.revokeLockedDevice(ctx, q, deviceID, actor.ID, req.Msg.GetReason(), now); err != nil {
					return err
				}
			}
		}
		return completeAdmin(ctx, q, actor.ID, methodRevokeGrant, requestID, grantID, deviceID, time.Unix(0, 0).UTC())
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return connect.NewResponse(&adminv1.RevokeEnrollmentGrantResponse{}), nil
}

func (s *Service) RevokeDevice(ctx context.Context, req *connect.Request[adminv1.RevokeDeviceRequest]) (*connect.Response[adminv1.RevokeDeviceResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.require(ctx, identity.PermissionRevokeDevice)
	if err != nil {
		return nil, err
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	if req.Msg == nil || hasNUL(req.Msg.GetReason()) {
		return nil, invalid("invalid_text")
	}
	requestID, err := parseUUID(req.Msg.GetRequestId())
	if err != nil {
		return nil, invalid("invalid_id")
	}
	deviceID, err := parseUUID(req.Msg.GetDeviceId())
	if err != nil {
		return nil, invalid("invalid_id")
	}
	digest := mutationDigest(methodRevokeDevice, deviceID.String(), req.Msg.GetReason())
	prepared, err := s.prepareRevokeApproval(ctx, actor, req.Msg)
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.identity.LockAndConsumeApproval(ctx, tx, prepared, s.approvalScope); err != nil {
		return nil, approvalError(err)
	}
	q := devicedb.New(tx)
	_, owned, err := s.beginAdminRequest(ctx, q, actor.ID, methodRevokeDevice, requestID, digest)
	if err != nil {
		return nil, mapErr(err)
	}
	if owned {
		if _, err := s.revokeLockedDevice(ctx, q, deviceID, actor.ID, req.Msg.GetReason(), s.now()); err != nil {
			return nil, mapErr(err)
		}
		if err := completeAdmin(ctx, q, actor.ID, methodRevokeDevice, requestID, uuid.Nil, deviceID, time.Unix(0, 0).UTC()); err != nil {
			return nil, mapErr(err)
		}
	}
	if err := s.identity.LockAndConsumeApproval(ctx, tx, prepared, s.approvalScope); err != nil {
		return nil, approvalError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return connect.NewResponse(&adminv1.RevokeDeviceResponse{}), nil
}

func (s *Service) ListAuditEvents(ctx context.Context, req *connect.Request[adminv1.ListAuditEventsRequest]) (*connect.Response[adminv1.ListAuditEventsResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	if _, err := s.requireUnrestricted(ctx, identity.PermissionReadAudit); err != nil {
		return nil, err
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	if req.Msg == nil {
		return nil, invalid("invalid_argument")
	}
	limit := pageLimit(req.Msg.GetPageSize())
	q := devicedb.New(s.pool)
	var (
		rows []devicedb.AuditEvent
		err  error
	)
	if req.Msg.GetPageToken() == "" {
		rows, err = q.ListAuditEventsFirst(ctx, limit+1)
	} else {
		var when time.Time
		var id uuid.UUID
		when, id, err = decodeCursor(req.Msg.GetPageToken())
		if err != nil {
			return nil, mapErr(err)
		}
		rows, err = q.ListAuditEventsAfter(ctx, devicedb.ListAuditEventsAfterParams{
			CursorOccurredAt: timestamptz(when),
			CursorID:         id,
			RowLimit:         limit + 1,
		})
	}
	if err != nil {
		return nil, mapErr(err)
	}
	next := ""
	if int32(len(rows)) > limit {
		occurred, ok := finiteTime(rows[limit-1].OccurredAt)
		if !ok {
			return nil, errInternalState
		}
		token, err := encodeCursor(occurred, rows[limit-1].ID)
		if err != nil {
			return nil, mapErr(err)
		}
		next = token
		rows = rows[:limit]
	}
	events := make([]*adminv1.AuditEvent, 0, len(rows))
	for _, row := range rows {
		occurred, ok := finiteTime(row.OccurredAt)
		if !ok {
			return nil, errInternalState
		}
		events = append(events, &adminv1.AuditEvent{
			Id:         row.ID.String(),
			OccurredAt: timestamppb.New(occurred),
			ActorId:    generationString(row.ActorID),
			Action:     row.Action,
			ResourceId: row.ResourceID,
			Reason:     row.Reason,
		})
	}
	return connect.NewResponse(&adminv1.ListAuditEventsResponse{Events: events, NextPageToken: next}), nil
}

func generationString(id *uuid.UUID) string {
	if id == nil || *id == uuid.Nil {
		return ""
	}
	return id.String()
}
