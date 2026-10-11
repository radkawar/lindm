package device

import (
	"bytes"
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/assistrelay"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

// assistanceTx runs fn in a read-committed transaction. Deadline enforcement
// inside fn commits even when fn returns a domain error, so a lazily observed
// end is durable; errors from the database itself roll back. Relay
// revocations are applied only after commit.
func (s *Service) assistanceTx(ctx context.Context, authorization *identity.Authorization, permission identity.Permission, fn func(*devicedb.Queries, *assistanceRevocations) error) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if authorization != nil {
		if err := s.identity.LockAuthorization(ctx, tx, authorization, permission); err != nil {
			return executionError(err)
		}
	}
	var revoked assistanceRevocations
	result := fn(devicedb.New(tx), &revoked)
	var domain *connect.Error
	if result != nil && !errors.As(result, &domain) {
		return mapErr(result)
	}
	if result == nil && authorization != nil {
		if err := s.identity.LockAuthorization(ctx, tx, authorization, permission); err != nil {
			return executionError(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return mapErr(err)
	}
	s.revokeAssistance(revoked)
	return result
}

// authorizeAssistance applies the CreateDeviceAction admission pattern: cached
// grant at entry, configured service, bounded slots, then fresh authority.
func (s *Service) authorizeAssistance(ctx context.Context) (identity.Principal, *identity.Authorization, func(), error) {
	actor, err := s.require(ctx, identity.PermissionRunRemoteAssistance)
	if err != nil {
		return identity.Principal{}, nil, nil, err
	}
	if s.assistance == nil {
		return identity.Principal{}, nil, nil, rpcreason.Error(connect.CodeFailedPrecondition, "assistance_unconfigured")
	}
	if s.identity == nil {
		return identity.Principal{}, nil, nil, rpcreason.Error(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	if err := s.acquire(ctx); err != nil {
		return identity.Principal{}, nil, nil, mapErr(err)
	}
	authorization, err := s.identity.AuthorizeFresh(ctx, actor.ID, identity.PermissionRunRemoteAssistance)
	if err != nil {
		s.release()
		return identity.Principal{}, nil, nil, executionError(err)
	}
	return actor, authorization, s.release, nil
}

func (s *Service) CreateAssistanceSession(ctx context.Context, req *connect.Request[adminv1.CreateAssistanceSessionRequest]) (*connect.Response[adminv1.CreateAssistanceSessionResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	if _, err := s.require(ctx, identity.PermissionRunRemoteAssistance); err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil || hasNUL(req.Msg.GetReason()) {
		return nil, invalid("invalid_assistance_session")
	}
	actor, authorization, release, err := s.authorizeAssistance(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	digest, err := actionDigest(req.Msg)
	if err != nil {
		return nil, mapErr(err)
	}
	deviceID, _ := uuid.Parse(req.Msg.GetDeviceId())
	requestID, _ := uuid.Parse(req.Msg.GetRequestId())
	duration := assistanceDefaultDuration
	if seconds := req.Msg.GetMaxDurationSeconds(); seconds != 0 {
		duration = time.Duration(seconds) * time.Second
	}
	display := actor.DisplayName
	if display == "" {
		display = actor.Subject
	}
	if display == "" {
		display = actor.ID.String()
	}
	if runes := []rune(display); len(runes) > 256 {
		display = string(runes[:256])
	}
	var session *adminv1.AssistanceSession
	err = s.assistanceTx(ctx, authorization, identity.PermissionRunRemoteAssistance, func(q *devicedb.Queries, revoked *assistanceRevocations) error {
		device, err := lockDeviceScope(ctx, q, authorization.Principal(), identity.PermissionRunRemoteAssistance, deviceID)
		if err != nil {
			return mapErr(err)
		}
		now := s.now()
		old, err := q.GetAssistanceSessionByRequest(ctx, requestID)
		if err == nil {
			if old.OperatorID != actor.ID || !bytes.Equal(old.RequestDigest, digest) {
				return errIdempotencyConflict
			}
			if err := enforceAssistance(ctx, q, &old, now, revoked); err != nil {
				return err
			}
			session = assistanceMessage(old)
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if device.State != stateActive || device.CurrentGenerationID == nil || !device.LastSeenAt.Valid || now.Sub(device.LastSeenAt.Time) > assistanceOnlineWindow {
			return rpcreason.Error(connect.CodeFailedPrecondition, "device_offline")
		}
		if err := enforceOpenAssistance(ctx, q, deviceID, now, revoked); err != nil {
			return err
		}
		if _, err := q.LockOpenAssistanceSession(ctx, deviceID); err == nil {
			return rpcreason.Error(connect.CodeFailedPrecondition, "assistance_busy")
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err := q.LockAssistanceAdmission(ctx); err != nil {
			return err
		}
		live, err := q.CountLiveAssistanceSessions(ctx, devicedb.CountLiveAssistanceSessionsParams{Now: timestamptz(now), UnreachableBefore: timestamptz(now.Add(-assistanceUnreachable))})
		if err != nil {
			return err
		}
		if live >= int64(s.assistance.MaxSessions()) {
			return rpcreason.Error(connect.CodeFailedPrecondition, "assistance_capacity")
		}
		id := uuid.New()
		if err := q.InsertAssistanceSession(ctx, devicedb.InsertAssistanceSessionParams{
			ID: id, DeviceID: deviceID, GenerationID: *device.CurrentGenerationID, RequestID: requestID, RequestDigest: digest,
			OperatorID: actor.ID, OperatorDisplay: display, Mode: int16(req.Msg.GetMode()), Reason: req.Msg.GetReason(),
			TargetUsername: req.Msg.GetTargetUsername(), CreatedAt: timestamptz(now),
			ConsentDeadline: timestamptz(now.Add(assistanceConsentWindow)), EndsAt: timestamptz(now.Add(duration)),
		}); err != nil {
			return err
		}
		row, err := q.GetAssistanceSession(ctx, id)
		if err != nil {
			return err
		}
		if err := recordAssistanceAudit(ctx, q, &actor.ID, "assistance.request", row, req.Msg.GetReason(), "target", req.Msg.GetTargetUsername()); err != nil {
			return err
		}
		session = assistanceMessage(row)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return noStore(&adminv1.CreateAssistanceSessionResponse{Session: session}), nil
}

func (s *Service) ListAssistanceSessions(ctx context.Context, req *connect.Request[adminv1.ListAssistanceSessionsRequest]) (*connect.Response[adminv1.ListAssistanceSessionsResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_assistance_sessions")
	}
	deviceID, _ := uuid.Parse(req.Msg.GetDeviceId())
	params := devicedb.ListAssistanceSessionsParams{DeviceID: deviceID, PageLimit: pageLimit(req.Msg.GetPageSize()) + 1, CursorTime: timestamptz(time.Unix(0, 0))}
	if req.Msg.GetPageToken() != "" {
		stamp, cursor, err := decodeCursor(req.Msg.GetPageToken())
		if err != nil {
			return nil, err
		}
		params.HasCursor, params.CursorTime, params.CursorID = true, timestamptz(stamp), cursor
	}
	response := &adminv1.ListAssistanceSessionsResponse{}
	err = s.assistanceTx(ctx, nil, "", func(q *devicedb.Queries, revoked *assistanceRevocations) error {
		if err := requireDeviceScope(ctx, q, actor, identity.PermissionReadFleet, deviceID); err != nil {
			return mapErr(err)
		}
		if err := enforceOpenAssistance(ctx, q, deviceID, s.now(), revoked); err != nil {
			return err
		}
		rows, err := q.ListAssistanceSessions(ctx, params)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if len(response.Sessions) == int(params.PageLimit)-1 {
				last := rows[len(response.Sessions)-1]
				token, err := encodeCursor(last.CreatedAt.Time, last.ID)
				if err != nil {
					return err
				}
				response.NextPageToken = token
				break
			}
			response.Sessions = append(response.Sessions, assistanceMessage(row))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return noStore(response), nil
}

func (s *Service) GetAssistanceSession(ctx context.Context, req *connect.Request[adminv1.GetAssistanceSessionRequest]) (*connect.Response[adminv1.GetAssistanceSessionResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_assistance_session")
	}
	id, _ := uuid.Parse(req.Msg.GetSessionId())
	var session *adminv1.AssistanceSession
	err = s.assistanceTx(ctx, nil, "", func(q *devicedb.Queries, revoked *assistanceRevocations) error {
		row, err := s.lockAssistanceInScope(ctx, q, actor, identity.PermissionReadFleet, id, false)
		if err != nil {
			return err
		}
		if err := enforceAssistance(ctx, q, &row, s.now(), revoked); err != nil {
			return err
		}
		session = assistanceMessage(row)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return noStore(&adminv1.GetAssistanceSessionResponse{Session: session}), nil
}

// lockAssistanceInScope keeps the device-before-session lock order shared with
// Create and SyncAssistance. Out-of-scope and absent sessions are both NotFound.
func (s *Service) lockAssistanceInScope(ctx context.Context, q *devicedb.Queries, principal identity.Principal, permission identity.Permission, id uuid.UUID, lockDevice bool) (devicedb.AssistanceSession, error) {
	found, err := q.GetAssistanceSession(ctx, id)
	if err != nil {
		return devicedb.AssistanceSession{}, mapErr(notFoundIfMissing(err))
	}
	if lockDevice {
		_, err = lockDeviceScope(ctx, q, principal, permission, found.DeviceID)
	} else {
		err = requireDeviceScope(ctx, q, principal, permission, found.DeviceID)
	}
	if err != nil {
		return devicedb.AssistanceSession{}, mapErr(err)
	}
	row, err := q.LockAssistanceSession(ctx, id)
	if err != nil {
		return devicedb.AssistanceSession{}, err
	}
	return row, nil
}

// creatorOffered admits only the creating operator while the session is OFFERED.
func creatorOffered(row devicedb.AssistanceSession, actor identity.Principal) error {
	if row.OperatorID != actor.ID {
		return rpcreason.Error(connect.CodePermissionDenied, "assistance_not_creator")
	}
	switch row.State {
	case assistanceOffered:
		return nil
	case assistanceEnded:
		return rpcreason.Error(connect.CodeFailedPrecondition, "assistance_ended")
	default:
		return rpcreason.Error(connect.CodeFailedPrecondition, "assistance_state")
	}
}

func (s *Service) JoinAssistanceSession(ctx context.Context, req *connect.Request[adminv1.JoinAssistanceSessionRequest]) (*connect.Response[adminv1.JoinAssistanceSessionResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	if _, err := s.require(ctx, identity.PermissionRunRemoteAssistance); err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_assistance_join")
	}
	actor, authorization, release, err := s.authorizeAssistance(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	id, _ := uuid.Parse(req.Msg.GetSessionId())
	response := &adminv1.JoinAssistanceSessionResponse{}
	err = s.assistanceTx(ctx, authorization, identity.PermissionRunRemoteAssistance, func(q *devicedb.Queries, revoked *assistanceRevocations) error {
		row, err := s.lockAssistanceInScope(ctx, q, authorization.Principal(), identity.PermissionRunRemoteAssistance, id, true)
		if err != nil {
			return err
		}
		if err := enforceAssistance(ctx, q, &row, s.now(), revoked); err != nil {
			return err
		}
		if err := creatorOffered(row, actor); err != nil {
			return err
		}
		ice, err := s.assistance.ICEServer(row.ID, assistrelay.RoleConsole, row.EndsAt.Time)
		if err != nil {
			return err
		}
		if err := recordAssistanceAudit(ctx, q, &actor.ID, "assistance.join", row, "", "offer", row.OfferFingerprint); err != nil {
			return err
		}
		response.Session, response.OfferSdp, response.IceServers = assistanceMessage(row), row.OfferSdp, []*agentv1.AssistanceIceServer{ice}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return noStore(response), nil
}

func (s *Service) AnswerAssistanceSession(ctx context.Context, req *connect.Request[adminv1.AnswerAssistanceSessionRequest]) (*connect.Response[adminv1.AnswerAssistanceSessionResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	if _, err := s.require(ctx, identity.PermissionRunRemoteAssistance); err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil || hasNUL(req.Msg.GetAnswerSdp()) {
		return nil, invalid("invalid_assistance_answer")
	}
	actor, authorization, release, err := s.authorizeAssistance(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	fingerprint, err := assistanceSDP(req.Msg.GetAnswerSdp(), s.assistance.RelayAddress())
	if errors.Is(err, errAssistanceNonRelay) {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, err.Error())
	}
	if err != nil {
		return nil, invalid(err.Error())
	}
	id, _ := uuid.Parse(req.Msg.GetSessionId())
	var session *adminv1.AssistanceSession
	err = s.assistanceTx(ctx, authorization, identity.PermissionRunRemoteAssistance, func(q *devicedb.Queries, revoked *assistanceRevocations) error {
		row, err := s.lockAssistanceInScope(ctx, q, authorization.Principal(), identity.PermissionRunRemoteAssistance, id, true)
		if err != nil {
			return err
		}
		now := s.now()
		if err := enforceAssistance(ctx, q, &row, now, revoked); err != nil {
			return err
		}
		if err := creatorOffered(row, actor); err != nil {
			return err
		}
		if fingerprint == row.OfferFingerprint {
			return invalid("assistance_fingerprint")
		}
		if err := q.AnswerAssistanceSession(ctx, devicedb.AnswerAssistanceSessionParams{ID: row.ID, AnsweredAt: timestamptz(now), AnswerSdp: req.Msg.GetAnswerSdp(), AnswerFingerprint: fingerprint}); err != nil {
			return err
		}
		if err := recordAssistanceAudit(ctx, q, &actor.ID, "assistance.answer", row, "", "offer", row.OfferFingerprint, "answer", fingerprint); err != nil {
			return err
		}
		row, err = q.GetAssistanceSession(ctx, row.ID)
		if err != nil {
			return err
		}
		session = assistanceMessage(row)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return noStore(&adminv1.AnswerAssistanceSessionResponse{Session: session}), nil
}

// StopAssistanceSession is de-escalation: any operator holding the grant in
// scope may stop, without a fresh directory round trip that could block it.
func (s *Service) StopAssistanceSession(ctx context.Context, req *connect.Request[adminv1.StopAssistanceSessionRequest]) (*connect.Response[adminv1.StopAssistanceSessionResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.require(ctx, identity.PermissionRunRemoteAssistance)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_assistance_stop")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	id, _ := uuid.Parse(req.Msg.GetSessionId())
	var session *adminv1.AssistanceSession
	err = s.assistanceTx(ctx, nil, "", func(q *devicedb.Queries, revoked *assistanceRevocations) error {
		row, err := s.lockAssistanceInScope(ctx, q, actor, identity.PermissionRunRemoteAssistance, id, true)
		if err != nil {
			return err
		}
		now := s.now()
		if err := enforceAssistance(ctx, q, &row, now, revoked); err != nil {
			return err
		}
		if row.State != assistanceEnded {
			if err := recordAssistanceAudit(ctx, q, &actor.ID, "assistance.stop", row, ""); err != nil {
				return err
			}
			if err := endAssistance(ctx, q, &row, now, &actor.ID, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED, "", false, revoked); err != nil {
				return err
			}
		}
		session = assistanceMessage(row)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return noStore(&adminv1.StopAssistanceSessionResponse{Session: session}), nil
}
