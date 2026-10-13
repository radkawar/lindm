package assistance

import (
	"bytes"
	"context"
	"errors"
	"time"

	"lindm/internal/auditkind"
	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

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
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if authorization != nil {
		if err := s.Identity.LockAuthorization(ctx, tx, authorization, permission); err != nil {
			return core.ExecutionError(err)
		}
	}
	var revoked assistanceRevocations
	result := fn(devicedb.New(tx), &revoked)
	var domain *connect.Error
	if result != nil && !errors.As(result, &domain) {
		return core.MapErr(result)
	}
	if result == nil && authorization != nil {
		if err := s.Identity.LockAuthorization(ctx, tx, authorization, permission); err != nil {
			return core.ExecutionError(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return core.MapErr(err)
	}
	s.revokeAssistance(revoked)
	return result
}

// authorizeAssistance applies the CreateDeviceAction admission pattern: cached
// grant at entry, configured service, bounded slots, then fresh authority.
func (s *Service) authorizeAssistance(ctx context.Context) (identity.Principal, *identity.Authorization, func(), error) {
	actor, err := s.Require(ctx, identity.PermissionViewRemoteAssistance)
	if err != nil {
		return identity.Principal{}, nil, nil, err
	}
	if s.Assistance == nil {
		return identity.Principal{}, nil, nil, rpcreason.Error(connect.CodeFailedPrecondition, "assistance_unconfigured")
	}
	if s.Identity == nil {
		return identity.Principal{}, nil, nil, rpcreason.Error(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	if err := s.Acquire(ctx); err != nil {
		return identity.Principal{}, nil, nil, core.MapErr(err)
	}
	authorization, err := s.Identity.AuthorizeFresh(ctx, actor.ID, identity.PermissionViewRemoteAssistance)
	if err != nil {
		s.Release()
		return identity.Principal{}, nil, nil, core.ExecutionError(err)
	}
	return actor, authorization, s.Release, nil
}

func (s *Service) CreateAssistanceSession(ctx context.Context, req *connect.Request[adminv1.CreateAssistanceSessionRequest]) (*connect.Response[adminv1.CreateAssistanceSessionResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	if _, err := s.Require(ctx, identity.PermissionViewRemoteAssistance); err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil || core.HasNUL(req.Msg.GetReason()) {
		return nil, core.Invalid("invalid_assistance_session")
	}
	if req.Msg.GetMode() == agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL {
		if _, err := s.Require(ctx, identity.PermissionControlRemoteAssistance); err != nil {
			return nil, err
		}
	}
	actor, authorization, release, err := s.authorizeAssistance(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	digest, err := core.ActionDigest(req.Msg)
	if err != nil {
		return nil, core.MapErr(err)
	}
	deviceID, _ := uuid.Parse(req.Msg.GetDeviceId())
	requestID, _ := uuid.Parse(req.Msg.GetRequestId())
	duration := assistanceDefaultDuration
	if seconds := req.Msg.GetMaxDurationSeconds(); seconds != 0 {
		duration = time.Duration(seconds) * time.Second
	}
	display := assistanceOperatorLabel(actor)
	var session *adminv1.AssistanceSession
	err = s.assistanceTx(ctx, authorization, identity.PermissionViewRemoteAssistance, func(q *devicedb.Queries, revoked *assistanceRevocations) error {
		device, err := core.LockMutableDevice(ctx, q, authorization.Principal(), identity.PermissionViewRemoteAssistance, deviceID)
		if err != nil {
			return core.MapErr(err)
		}
		if err := scopeAssistanceCapabilities(ctx, q, authorization.Principal(), deviceID, req.Msg.GetMode(), req.Msg.GetRequestedCapabilities()); err != nil {
			return err
		}
		now := s.Now()
		old, err := q.GetAssistanceSessionByRequest(ctx, requestID)
		if err == nil {
			if old.OperatorID != actor.ID || !bytes.Equal(old.RequestDigest, digest) {
				return core.ErrIdempotencyConflict
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
		// Refusals the device reported in advance come before availability; none records a session.
		if err := refuseUnreachable(ctx, q, deviceID); err != nil {
			return err
		}
		if device.State != core.StateActive || device.CurrentGenerationID == nil || !device.LastSeenAt.Valid || now.Sub(device.LastSeenAt.Time) > assistanceOnlineWindow {
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
		live, err := q.CountLiveAssistanceSessions(ctx, devicedb.CountLiveAssistanceSessionsParams{Now: core.Timestamptz(now), UnreachableBefore: core.Timestamptz(now.Add(-assistanceUnreachable))})
		if err != nil {
			return err
		}
		if live >= int64(s.Assistance.MaxSessions()) {
			return rpcreason.Error(connect.CodeFailedPrecondition, "assistance_capacity")
		}
		id := uuid.New()
		policy, err := loadAssistancePolicy(ctx, q, deviceID)
		if err != nil {
			return err
		}
		requested, err := proto.Marshal(assistancePolicy(req.Msg.GetRequestedCapabilities()))
		if err != nil {
			return err
		}
		effective, err := proto.Marshal(intersectAssistancePolicy(req.Msg.GetRequestedCapabilities(), intersectAssistancePolicy(policy, s.AssistanceCeiling)))
		if err != nil {
			return err
		}
		if err := q.InsertAssistanceSession(ctx, devicedb.InsertAssistanceSessionParams{
			ID: id, DeviceID: deviceID, GenerationID: *device.CurrentGenerationID, RequestID: requestID, RequestDigest: digest,
			OperatorID: actor.ID, OperatorDisplay: display, Mode: int16(req.Msg.GetMode()), Reason: req.Msg.GetReason(),
			TargetUsername: req.Msg.GetTargetUsername(), CreatedAt: core.Timestamptz(now),
			ConsentDeadline: core.Timestamptz(now.Add(assistanceConsentWindow)), EndsAt: core.Timestamptz(now.Add(duration)),
		}); err != nil {
			return err
		}
		if err := q.SetAssistanceCapabilities(ctx, devicedb.SetAssistanceCapabilitiesParams{ID: id, RequestedCapabilities: requested, EffectiveCapabilities: effective}); err != nil {
			return err
		}
		if err := q.AuthorizeAssistanceSession(ctx, devicedb.AuthorizeAssistanceSessionParams{ID: id, AuthorizedUntil: core.Timestamptz(authorization.ExpiresAt())}); err != nil {
			return err
		}
		row, err := q.GetAssistanceSession(ctx, id)
		if err != nil {
			return err
		}
		if err := recordAssistanceAudit(ctx, q, &actor.ID, auditkind.AssistanceRequest, row, req.Msg.GetReason(), "target", req.Msg.GetTargetUsername()); err != nil {
			return err
		}
		session = assistanceMessage(row)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return core.NoStore(&adminv1.CreateAssistanceSessionResponse{Session: session}), nil
}

func assistanceOperatorLabel(actor identity.Principal) string {
	display := actor.DisplayName
	if display == "" {
		display = actor.Subject
	}
	if display == "" {
		return actor.ID.String()
	}
	count := 0
	for index := range display {
		if count == 256 {
			return display[:index]
		}
		count++
	}
	return display
}

func (s *Service) ListAssistanceSessions(ctx context.Context, req *connect.Request[adminv1.ListAssistanceSessionsRequest]) (*connect.Response[adminv1.ListAssistanceSessionsResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_assistance_sessions")
	}
	deviceID, _ := uuid.Parse(req.Msg.GetDeviceId())
	params := devicedb.ListAssistanceSessionsParams{DeviceID: deviceID, PageLimit: core.PageLimit(req.Msg.GetPageSize()) + 1, CursorTime: core.Timestamptz(time.Unix(0, 0))}
	if req.Msg.GetPageToken() != "" {
		stamp, cursor, err := core.DecodeCursor(req.Msg.GetPageToken())
		if err != nil {
			return nil, err
		}
		params.HasCursor, params.CursorTime, params.CursorID = true, core.Timestamptz(stamp), cursor
	}
	response := &adminv1.ListAssistanceSessionsResponse{}
	err = s.assistanceTx(ctx, nil, "", func(q *devicedb.Queries, revoked *assistanceRevocations) error {
		if err := core.RequireDeviceScope(ctx, q, actor, identity.PermissionReadFleet, deviceID); err != nil {
			return core.MapErr(err)
		}
		if err := enforceOpenAssistance(ctx, q, deviceID, s.Now(), revoked); err != nil {
			return err
		}
		rows, err := q.ListAssistanceSessions(ctx, params)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if len(response.Sessions) == int(params.PageLimit)-1 {
				last := rows[len(response.Sessions)-1]
				token, err := core.EncodeCursor(last.CreatedAt.Time, last.ID)
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
	return core.NoStore(response), nil
}

func (s *Service) GetAssistanceSession(ctx context.Context, req *connect.Request[adminv1.GetAssistanceSessionRequest]) (*connect.Response[adminv1.GetAssistanceSessionResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_assistance_session")
	}
	id, _ := uuid.Parse(req.Msg.GetSessionId())
	var session *adminv1.AssistanceSession
	err = s.assistanceTx(ctx, nil, "", func(q *devicedb.Queries, revoked *assistanceRevocations) error {
		row, err := s.lockAssistanceInScope(ctx, q, actor, identity.PermissionReadFleet, id, false)
		if err != nil {
			return err
		}
		if err := enforceAssistance(ctx, q, &row, s.Now(), revoked); err != nil {
			return err
		}
		session = assistanceMessage(row)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return core.NoStore(&adminv1.GetAssistanceSessionResponse{Session: session}), nil
}

// lockAssistanceInScope keeps the device-before-session lock order shared with
// Create and SyncAssistance. Out-of-scope and absent sessions are both NotFound.
func (s *Service) lockAssistanceInScope(ctx context.Context, q *devicedb.Queries, principal identity.Principal, permission identity.Permission, id uuid.UUID, lockDevice bool) (devicedb.AssistanceSession, error) {
	found, err := q.GetAssistanceSession(ctx, id)
	if err != nil {
		return devicedb.AssistanceSession{}, core.MapErr(core.NotFoundIfMissing(err))
	}
	if lockDevice {
		_, err = core.LockDeviceScope(ctx, q, principal, permission, found.DeviceID)
	} else {
		err = core.RequireDeviceScope(ctx, q, principal, permission, found.DeviceID)
	}
	if err != nil {
		return devicedb.AssistanceSession{}, core.MapErr(err)
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
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	if _, err := s.Require(ctx, identity.PermissionViewRemoteAssistance); err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_assistance_join")
	}
	actor, authorization, release, err := s.authorizeAssistance(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	id, _ := uuid.Parse(req.Msg.GetSessionId())
	response := &adminv1.JoinAssistanceSessionResponse{}
	err = s.assistanceTx(ctx, authorization, identity.PermissionViewRemoteAssistance, func(q *devicedb.Queries, revoked *assistanceRevocations) error {
		row, err := s.lockAssistanceInScope(ctx, q, authorization.Principal(), identity.PermissionViewRemoteAssistance, id, true)
		if err != nil {
			return err
		}
		if err := enforceAssistance(ctx, q, &row, s.Now(), revoked); err != nil {
			return err
		}
		if err := creatorOffered(row, actor); err != nil {
			return err
		}
		if err := scopeAssistanceCapabilities(ctx, q, authorization.Principal(), row.DeviceID, agentv1.AssistanceMode(row.Mode), decodeAssistancePolicy(row.EffectiveCapabilities)); err != nil {
			return err
		}
		if err := s.checkAssistancePolicy(ctx, q, row); err != nil {
			return err
		}
		ice, err := s.Assistance.ICEServer(row.ID, assistrelay.RoleConsole, row.EndsAt.Time)
		if err != nil {
			return err
		}
		if err := recordAssistanceAudit(ctx, q, &actor.ID, auditkind.AssistanceJoin, row, "", "offer", row.OfferFingerprint); err != nil {
			return err
		}
		response.Session, response.OfferSdp, response.IceServers = assistanceMessage(row), row.OfferSdp, []*agentv1.AssistanceIceServer{ice}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return core.NoStore(response), nil
}

func (s *Service) AnswerAssistanceSession(ctx context.Context, req *connect.Request[adminv1.AnswerAssistanceSessionRequest]) (*connect.Response[adminv1.AnswerAssistanceSessionResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	if _, err := s.Require(ctx, identity.PermissionViewRemoteAssistance); err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil || core.HasNUL(req.Msg.GetAnswerSdp()) {
		return nil, core.Invalid("invalid_assistance_answer")
	}
	actor, authorization, release, err := s.authorizeAssistance(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	fingerprint, err := AssistanceSDP(req.Msg.GetAnswerSdp(), s.Assistance.RelayAddress())
	if errors.Is(err, ErrAssistanceNonRelay) {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, err.Error())
	}
	if err != nil {
		return nil, core.Invalid(err.Error())
	}
	id, _ := uuid.Parse(req.Msg.GetSessionId())
	var session *adminv1.AssistanceSession
	err = s.assistanceTx(ctx, authorization, identity.PermissionViewRemoteAssistance, func(q *devicedb.Queries, revoked *assistanceRevocations) error {
		row, err := s.lockAssistanceInScope(ctx, q, authorization.Principal(), identity.PermissionViewRemoteAssistance, id, true)
		if err != nil {
			return err
		}
		now := s.Now()
		if err := enforceAssistance(ctx, q, &row, now, revoked); err != nil {
			return err
		}
		if err := creatorOffered(row, actor); err != nil {
			return err
		}
		if err := scopeAssistanceCapabilities(ctx, q, authorization.Principal(), row.DeviceID, agentv1.AssistanceMode(row.Mode), decodeAssistancePolicy(row.EffectiveCapabilities)); err != nil {
			return err
		}
		if err := s.checkAssistancePolicy(ctx, q, row); err != nil {
			return err
		}
		if fingerprint == row.OfferFingerprint {
			return core.Invalid("assistance_fingerprint")
		}
		if err := q.AnswerAssistanceSession(ctx, devicedb.AnswerAssistanceSessionParams{ID: row.ID, AnsweredAt: core.Timestamptz(now), AnswerSdp: req.Msg.GetAnswerSdp(), AnswerFingerprint: fingerprint}); err != nil {
			return err
		}
		if err := recordAssistanceAudit(ctx, q, &actor.ID, auditkind.AssistanceAnswer, row, "", "offer", row.OfferFingerprint, "answer", fingerprint); err != nil {
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
	return core.NoStore(&adminv1.AnswerAssistanceSessionResponse{Session: session}), nil
}

// StopAssistanceSession is de-escalation: any operator holding view in scope may
// stop either mode, without a fresh directory round trip that could block it.
func (s *Service) StopAssistanceSession(ctx context.Context, req *connect.Request[adminv1.StopAssistanceSessionRequest]) (*connect.Response[adminv1.StopAssistanceSessionResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionViewRemoteAssistance)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_assistance_stop")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	id, _ := uuid.Parse(req.Msg.GetSessionId())
	var session *adminv1.AssistanceSession
	err = s.assistanceTx(ctx, nil, "", func(q *devicedb.Queries, revoked *assistanceRevocations) error {
		row, err := s.lockAssistanceInScope(ctx, q, actor, identity.PermissionViewRemoteAssistance, id, true)
		if err != nil {
			return err
		}
		now := s.Now()
		if err := enforceAssistance(ctx, q, &row, now, revoked); err != nil {
			return err
		}
		if row.State != assistanceEnded {
			if err := recordAssistanceAudit(ctx, q, &actor.ID, auditkind.AssistanceStop, row, ""); err != nil {
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
	return core.NoStore(&adminv1.StopAssistanceSessionResponse{Session: session}), nil
}
