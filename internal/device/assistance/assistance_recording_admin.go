// SPDX-License-Identifier: Apache-2.0

package assistance

import (
	"bytes"
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/assistancerecording"
	"lindm/internal/auditkind"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

// A retrieval is fresh archive authority for a bounded interval. Reading its
// segments rechecks the cached grant and device scope but is not re-audited.
const assistanceRetrievalLifetime = 10 * time.Minute

// auditAssistanceRecordingDenied records a refused archive operation with the
// recording's device when it exists. It never includes content or keys.
func auditAssistanceRecordingDenied(ctx context.Context, q *devicedb.Queries, actor uuid.UUID, action auditkind.Kind, recordingID, reason string, denied error) error {
	id, err := uuid.Parse(recordingID)
	if err != nil || id == uuid.Nil {
		return denied
	}
	var target *uuid.UUID
	row, err := q.GetAssistanceRecording(ctx, id)
	if err == nil {
		target = &row.DeviceID
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err := core.InsertDetailedAudit(ctx, q, devicedb.InsertAuditEventParams{ID: uuid.New(), ActorID: &actor, Action: action.String(), ResourceID: id.String(), TargetDeviceID: target}, core.AuditDetails("recording", id.String(), "result", "denied", "reason", reason)); err != nil {
		return err
	}
	return denied
}

func (s *Service) assistanceRecordingDenied(ctx context.Context, action auditkind.Kind, recordingID string, denied error) error {
	actor, ok := identity.PrincipalFromContext(ctx)
	if !ok || s.Pool == nil {
		return denied
	}
	reason := rpcreason.Get(denied)
	if reason == "" {
		reason = "authority_denied"
	}
	return core.MapErr(auditAssistanceRecordingDenied(ctx, devicedb.New(s.Pool), actor.ID, action, recordingID, reason, denied))
}

// ListAssistanceRecordings returns archive metadata to fleet readers in scope,
// like session metadata. It discloses no content, key or retrieval authority.
func (s *Service) ListAssistanceRecordings(ctx context.Context, req *connect.Request[adminv1.ListAssistanceRecordingsRequest]) (*connect.Response[adminv1.ListAssistanceRecordingsResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_assistance_recordings")
	}
	deviceID, _ := uuid.Parse(req.Msg.GetDeviceId())
	params := devicedb.ListAssistanceRecordingsParams{DeviceID: deviceID, PageLimit: core.PageLimit(req.Msg.GetPageSize()) + 1, CursorTime: core.Timestamptz(time.Unix(0, 0))}
	if req.Msg.GetPageToken() != "" {
		stamp, cursor, err := core.DecodeCursor(req.Msg.GetPageToken())
		if err != nil {
			return nil, err
		}
		params.HasCursor, params.CursorTime, params.CursorID = true, core.Timestamptz(stamp), cursor
	}
	response := &adminv1.ListAssistanceRecordingsResponse{}
	err = s.assistanceTx(ctx, nil, "", func(q *devicedb.Queries, _ *assistanceRevocations) error {
		if err := core.RequireDeviceScope(ctx, q, actor, identity.PermissionReadFleet, deviceID); err != nil {
			return core.MapErr(err)
		}
		rows, err := q.ListAssistanceRecordings(ctx, params)
		if err != nil {
			return err
		}
		for i, row := range rows {
			if i == int(params.PageLimit)-1 {
				last := rows[i-1]
				token, err := core.EncodeCursor(last.CreatedAt.Time, last.ID)
				if err != nil {
					return err
				}
				response.NextPageToken = token
				break
			}
			response.Recordings = append(response.Recordings, assistanceRecordingMessage(row))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return core.NoStore(response), nil
}

// archiveRecording locks a recording in the caller's permission scope and
// settles a capture whose session ended without its final segment.
func (s *Service) archiveRecording(ctx context.Context, q *devicedb.Queries, principal identity.Principal, permission identity.Permission, id uuid.UUID) (devicedb.AssistanceRecording, error) {
	row, err := q.LockAssistanceRecording(ctx, id)
	if err != nil {
		return devicedb.AssistanceRecording{}, core.MapErr(core.NotFoundIfMissing(err))
	}
	if err := core.RequireDeviceScope(ctx, q, principal, permission, row.DeviceID); err != nil {
		return devicedb.AssistanceRecording{}, core.MapErr(err)
	}
	if err := settleAssistanceRecording(ctx, q, &row, s.Now()); err != nil {
		return devicedb.AssistanceRecording{}, err
	}
	return row, nil
}

// archiveAuthority applies the CreateDeviceAction admission pattern to an
// archive operation: cached grant first, then bounded slots and fresh authority.
func (s *Service) archiveAuthority(ctx context.Context, permission identity.Permission, action auditkind.Kind, msg interface {
	proto.Message
	GetRecordingId() string
},
) (identity.Principal, *identity.Authorization, func(), error) {
	actor, err := s.Require(ctx, permission)
	if err != nil {
		if msg != nil {
			err = s.assistanceRecordingDenied(ctx, action, msg.GetRecordingId(), err)
		}
		return identity.Principal{}, nil, nil, err
	}
	if msg == nil || !msg.ProtoReflect().IsValid() || s.Rules.Validate(msg) != nil {
		return identity.Principal{}, nil, nil, core.Invalid("invalid_assistance_recording")
	}
	if s.Identity == nil {
		return identity.Principal{}, nil, nil, rpcreason.Error(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	if err := s.Acquire(ctx); err != nil {
		return identity.Principal{}, nil, nil, core.MapErr(err)
	}
	authorization, err := s.Identity.AuthorizeFresh(ctx, actor.ID, permission)
	if err != nil {
		s.Release()
		return identity.Principal{}, nil, nil, s.assistanceRecordingDenied(ctx, action, msg.GetRecordingId(), core.ExecutionError(err))
	}
	return actor, authorization, s.Release, nil
}

// OpenAssistanceRecording audits and starts one expiring, operator-bound
// retrieval of a finalized recording. It grants no live assistance.
func (s *Service) OpenAssistanceRecording(ctx context.Context, req *connect.Request[adminv1.OpenAssistanceRecordingRequest]) (*connect.Response[adminv1.OpenAssistanceRecordingResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	action := auditkind.AssistanceRecordingRead
	var msg *adminv1.OpenAssistanceRecordingRequest
	if req != nil {
		msg = req.Msg
	}
	actor, authorization, release, err := s.archiveAuthority(ctx, identity.PermissionReadAssistanceRecordings, action, msg)
	if err != nil {
		return nil, err
	}
	defer release()
	id, _ := uuid.Parse(req.Msg.GetRecordingId())
	response := &adminv1.OpenAssistanceRecordingResponse{MediaType: assistancerecording.MediaType}
	err = s.assistanceTx(ctx, authorization, identity.PermissionReadAssistanceRecordings, func(q *devicedb.Queries, _ *assistanceRevocations) error {
		deny := func(reason string, denied error) error {
			return auditAssistanceRecordingDenied(ctx, q, actor.ID, action, id.String(), reason, denied)
		}
		row, err := s.archiveRecording(ctx, q, authorization.Principal(), identity.PermissionReadAssistanceRecordings, id)
		if err != nil {
			if code := connect.CodeOf(err); code == connect.CodeNotFound || code == connect.CodePermissionDenied {
				return deny("scope_denied", err)
			}
			return err
		}
		if row.State != recordingComplete && row.State != recordingIncomplete {
			return deny("recording_unavailable", rpcreason.Error(connect.CodeFailedPrecondition, "assistance_recording_unavailable"))
		}
		if s.AssistanceRecording == nil || s.AssistanceRecording.KeyID() != row.KeyID {
			return deny("recording_key_unavailable", rpcreason.Error(connect.CodeFailedPrecondition, "assistance_recording_key_unavailable"))
		}
		now := s.Now()
		retrieval := uuid.New()
		expires := now.Add(assistanceRetrievalLifetime)
		if err := q.InsertAssistanceRecordingRetrieval(ctx, devicedb.InsertAssistanceRecordingRetrievalParams{ID: retrieval, RecordingID: row.ID, OperatorID: actor.ID, CreatedAt: core.Timestamptz(now), ExpiresAt: core.Timestamptz(expires)}); err != nil {
			return err
		}
		if err := recordAssistanceRecordingAccess(ctx, q, &actor.ID, action, row, "opened", "", req.Msg.GetReason(), "retrieval", retrieval.String(), "expires_at", expires.Format(time.RFC3339)); err != nil {
			return err
		}
		response.RetrievalId, response.ExpiresAt, response.Recording = retrieval.String(), timestamppb.New(expires), assistanceRecordingMessage(row)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return core.NoStore(response), nil
}

// ReadAssistanceRecording decrypts one segment of an open retrieval in memory.
// Plaintext is returned over TLS and never written to server storage or logs.
func (s *Service) ReadAssistanceRecording(ctx context.Context, req *connect.Request[adminv1.ReadAssistanceRecordingRequest]) (*connect.Response[adminv1.ReadAssistanceRecordingResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionReadAssistanceRecordings)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_assistance_recording")
	}
	if s.AssistanceRecording == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "assistance_recording_key_unavailable")
	}
	id, _ := uuid.Parse(req.Msg.GetRetrievalId())
	sequence := req.Msg.GetSequence()
	response := &adminv1.ReadAssistanceRecordingResponse{Sequence: sequence}
	err = s.assistanceTx(ctx, nil, "", func(q *devicedb.Queries, _ *assistanceRevocations) error {
		retrieval, err := q.GetAssistanceRecordingRetrieval(ctx, id)
		if err != nil {
			return core.MapErr(core.NotFoundIfMissing(err))
		}
		if retrieval.OperatorID != actor.ID {
			return rpcreason.Error(connect.CodeNotFound, "not_found")
		}
		if !s.Now().Before(retrieval.ExpiresAt.Time) {
			return rpcreason.Error(connect.CodeFailedPrecondition, "assistance_recording_retrieval_expired")
		}
		row, err := q.GetAssistanceRecording(ctx, retrieval.RecordingID)
		if err != nil {
			return err
		}
		if err := core.RequireDeviceScope(ctx, q, actor, identity.PermissionReadAssistanceRecordings, row.DeviceID); err != nil {
			return core.MapErr(err)
		}
		if row.State != recordingComplete && row.State != recordingIncomplete {
			return rpcreason.Error(connect.CodeFailedPrecondition, "assistance_recording_unavailable")
		}
		if s.AssistanceRecording.KeyID() != row.KeyID {
			return rpcreason.Error(connect.CodeFailedPrecondition, "assistance_recording_key_unavailable")
		}
		if int64(sequence) >= int64(row.Segments) {
			return rpcreason.Error(connect.CodeOutOfRange, "assistance_recording_sequence")
		}
		segment, err := q.GetAssistanceRecordingSegment(ctx, devicedb.GetAssistanceRecordingSegmentParams{RecordingID: row.ID, Sequence: int32(sequence)})
		if err != nil {
			return err
		}
		last := int64(sequence) == int64(row.Segments)-1
		if segment.Final && !last {
			return rpcreason.Error(connect.CodeDataLoss, "assistance_recording_integrity")
		}
		opener, err := s.AssistanceRecording.Open(row.ID, row.EncapsulatedKey)
		if err != nil {
			return rpcreason.Error(connect.CodeDataLoss, "assistance_recording_integrity")
		}
		data, err := opener.Open(sequence, segment.Final, segment.Ciphertext)
		if err != nil {
			return rpcreason.Error(connect.CodeDataLoss, "assistance_recording_integrity")
		}
		response.Data, response.Last, response.Complete = data, last, row.State == recordingComplete
		return nil
	})
	if err != nil {
		clear(response.Data)
		return nil, err
	}
	return core.NoStore(response), nil
}

// DeleteAssistanceRecording destroys a finalized recording's ciphertext and
// encapsulated key with its own permission and device scope.
func (s *Service) DeleteAssistanceRecording(ctx context.Context, req *connect.Request[adminv1.DeleteAssistanceRecordingRequest]) (*connect.Response[adminv1.DeleteAssistanceRecordingResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	action := auditkind.AssistanceRecordingDelete
	var msg *adminv1.DeleteAssistanceRecordingRequest
	if req != nil {
		msg = req.Msg
	}
	actor, authorization, release, err := s.archiveAuthority(ctx, identity.PermissionDeleteAssistanceRecordings, action, msg)
	if err != nil {
		return nil, err
	}
	defer release()
	digest, err := core.ActionDigest(req.Msg)
	if err != nil {
		return nil, core.MapErr(err)
	}
	id, _ := uuid.Parse(req.Msg.GetRecordingId())
	requestID, _ := uuid.Parse(req.Msg.GetRequestId())
	var recording *adminv1.AssistanceRecording
	err = s.assistanceTx(ctx, authorization, identity.PermissionDeleteAssistanceRecordings, func(q *devicedb.Queries, _ *assistanceRevocations) error {
		deny := func(reason string, denied error) error {
			return auditAssistanceRecordingDenied(ctx, q, actor.ID, action, id.String(), reason, denied)
		}
		row, err := s.archiveRecording(ctx, q, authorization.Principal(), identity.PermissionDeleteAssistanceRecordings, id)
		if err != nil {
			if code := connect.CodeOf(err); code == connect.CodeNotFound || code == connect.CodePermissionDenied {
				return deny("scope_denied", err)
			}
			return err
		}
		old, err := q.GetAssistanceRecordingDeletion(ctx, requestID)
		if err == nil {
			if old.OperatorID != actor.ID || old.RecordingID != row.ID || !bytes.Equal(old.RequestDigest, digest) {
				return core.ErrIdempotencyConflict
			}
			recording = assistanceRecordingMessage(row)
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if row.State == recordingPending || row.State == recordingActive {
			return deny("recording_active", rpcreason.Error(connect.CodeFailedPrecondition, "assistance_recording_active"))
		}
		if row.State != recordingDeleted {
			if err := deleteAssistanceRecordingContent(ctx, q, &row, s.Now(), "operator_deleted"); err != nil {
				return err
			}
			if err := recordAssistanceRecordingAccess(ctx, q, &actor.ID, action, row, "deleted", "operator_deleted", req.Msg.GetReason()); err != nil {
				return err
			}
		}
		if err := q.InsertAssistanceRecordingDeletion(ctx, devicedb.InsertAssistanceRecordingDeletionParams{RequestID: requestID, RecordingID: row.ID, OperatorID: actor.ID, RequestDigest: digest}); err != nil {
			return err
		}
		recording = assistanceRecordingMessage(row)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return core.NoStore(&adminv1.DeleteAssistanceRecordingResponse{Recording: recording}), nil
}
