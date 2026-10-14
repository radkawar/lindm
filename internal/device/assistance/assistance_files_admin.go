// SPDX-License-Identifier: Apache-2.0

package assistance

import (
	"bytes"
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/assistancefiles"
	"lindm/internal/auditkind"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

func auditAssistanceFileDenied(ctx context.Context, q *devicedb.Queries, actor uuid.UUID, sessionID, requestID, reason string, denied error) error {
	id, err := uuid.Parse(sessionID)
	if err != nil || id == uuid.Nil {
		return denied
	}
	request, err := uuid.Parse(requestID)
	if err != nil || request == uuid.Nil {
		return denied
	}
	var target *uuid.UUID
	row, err := q.GetAssistanceSession(ctx, id)
	if err == nil {
		target = &row.DeviceID
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err := core.InsertDetailedAudit(ctx, q, devicedb.InsertAuditEventParams{ID: uuid.New(), ActorID: &actor, Action: auditkind.AssistanceFileDeny.String(), ResourceID: id.String(), TargetDeviceID: target}, core.AuditDetails("request", request.String(), "result", "denied", "reason", reason)); err != nil {
		return err
	}
	return denied
}

func (s *Service) assistanceFileDenied(ctx context.Context, sessionID, requestID string, denied error) error {
	actor, ok := identity.PrincipalFromContext(ctx)
	if !ok || s.Pool == nil {
		return denied
	}
	reason := rpcreason.Get(denied)
	if reason == "" {
		reason = "authority_denied"
	}
	return core.MapErr(auditAssistanceFileDenied(ctx, devicedb.New(s.Pool), actor.ID, sessionID, requestID, reason, denied))
}

// All file RPCs share this fresh, transaction-fenced authorization boundary.
// A fleet reader, another operator or independently scoped mode grants cannot
// disclose metadata or cancel a creator's operation without the files grant.
func (s *Service) assistanceFileTx(ctx context.Context, sessionID, requestID string, fn func(*devicedb.Queries, devicedb.AssistanceSession) (*agentv1.AssistanceFileReport, error)) (*agentv1.AssistanceFileReport, error) {
	actor, authorization, release, err := s.authorizeAssistance(ctx)
	if err != nil {
		return nil, s.assistanceFileDenied(ctx, sessionID, requestID, err)
	}
	defer release()
	id, _ := uuid.Parse(sessionID)
	var report *agentv1.AssistanceFileReport
	err = s.assistanceTx(ctx, authorization, identity.PermissionViewRemoteAssistance, func(q *devicedb.Queries, revoked *assistanceRevocations) error {
		deny := func(reason string, denied error) error {
			return auditAssistanceFileDenied(ctx, q, actor.ID, sessionID, requestID, reason, denied)
		}
		row, err := s.lockAssistanceInScope(ctx, q, authorization.Principal(), identity.PermissionViewRemoteAssistance, id, true)
		if err != nil {
			if connect.CodeOf(err) == connect.CodeNotFound || connect.CodeOf(err) == connect.CodePermissionDenied {
				return deny("scope_denied", err)
			}
			return err
		}
		if row.OperatorID != actor.ID {
			return deny("not_creator", rpcreason.Error(connect.CodePermissionDenied, "assistance_not_creator"))
		}
		if err := scopeAssistanceMode(ctx, q, authorization.Principal(), row.DeviceID, agentv1.AssistanceMode(row.Mode)); err != nil {
			return deny("mode_scope_denied", err)
		}
		if err := core.RequireDeviceScope(ctx, q, authorization.Principal(), identity.PermissionAssistanceFiles, row.DeviceID); err != nil {
			return deny("files_scope_denied", core.MapErr(err))
		}
		// lockAssistanceInScope already owns this device lock. Recheck its
		// lifecycle as well as scope before disclosing any file metadata.
		device, err := q.GetDeviceForUpdate(ctx, row.DeviceID)
		if err != nil {
			return err
		}
		if device.State != core.StateActive || device.CurrentGenerationID == nil || *device.CurrentGenerationID != row.GenerationID {
			if err := endAssistance(ctx, q, &row, s.Now(), nil, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "device_authority_lost", false, revoked); err != nil {
				return err
			}
			return deny("device_authority_lost", rpcreason.Error(connect.CodeFailedPrecondition, "assistance_device_authority_lost"))
		}
		if err := enforceAssistance(ctx, q, &row, s.Now(), revoked); err != nil {
			return err
		}
		if row.State != assistanceActive {
			return deny("session_not_active", rpcreason.Error(connect.CodeFailedPrecondition, "assistance_not_active"))
		}
		if err := s.checkAssistancePolicy(ctx, q, row); err != nil {
			if endErr := endAssistance(ctx, q, &row, s.Now(), nil, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "policy_changed", false, revoked); endErr != nil {
				return endErr
			}
			return deny("policy_changed", err)
		}
		report, err = fn(q, row)
		var domain *connect.Error
		if errors.As(err, &domain) {
			return deny(rpcreason.Get(err), err)
		}
		return err
	})
	return report, err
}

func (s *Service) StartAssistanceFileTransfer(ctx context.Context, req *connect.Request[adminv1.StartAssistanceFileTransferRequest]) (*connect.Response[adminv1.StartAssistanceFileTransferResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	if _, err := s.Require(ctx, identity.PermissionViewRemoteAssistance); err != nil {
		if req != nil && req.Msg != nil {
			err = s.assistanceFileDenied(ctx, req.Msg.GetSessionId(), req.Msg.GetTransfer().GetRequestId(), err)
		}
		return nil, err
	}
	if req == nil || req.Msg == nil {
		return nil, core.Invalid("invalid_assistance_file")
	}
	if s.Rules.Validate(req.Msg) != nil {
		return nil, s.assistanceFileDenied(ctx, req.Msg.GetSessionId(), req.Msg.GetTransfer().GetRequestId(), core.Invalid("invalid_assistance_file"))
	}
	digest, err := core.ActionDigest(req.Msg)
	if err != nil {
		return nil, core.MapErr(err)
	}
	request := &agentv1.AssistanceFileRequest{RequestId: req.Msg.GetTransfer().GetRequestId(), Direction: req.Msg.GetTransfer().GetDirection(), File: assistanceFileMetadata(req.Msg.GetTransfer().GetFile())}
	requestID, _ := uuid.Parse(request.GetRequestId())
	report, err := s.assistanceFileTx(ctx, req.Msg.GetSessionId(), request.GetRequestId(), func(q *devicedb.Queries, row devicedb.AssistanceSession) (*agentv1.AssistanceFileReport, error) {
		policy := assistanceFilePolicy(row, request.GetDirection())
		if policy == nil {
			return nil, rpcreason.Error(connect.CodeFailedPrecondition, "assistance_files_not_granted")
		}
		old, err := q.GetAssistanceFileTransfer(ctx, requestID)
		if err == nil {
			if old.SessionID != row.ID || old.OperatorID != row.OperatorID || !bytes.Equal(old.RequestDigest, digest) {
				return nil, core.ErrIdempotencyConflict
			}
			if err := s.enforceAssistanceFile(ctx, q, &old, s.Now()); err != nil {
				return nil, err
			}
			return assistanceFileReport(old)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		if row.InputPaused {
			return nil, rpcreason.Error(connect.CodeFailedPrecondition, "assistance_input_paused")
		}
		if command, err := q.GetPendingAssistanceCommand(ctx, row.ID); err == nil {
			result, err := s.assistanceCommandResult(ctx, q, &command, s.Now())
			if err != nil {
				return nil, err
			}
			if result.GetStatus() == agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_PENDING {
				return nil, rpcreason.Error(connect.CodeFailedPrecondition, "assistance_command_busy")
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		if busy, err := s.assistanceFileBusy(ctx, q, row.ID, s.Now()); err != nil {
			return nil, err
		} else if busy {
			return nil, rpcreason.Error(connect.CodeFailedPrecondition, "assistance_file_busy")
		}
		quota, err := q.AssistanceFileQuota(ctx, row.ID)
		if err != nil {
			return nil, err
		}
		if quota.Requests >= 32 || uint64(quota.ReservedBytes) >= policy.GetMaxSessionBytes() {
			return nil, rpcreason.Error(connect.CodeResourceExhausted, "assistance_file_quota")
		}
		policy.MaxSessionBytes -= uint64(quota.ReservedBytes)
		policy.MaxFileBytes = min(policy.MaxFileBytes, policy.MaxSessionBytes)
		reservation := policy.MaxFileBytes
		if request.GetDirection() == agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER {
			if !assistancefiles.MetadataAllowed(policy, request.GetFile(), true) {
				return nil, rpcreason.Error(connect.CodeFailedPrecondition, "assistance_file_policy")
			}
			reservation = request.GetFile().GetSize()
		}
		now := s.Now()
		deadline := now.Add(assistanceFileLifetime)
		if row.EndsAt.Time.Before(deadline) {
			deadline = row.EndsAt.Time
		}
		request.Policy, request.Deadline = policy, timestamppb.New(deadline)
		metadata, err := proto.Marshal(request)
		if err != nil {
			return nil, err
		}
		report := &agentv1.AssistanceFileReport{RequestId: request.GetRequestId(), Direction: request.GetDirection(), State: agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_REQUESTED}
		data, err := proto.Marshal(report)
		if err != nil {
			return nil, err
		}
		if err := q.InsertAssistanceFileTransfer(ctx, devicedb.InsertAssistanceFileTransferParams{RequestID: requestID, SessionID: row.ID, DeviceID: row.DeviceID, OperatorID: row.OperatorID, OwnerInstance: s.runtime.assistanceInstance, RequestNumber: int16(quota.Requests + 1), RequestDigest: digest, Direction: int16(request.GetDirection()), RequestMetadata: metadata, Report: data, ReservedBytes: int64(reservation), CreatedAt: core.Timestamptz(now), Deadline: core.Timestamptz(deadline)}); err != nil {
			return nil, err
		}
		operation, err := q.GetAssistanceFileTransfer(ctx, requestID)
		if err != nil {
			return nil, err
		}
		if err := recordAssistanceFileAudit(ctx, q, operation, auditkind.AssistanceFileRequest, ""); err != nil {
			return nil, err
		}
		return report, nil
	})
	if err != nil {
		return nil, err
	}
	return core.NoStore(&adminv1.StartAssistanceFileTransferResponse{Transfer: report}), nil
}

func (s *Service) getAssistanceFile(ctx context.Context, sessionID, requestID string, cancel bool) (*agentv1.AssistanceFileReport, error) {
	return s.assistanceFileTx(ctx, sessionID, requestID, func(q *devicedb.Queries, row devicedb.AssistanceSession) (*agentv1.AssistanceFileReport, error) {
		id, _ := uuid.Parse(requestID)
		operation, err := q.GetAssistanceFileTransfer(ctx, id)
		if err != nil {
			return nil, core.MapErr(core.NotFoundIfMissing(err))
		}
		if operation.SessionID != row.ID || operation.OperatorID != row.OperatorID {
			return nil, rpcreason.Error(connect.CodeNotFound, "not_found")
		}
		if assistanceFilePolicy(row, agentv1.AssistanceFileDirection(operation.Direction)) == nil {
			return nil, rpcreason.Error(connect.CodeFailedPrecondition, "assistance_files_not_granted")
		}
		if err := s.enforceAssistanceFile(ctx, q, &operation, s.Now()); err != nil {
			return nil, err
		}
		if cancel {
			if err := stopAssistanceFile(ctx, q, &operation, s.Now(), "operator_cancelled"); err != nil {
				return nil, err
			}
		}
		return assistanceFileReport(operation)
	})
}

type assistanceFileReference interface {
	proto.Message
	GetSessionId() string
	GetRequestId() string
}

func (s *Service) referenceAssistanceFile(ctx context.Context, msg assistanceFileReference, cancelTransfer bool) (*agentv1.AssistanceFileReport, error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	if _, err := s.Require(ctx, identity.PermissionViewRemoteAssistance); err != nil {
		if msg != nil {
			err = s.assistanceFileDenied(ctx, msg.GetSessionId(), msg.GetRequestId(), err)
		}
		return nil, err
	}
	if msg == nil || s.Rules.Validate(msg) != nil {
		return nil, core.Invalid("invalid_assistance_file")
	}
	return s.getAssistanceFile(ctx, msg.GetSessionId(), msg.GetRequestId(), cancelTransfer)
}

func (s *Service) GetAssistanceFileTransfer(ctx context.Context, req *connect.Request[adminv1.GetAssistanceFileTransferRequest]) (*connect.Response[adminv1.GetAssistanceFileTransferResponse], error) {
	var msg assistanceFileReference
	if req != nil && req.Msg != nil {
		msg = req.Msg
	}
	report, err := s.referenceAssistanceFile(ctx, msg, false)
	if err != nil {
		return nil, err
	}
	return core.NoStore(&adminv1.GetAssistanceFileTransferResponse{Transfer: report}), nil
}

func (s *Service) CancelAssistanceFileTransfer(ctx context.Context, req *connect.Request[adminv1.CancelAssistanceFileTransferRequest]) (*connect.Response[adminv1.CancelAssistanceFileTransferResponse], error) {
	var msg assistanceFileReference
	if req != nil && req.Msg != nil {
		msg = req.Msg
	}
	report, err := s.referenceAssistanceFile(ctx, msg, true)
	if err != nil {
		return nil, err
	}
	return core.NoStore(&adminv1.CancelAssistanceFileTransferResponse{Transfer: report}), nil
}
