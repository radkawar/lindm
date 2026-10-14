// SPDX-License-Identifier: Apache-2.0

package assistance

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/auditkind"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

const assistanceCommandLifetime = 30 * time.Second

func assistanceCommandPermission(kind agentv1.AssistanceCommandKind) identity.Permission {
	switch kind {
	case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_WRITE, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ:
		return identity.PermissionAssistanceClipboard
	case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SPECIAL_KEYS:
		return identity.PermissionAssistanceKeyboard
	case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SELECT_DISPLAY:
		return identity.PermissionAssistanceDisplay
	case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE:
		return identity.PermissionAssistanceMessage
	default:
		return ""
	}
}

func assistanceCommandAllowed(row devicedb.AssistanceSession, command *agentv1.AssistanceCommand) bool {
	projection := assistanceProjection(row)
	policy := intersectAssistancePolicy(decodeAssistancePolicy(row.EffectiveCapabilities), projection.GetGrantedCapabilities().GetPolicy())
	on := agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON
	switch command.GetKind() {
	case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_WRITE:
		return policy.GetClipboard() >= agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
	case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ:
		return policy.GetClipboard() == on
	case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SPECIAL_KEYS:
		return row.ControlGranted && policy.GetKeyboard() == on
	case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SELECT_DISPLAY:
		if policy.GetDisplay() != on {
			return false
		}
		for _, display := range projection.GetDisplays() {
			if display.GetId() == command.GetDisplayId() {
				return true
			}
		}
	case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE:
		return policy.GetMessages() >= agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
	}
	return false
}

func assistanceCommandAuditKind(kind int16) auditkind.Kind {
	switch agentv1.AssistanceCommandKind(kind) {
	case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_WRITE, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ:
		return auditkind.AssistanceClipboard
	case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SPECIAL_KEYS:
		return auditkind.AssistanceSpecialKeys
	case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SELECT_DISPLAY:
		return auditkind.AssistanceDisplay
	default:
		return auditkind.AssistanceMessage
	}
}

func finishAssistanceCommand(ctx context.Context, q *devicedb.Queries, command *devicedb.AssistanceCommand, status agentv1.AssistanceCommandStatus, reason string, now time.Time) error {
	if command.Status != int16(agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_PENDING) {
		return nil
	}
	if err := q.FinishAssistanceCommand(ctx, devicedb.FinishAssistanceCommandParams{RequestID: command.RequestID, Status: int16(status), Reason: reason, CompletedAt: core.Timestamptz(now), ByteCount: command.ByteCount}); err != nil {
		return err
	}
	command.Status, command.Reason, command.CompletedAt = int16(status), reason, core.Timestamptz(now)
	// Never include payload, digest, desktop-provided prose, or read result.
	outcome := strings.ToLower(strings.TrimPrefix(status.String(), "ASSISTANCE_COMMAND_STATUS_"))
	if command.Kind == int16(agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE) {
		// Notification service acceptance is not proof the employee saw it.
		outcome = "unknown"
		if status == agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_FAILED {
			outcome = "rejected"
		}
	}
	return core.InsertDetailedAudit(ctx, q, devicedb.InsertAuditEventParams{
		ID: uuid.New(), ActorID: &command.OperatorID, Action: assistanceCommandAuditKind(command.Kind).String(), ResourceID: command.SessionID.String(), TargetDeviceID: &command.DeviceID,
	}, core.AuditDetails(assistanceOperationAudit(*command, outcome, reason)...))
}

func cancelAssistanceCommand(ctx context.Context, q *devicedb.Queries, sessionID uuid.UUID, now time.Time, reason string) error {
	command, err := q.GetPendingAssistanceCommand(ctx, sessionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return finishAssistanceCommand(ctx, q, &command, agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_CANCELLED, reason, now)
}

func commandResultMetadata(row devicedb.AssistanceCommand) *agentv1.AssistanceCommandResult {
	return &agentv1.AssistanceCommandResult{RequestId: row.RequestID.String(), Kind: agentv1.AssistanceCommandKind(row.Kind), Status: agentv1.AssistanceCommandStatus(row.Status), Reason: row.Reason, CompletedAt: core.ProtoTime(row.CompletedAt)}
}

// The session SQL row serializes command acceptance, completion and stop. Every
// caller holds it before touching the ephemeral slot, avoiding lock inversion.
func (s *Service) assistanceCommandResult(ctx context.Context, q *devicedb.Queries, operation *devicedb.AssistanceCommand, now time.Time) (*agentv1.AssistanceCommandResult, error) {
	s.runtime.assistanceMu.Lock()
	defer s.runtime.assistanceMu.Unlock()
	memory := s.runtime.assistanceCommands[operation.SessionID]
	known := memory != nil && memory.command.GetRequestId() == operation.RequestID.String() && now.Before(memory.command.GetDeadline().AsTime())
	if operation.Status == int16(agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_PENDING) && (!known || !now.Before(operation.Deadline.Time)) {
		status, reason := agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_CANCELLED, "command_state_lost"
		if !now.Before(operation.Deadline.Time) {
			status, reason = agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_EXPIRED, "command_expired"
		}
		if err := finishAssistanceCommand(ctx, q, operation, status, reason, now); err != nil {
			return nil, err
		}
	}
	result := commandResultMetadata(*operation)
	if known && memory.result != nil && operation.Status == int16(memory.result.GetStatus()) {
		result.Text = memory.result.GetText()
	} else if operation.Kind == int16(agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ) && operation.Status == int16(agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED) {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "assistance_content_expired")
	}
	return result, nil
}

func (s *Service) RunAssistanceCommand(ctx context.Context, req *connect.Request[adminv1.RunAssistanceCommandRequest]) (*connect.Response[adminv1.RunAssistanceCommandResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	if _, err := s.Require(ctx, identity.PermissionViewRemoteAssistance); err != nil {
		if req != nil && req.Msg != nil {
			err = s.assistanceAccessDenied(ctx, req.Msg.GetSessionId(), req.Msg.GetCommand().GetRequestId(), err)
		}
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_assistance_command")
	}
	actor, authorization, release, err := s.authorizeAssistance(ctx)
	if err != nil {
		return nil, s.assistanceAccessDenied(ctx, req.Msg.GetSessionId(), req.Msg.GetCommand().GetRequestId(), err)
	}
	defer release()
	command := proto.CloneOf(req.Msg.GetCommand())
	id, _ := uuid.Parse(req.Msg.GetSessionId())
	requestID, _ := uuid.Parse(command.GetRequestId())
	digest, err := core.ActionDigest(req.Msg)
	if err != nil {
		return nil, core.MapErr(err)
	}
	var result *agentv1.AssistanceCommandResult
	var accepted *assistanceCommandMemory
	err = s.assistanceTx(ctx, authorization, identity.PermissionViewRemoteAssistance, func(q *devicedb.Queries, revoked *assistanceRevocations) error {
		row, err := s.lockAssistanceInScope(ctx, q, authorization.Principal(), identity.PermissionViewRemoteAssistance, id, true)
		if err != nil {
			if connect.CodeOf(err) == connect.CodeNotFound || connect.CodeOf(err) == connect.CodePermissionDenied {
				return auditAssistanceAccessDenied(ctx, q, actor.ID, id.String(), requestID.String(), "scope_denied", err)
			}
			return err
		}
		deny := func(reason string, denied error) error {
			return denyAssistanceOperation(ctx, q, row, actor.ID, command, reason, denied)
		}
		if row.OperatorID != actor.ID {
			return deny("not_creator", rpcreason.Error(connect.CodePermissionDenied, "assistance_not_creator"))
		}
		if err := scopeAssistanceMode(ctx, q, authorization.Principal(), row.DeviceID, agentv1.AssistanceMode(row.Mode)); err != nil {
			return deny("mode_scope_denied", err)
		}
		if err := core.RequireDeviceScope(ctx, q, authorization.Principal(), assistanceCommandPermission(command.GetKind()), row.DeviceID); err != nil {
			return deny("capability_scope_denied", core.MapErr(err))
		}
		now := s.Now()
		if err := enforceAssistance(ctx, q, &row, now, revoked); err != nil {
			return err
		}
		if row.State == assistanceEnded {
			return deny("session_ended", rpcreason.Error(connect.CodeFailedPrecondition, "assistance_ended"))
		}
		if err := s.checkAssistancePolicy(ctx, q, row); err != nil {
			return deny("policy_changed", err)
		}
		old, err := q.GetAssistanceCommand(ctx, requestID)
		if err == nil {
			if old.SessionID != id || old.OperatorID != actor.ID || !bytes.Equal(old.RequestDigest, digest) {
				return deny("request_conflict", core.ErrIdempotencyConflict)
			}
			result, err = s.assistanceCommandResult(ctx, q, &old, now)
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if row.State != assistanceActive {
			return deny("not_active", rpcreason.Error(connect.CodeFailedPrecondition, "assistance_not_active"))
		}
		if !assistanceCommandAllowed(row, command) {
			return deny("capability_not_granted", rpcreason.Error(connect.CodeFailedPrecondition, "assistance_capability_not_granted"))
		}
		count, err := q.CountAssistanceCommands(ctx, id)
		if err != nil {
			return err
		}
		if count >= 256 {
			return deny("command_capacity", rpcreason.Error(connect.CodeResourceExhausted, "assistance_command_capacity"))
		}
		deadline := now.Add(assistanceCommandLifetime)
		if row.EndsAt.Time.Before(deadline) {
			deadline = row.EndsAt.Time
		}
		command.Deadline = timestamppb.New(deadline)
		pending, err := q.GetPendingAssistanceCommand(ctx, id)
		if err == nil {
			state, err := s.assistanceCommandResult(ctx, q, &pending, now)
			if err != nil {
				return err
			}
			if state.GetStatus() == agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_PENDING {
				return deny("command_busy", rpcreason.Error(connect.CodeFailedPrecondition, "assistance_command_busy"))
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err := q.InsertAssistanceCommand(ctx, devicedb.InsertAssistanceCommandParams{RequestID: requestID, SessionID: id, DeviceID: row.DeviceID, OperatorID: actor.ID, RequestDigest: digest, Kind: int16(command.GetKind()), Policy: row.EffectiveCapabilities, ByteCount: int32(len(command.GetText())), SpecialKey: int16(command.GetSpecialKey()), DisplayID: command.GetDisplayId(), Deadline: core.Timestamptz(deadline)}); err != nil {
			return err
		}
		accepted = s.runtime.rememberAssistanceCommand(id, command, s.Now())
		result = &agentv1.AssistanceCommandResult{RequestId: command.GetRequestId(), Kind: command.GetKind(), Status: agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_PENDING}
		return nil
	})
	if err != nil {
		if accepted != nil {
			s.runtime.forgetAssistanceCommand(id, accepted)
		}
		return nil, err
	}
	// Mutation recovery exposes outcome metadata only. Clipboard disclosure
	// has exactly one API boundary: the freshly authorized Get command.
	result.Text = ""
	return core.NoStore(&adminv1.RunAssistanceCommandResponse{Result: result}), nil
}

func (s *Service) checkAssistancePolicy(ctx context.Context, q *devicedb.Queries, row devicedb.AssistanceSession) error {
	policy, err := loadAssistancePolicy(ctx, q, row.DeviceID)
	if err != nil {
		return err
	}
	effective := decodeAssistancePolicy(row.EffectiveCapabilities)
	if !proto.Equal(effective, intersectAssistancePolicy(effective, intersectAssistancePolicy(policy, s.AssistanceCeiling))) {
		return rpcreason.Error(connect.CodePermissionDenied, "assistance_policy_changed")
	}
	return nil
}

func (s *Service) GetAssistanceCommand(ctx context.Context, req *connect.Request[adminv1.GetAssistanceCommandRequest]) (*connect.Response[adminv1.GetAssistanceCommandResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	if _, err := s.Require(ctx, identity.PermissionViewRemoteAssistance); err != nil {
		if req != nil && req.Msg != nil {
			err = s.assistanceAccessDenied(ctx, req.Msg.GetSessionId(), req.Msg.GetRequestId(), err)
		}
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_assistance_command")
	}
	actor, authorization, release, err := s.authorizeAssistance(ctx)
	if err != nil {
		return nil, s.assistanceAccessDenied(ctx, req.Msg.GetSessionId(), req.Msg.GetRequestId(), err)
	}
	defer release()
	id, _ := uuid.Parse(req.Msg.GetSessionId())
	requestID, _ := uuid.Parse(req.Msg.GetRequestId())
	var result *agentv1.AssistanceCommandResult
	err = s.assistanceTx(ctx, authorization, identity.PermissionViewRemoteAssistance, func(q *devicedb.Queries, revoked *assistanceRevocations) error {
		row, err := s.lockAssistanceInScope(ctx, q, authorization.Principal(), identity.PermissionViewRemoteAssistance, id, true)
		if err != nil {
			if connect.CodeOf(err) == connect.CodeNotFound || connect.CodeOf(err) == connect.CodePermissionDenied {
				return auditAssistanceAccessDenied(ctx, q, actor.ID, id.String(), requestID.String(), "scope_denied", err)
			}
			return err
		}
		deny := func(reason string, denied error) error {
			return auditAssistanceAccessDenied(ctx, q, actor.ID, id.String(), requestID.String(), reason, denied)
		}
		if row.OperatorID != actor.ID {
			return deny("not_creator", rpcreason.Error(connect.CodePermissionDenied, "assistance_not_creator"))
		}
		if err := scopeAssistanceMode(ctx, q, authorization.Principal(), row.DeviceID, agentv1.AssistanceMode(row.Mode)); err != nil {
			return deny("mode_scope_denied", err)
		}
		operation, err := q.GetAssistanceCommand(ctx, requestID)
		if errors.Is(err, pgx.ErrNoRows) {
			return deny("command_not_found", core.MapErr(core.NotFoundIfMissing(err)))
		}
		if err != nil {
			return err
		}
		if operation.SessionID != id || operation.OperatorID != actor.ID {
			return deny("command_scope_denied", rpcreason.Error(connect.CodeNotFound, "not_found"))
		}
		if err := core.RequireDeviceScope(ctx, q, authorization.Principal(), assistanceCommandPermission(agentv1.AssistanceCommandKind(operation.Kind)), row.DeviceID); err != nil {
			return deny("capability_scope_denied", core.MapErr(err))
		}
		if err := enforceAssistance(ctx, q, &row, s.Now(), revoked); err != nil {
			return err
		}
		if row.State == assistanceEnded {
			return deny("session_ended", rpcreason.Error(connect.CodeFailedPrecondition, "assistance_ended"))
		}
		if err := s.checkAssistancePolicy(ctx, q, row); err != nil {
			return deny("policy_changed", err)
		}
		result, err = s.assistanceCommandResult(ctx, q, &operation, s.Now())
		if err != nil && connect.CodeOf(err) == connect.CodeFailedPrecondition {
			return deny("content_expired", err)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return core.NoStore(&adminv1.GetAssistanceCommandResponse{Result: result}), nil
}

func (s *Service) commandForAssistance(ctx context.Context, q *devicedb.Queries, row devicedb.AssistanceSession, now time.Time) (*agentv1.AssistanceCommand, error) {
	if row.State != assistanceActive {
		return nil, nil
	}
	operation, err := q.GetPendingAssistanceCommand(ctx, row.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	result, err := s.assistanceCommandResult(ctx, q, &operation, now)
	if err != nil || result.GetStatus() != agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_PENDING {
		return nil, err
	}
	s.runtime.assistanceMu.Lock()
	defer s.runtime.assistanceMu.Unlock()
	if memory := s.runtime.assistanceCommands[row.ID]; memory != nil && memory.command.GetRequestId() == operation.RequestID.String() {
		return proto.CloneOf(memory.command), nil
	}
	return nil, nil
}

func (s *Service) completeAssistanceCommand(ctx context.Context, q *devicedb.Queries, row devicedb.AssistanceSession, result *agentv1.AssistanceCommandResult, now time.Time) error {
	if result == nil {
		return nil
	}
	id, _ := uuid.Parse(result.GetRequestId())
	operation, err := q.GetAssistanceCommand(ctx, id)
	if err != nil {
		return err
	}
	if operation.SessionID != row.ID || operation.OperatorID != row.OperatorID || operation.Kind != int16(result.GetKind()) || result.GetStatus() == agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_PENDING {
		return core.Invalid("assistance_command_result")
	}
	if operation.Status != int16(agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_PENDING) {
		return nil
	}
	if row.State != assistanceActive {
		return core.Invalid("assistance_command_before_active")
	}
	s.runtime.assistanceMu.Lock()
	defer s.runtime.assistanceMu.Unlock()
	memory := s.runtime.assistanceCommands[row.ID]
	if memory == nil || memory.command.GetRequestId() != result.GetRequestId() {
		return finishAssistanceCommand(ctx, q, &operation, agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_CANCELLED, "command_state_lost", now)
	}
	if !now.Before(operation.Deadline.Time) {
		return finishAssistanceCommand(ctx, q, &operation, agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_EXPIRED, "command_expired", now)
	}
	// Receipt before the server deadline is authoritative. A helper's wall
	// clock cannot backdate late completion or create a future audit time.
	if operation.Kind == int16(agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ) {
		operation.ByteCount = int32(len(result.GetText()))
	}
	if err := finishAssistanceCommand(ctx, q, &operation, result.GetStatus(), result.GetReason(), now); err != nil {
		return err
	}
	memory.result = proto.CloneOf(result)
	memory.result.CompletedAt = timestamppb.New(now)
	return nil
}
