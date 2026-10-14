// SPDX-License-Identifier: Apache-2.0

package assistance

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strconv"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/auditkind"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

// Reconnect workflow contract (docs/architecture.md "Reconnect workflows").
// A workflow remembers only bounded metadata. Every linked invitation repeats
// the complete creation authority and needs fresh local and portal consent;
// nothing from the ended session's grant, portal, relay or DTLS state is reused.
const (
	assistanceReconnectActive  = int16(adminv1.AssistanceReconnectState_ASSISTANCE_RECONNECT_STATE_ACTIVE)
	assistanceReconnectWaiting = int16(adminv1.AssistanceReconnectState_ASSISTANCE_RECONNECT_STATE_WAITING)
	assistanceReconnectEnded   = int16(adminv1.AssistanceReconnectState_ASSISTANCE_RECONNECT_STATE_ENDED)
	assistanceReconnectExpired = int16(adminv1.AssistanceReconnectState_ASSISTANCE_RECONNECT_STATE_EXPIRED)
	// An automatic attempt that found no eligible local user waits this long
	// before the next one, so a logged-out device is not re-invited every sync.
	assistanceReconnectPacing = 30 * time.Second
	// assistanceReconnectAuthorityMargin is the operator authority an
	// automatic invitation must still hold, so the device can sync and renew
	// it before it lapses.
	assistanceReconnectAuthorityMargin = 15 * time.Second
)

// automaticReconnectAuthorityUsable reports whether authority expiring at
// expiresAt leaves an automatic invitation the renewal margin at now.
func automaticReconnectAuthorityUsable(expiresAt, now time.Time) bool {
	return expiresAt.Sub(now) >= assistanceReconnectAuthorityMargin
}

func updateAssistanceReconnect(ctx context.Context, q *devicedb.Queries, workflow devicedb.AssistanceReconnectWorkflow) error {
	return q.UpdateAssistanceReconnectWorkflow(ctx, devicedb.UpdateAssistanceReconnectWorkflowParams{
		ID: workflow.ID, LatestSessionID: workflow.LatestSessionID, Reconnects: workflow.Reconnects, TargetUsername: workflow.TargetUsername,
		Approved: workflow.Approved, State: workflow.State, ExpiresAt: workflow.ExpiresAt, NextAttemptAt: workflow.NextAttemptAt,
		EndedAt: workflow.EndedAt, EndReason: workflow.EndReason,
	})
}

// recordAssistanceReconnectAudit records workflow metadata only. It links the
// sessions by identity and never includes grants or media credentials.
func recordAssistanceReconnectAudit(ctx context.Context, q *devicedb.Queries, actor *uuid.UUID, action auditkind.Kind, workflow devicedb.AssistanceReconnectWorkflow, result, reason string, pairs ...string) error {
	details := core.AuditDetails(append([]string{
		"workflow", workflow.ID.String(), "operator", workflow.OperatorID.String(), "origin_session", workflow.OriginSessionID.String(),
		"latest_session", workflow.LatestSessionID.String(), "mode", assistancePolicyModeName(agentv1.AssistancePolicyMode(workflow.Mode)),
		"reconnects", strconv.Itoa(int(workflow.Reconnects)), "max_reconnects", strconv.Itoa(int(workflow.MaxReconnects)),
		"result", result, "reason", reason,
	}, pairs...)...)
	return core.InsertDetailedAudit(ctx, q, devicedb.InsertAuditEventParams{
		ID: uuid.New(), ActorID: actor, Action: action.String(), ResourceID: workflow.ID.String(), TargetDeviceID: &workflow.DeviceID,
	}, details)
}

func endAssistanceReconnect(ctx context.Context, q *devicedb.Queries, workflow *devicedb.AssistanceReconnectWorkflow, now time.Time, actor *uuid.UUID, reason string) error {
	if workflow.State >= assistanceReconnectEnded {
		return nil
	}
	workflow.State, workflow.EndedAt, workflow.EndReason = assistanceReconnectEnded, core.Timestamptz(now), reason
	workflow.NextAttemptAt.Valid = false
	if err := updateAssistanceReconnect(ctx, q, *workflow); err != nil {
		return err
	}
	return recordAssistanceReconnectAudit(ctx, q, actor, auditkind.AssistanceReconnectEnd, *workflow, "ended", reason)
}

// expireAssistanceReconnect closes a waiting workflow whose window elapsed.
func expireAssistanceReconnect(ctx context.Context, q *devicedb.Queries, workflow *devicedb.AssistanceReconnectWorkflow, now time.Time) (bool, error) {
	if workflow.State != assistanceReconnectWaiting || now.Before(workflow.ExpiresAt.Time) {
		return false, nil
	}
	workflow.State, workflow.EndedAt, workflow.EndReason = assistanceReconnectExpired, core.Timestamptz(now), "window_elapsed"
	workflow.NextAttemptAt.Valid = false
	if err := updateAssistanceReconnect(ctx, q, *workflow); err != nil {
		return false, err
	}
	return true, recordAssistanceReconnectAudit(ctx, q, nil, auditkind.AssistanceReconnectExpire, *workflow, "expired", "window_elapsed")
}

// reconnectEligible reports whether an end is the logout, reboot, lock or lost
// connection that a workflow may resume after. Declines, local or operator
// stops, expiry, policy or authority loss and unavailable capability end it.
func reconnectEligible(cause agentv1.AssistanceEndCause, detail string) bool {
	switch cause {
	case agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED,
		agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_LOCKED,
		agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONNECTION_FAILED:
		return true
	case agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST:
		// A rebooting device stops synchronizing. Lost operator authority or a
		// changed policy is not eligible.
		return detail == "device_unreachable"
	default:
		return false
	}
}

// continueAssistanceReconnect runs when a workflow's latest session ends.
// prior is the session state immediately before the end.
func continueAssistanceReconnect(ctx context.Context, q *devicedb.Queries, row devicedb.AssistanceSession, prior int16, now time.Time) error {
	if row.ReconnectWorkflowID == nil {
		return nil
	}
	workflow, err := q.LockAssistanceReconnectWorkflow(ctx, *row.ReconnectWorkflowID)
	if err != nil {
		return err
	}
	if workflow.State >= assistanceReconnectEnded || workflow.LatestSessionID != row.ID {
		return nil
	}
	cause := agentv1.AssistanceEndCause(row.EndCause)
	absent := cause == agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_NO_ELIGIBLE_SESSION ||
		(cause == agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONSENT_TIMEOUT && prior == assistanceRequested)
	switch {
	case absent && row.ReconnectOf != nil && workflow.Approved && workflow.ExpiresAt.Valid:
		// The target user has not signed in yet: nothing was shown. The
		// attempt is refunded but the original window is not extended.
		workflow.State, workflow.Reconnects = assistanceReconnectWaiting, workflow.Reconnects-1
		workflow.NextAttemptAt = core.Timestamptz(now.Add(assistanceReconnectPacing))
		return updateAssistanceReconnect(ctx, q, workflow)
	case !workflow.Approved:
		return endAssistanceReconnect(ctx, q, &workflow, now, nil, "not_approved")
	case !reconnectEligible(cause, row.EndDetail):
		return endAssistanceReconnect(ctx, q, &workflow, now, nil, assistanceCauseName(cause))
	case workflow.Reconnects >= workflow.MaxReconnects:
		return endAssistanceReconnect(ctx, q, &workflow, now, nil, "max_reconnects")
	}
	workflow.State = assistanceReconnectWaiting
	workflow.ExpiresAt = core.Timestamptz(now.Add(time.Duration(workflow.WindowSeconds) * time.Second))
	workflow.NextAttemptAt = core.Timestamptz(now)
	return updateAssistanceReconnect(ctx, q, workflow)
}

// approveAssistanceReconnect binds the workflow to the consenting account at
// the first consent and audits consent to a linked reconnect.
func approveAssistanceReconnect(ctx context.Context, q *devicedb.Queries, row devicedb.AssistanceSession, grant *agentv1.AssistancePolicy, now time.Time) error {
	if row.ReconnectWorkflowID == nil {
		return nil
	}
	workflow, err := q.LockAssistanceReconnectWorkflow(ctx, *row.ReconnectWorkflowID)
	if err != nil {
		return err
	}
	if workflow.State != assistanceReconnectActive || workflow.LatestSessionID != row.ID {
		return nil
	}
	if !policyEnabled(grant.GetReconnect()) {
		// The device did not admit reconnect (for example an unqualified
		// release): nothing is remembered for this session.
		return endAssistanceReconnect(ctx, q, &workflow, now, nil, "not_granted")
	}
	workflow.Approved = true
	if workflow.TargetUsername == "" {
		workflow.TargetUsername = row.LocalUsername
	}
	if err := updateAssistanceReconnect(ctx, q, workflow); err != nil {
		return err
	}
	if row.ReconnectOf == nil {
		return nil
	}
	return recordAssistanceReconnectAudit(ctx, q, nil, auditkind.AssistanceReconnectConsent, workflow, "accepted", "", "previous_session", row.ReconnectOf.String(), "session", row.ID.String(), "user", row.LocalUsername, "logind_session", row.LocalLogindSession)
}

// assistanceReconnectMessage reports workflow at now. A waiting workflow whose
// window has elapsed reads as expired before the maintenance job or a
// reconnect attempt records it, so the console never offers a reconnect the
// server will refuse (layers-fedora44-reconnect-14 offered one).
func assistanceReconnectMessage(workflow devicedb.AssistanceReconnectWorkflow, now time.Time) *adminv1.AssistanceReconnectWorkflow {
	message := &adminv1.AssistanceReconnectWorkflow{
		Id: workflow.ID.String(), State: adminv1.AssistanceReconnectState(workflow.State), Mode: agentv1.AssistancePolicyMode(workflow.Mode),
		OriginSessionId: workflow.OriginSessionID.String(), LatestSessionId: workflow.LatestSessionID.String(),
		Reconnects: uint32(workflow.Reconnects), MaxReconnects: uint32(workflow.MaxReconnects),
		EndedAt: core.ProtoTime(workflow.EndedAt), EndReason: workflow.EndReason,
	}
	if workflow.ExpiresAt.Valid {
		message.ExpiresAt = timestamppb.New(workflow.ExpiresAt.Time)
		if workflow.State == assistanceReconnectWaiting && !now.Before(workflow.ExpiresAt.Time) {
			message.State, message.EndedAt, message.EndReason = adminv1.AssistanceReconnectState_ASSISTANCE_RECONNECT_STATE_EXPIRED, message.ExpiresAt, "window_elapsed"
		}
	}
	return message
}

// admitAssistanceReconnect checks the locked workflow of a waiting session.
func admitAssistanceReconnect(ctx context.Context, q *devicedb.Queries, workflow *devicedb.AssistanceReconnectWorkflow, previous devicedb.AssistanceSession, now time.Time) error {
	if expired, err := expireAssistanceReconnect(ctx, q, workflow, now); err != nil {
		return err
	} else if expired || workflow.State == assistanceReconnectExpired {
		// A read or the maintenance job may have expired it first; the
		// operator still learns why (layers-ubuntu24-reconnect-11 was told
		// not_waiting for an expired workflow).
		return rpcreason.Error(connect.CodeFailedPrecondition, "assistance_reconnect_expired")
	}
	switch {
	case workflow.State != assistanceReconnectWaiting || workflow.LatestSessionID != previous.ID || previous.State != assistanceEnded:
		return rpcreason.Error(connect.CodeFailedPrecondition, "assistance_reconnect_not_waiting")
	case workflow.Reconnects >= workflow.MaxReconnects:
		return rpcreason.Error(connect.CodeFailedPrecondition, "assistance_reconnect_exhausted")
	}
	return nil
}

func reconnectRequested(previous devicedb.AssistanceSession) *agentv1.AssistancePolicy {
	return decodeAssistancePolicy(previous.RequestedCapabilities)
}

// ReconnectAssistanceSession lets the creating operator resume a waiting
// workflow with a fresh linked invitation. It repeats Create's authority.
func (s *Service) ReconnectAssistanceSession(ctx context.Context, req *connect.Request[adminv1.ReconnectAssistanceSessionRequest]) (*connect.Response[adminv1.ReconnectAssistanceSessionResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	if _, err := s.Require(ctx, identity.PermissionViewRemoteAssistance); err != nil {
		return nil, err
	}
	if _, err := s.Require(ctx, identity.PermissionAssistanceReconnect); err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_assistance_reconnect")
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
	requestID, _ := uuid.Parse(req.Msg.GetRequestId())
	previousID, _ := uuid.Parse(req.Msg.GetSessionId())
	var session *adminv1.AssistanceSession
	err = s.assistanceTx(ctx, authorization, identity.PermissionViewRemoteAssistance, func(q *devicedb.Queries, revoked *assistanceRevocations) error {
		previous, err := s.lockAssistanceInScope(ctx, q, authorization.Principal(), identity.PermissionViewRemoteAssistance, previousID, true)
		if err != nil {
			return err
		}
		now := s.Now()
		if old, err := q.GetAssistanceSessionByRequest(ctx, requestID); err == nil {
			if old.OperatorID != actor.ID || !bytes.Equal(old.RequestDigest, digest) || old.ReconnectOf == nil || *old.ReconnectOf != previous.ID {
				return core.ErrIdempotencyConflict
			}
			if err := enforceAssistance(ctx, q, &old, now, revoked); err != nil {
				return err
			}
			session, err = s.assistanceSessionMessage(ctx, q, old)
			return err
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err := enforceAssistance(ctx, q, &previous, now, revoked); err != nil {
			return err
		}
		deny := func(workflow *devicedb.AssistanceReconnectWorkflow, reason string, denied error) error {
			if workflow != nil {
				if err := recordAssistanceReconnectAudit(ctx, q, &actor.ID, auditkind.AssistanceReconnectRequest, *workflow, "denied", reason, "previous_session", previous.ID.String()); err != nil {
					return err
				}
			}
			return denied
		}
		if previous.ReconnectWorkflowID == nil {
			return rpcreason.Error(connect.CodeFailedPrecondition, "assistance_reconnect_unavailable")
		}
		workflow, err := q.LockAssistanceReconnectWorkflow(ctx, *previous.ReconnectWorkflowID)
		if err != nil {
			return err
		}
		if previous.OperatorID != actor.ID || workflow.OperatorID != actor.ID {
			return deny(&workflow, "not_creator", rpcreason.Error(connect.CodePermissionDenied, "assistance_not_creator"))
		}
		requested := reconnectRequested(previous)
		if err := scopeAssistanceCapabilities(ctx, q, authorization.Principal(), previous.DeviceID, agentv1.AssistanceMode(previous.Mode), requested); err != nil {
			if endErr := endAssistanceReconnect(ctx, q, &workflow, now, &actor.ID, "operator_scope_lost"); endErr != nil {
				return endErr
			}
			return deny(&workflow, "operator_scope_lost", err)
		}
		if err := admitAssistanceReconnect(ctx, q, &workflow, previous, now); err != nil {
			return deny(&workflow, rpcreason.Get(err), err)
		}
		device, err := q.GetDeviceForUpdate(ctx, previous.DeviceID)
		if err != nil {
			return err
		}
		if device.State != core.StateActive || device.CurrentGenerationID == nil || !device.LastSeenAt.Valid || now.Sub(device.LastSeenAt.Time) > assistanceOnlineWindow {
			return deny(&workflow, "device_offline", rpcreason.Error(connect.CodeFailedPrecondition, "device_offline"))
		}
		row, err := s.issueAssistanceInvitation(ctx, q, assistanceInvitation{
			requestID: requestID, digest: digest, deviceID: previous.DeviceID, generationID: *device.CurrentGenerationID,
			operatorID: actor.ID, display: assistanceOperatorLabel(actor), mode: agentv1.AssistanceMode(previous.Mode), reason: previous.Reason,
			target: workflow.TargetUsername, requested: requested, duration: previous.EndsAt.Time.Sub(previous.CreatedAt.Time),
			authorizedUntil: authorization.ExpiresAt(), actor: &actor.ID, workflow: &workflow,
		}, now, revoked)
		var domain *connect.Error
		if errors.As(err, &domain) {
			if reason := rpcreason.Get(err); reason == "assistance_reconnect_not_permitted" || reason == "assistance_recording_not_permitted" || reason == "assistance_recording_unavailable" {
				if endErr := endAssistanceReconnect(ctx, q, &workflow, now, &actor.ID, "policy_changed"); endErr != nil {
					return endErr
				}
			}
			return deny(&workflow, rpcreason.Get(err), err)
		}
		if err != nil {
			return err
		}
		session, err = s.assistanceSessionMessage(ctx, q, row)
		return err
	})
	if err != nil {
		return nil, err
	}
	return core.NoStore(&adminv1.ReconnectAssistanceSessionResponse{Session: session}), nil
}

// assistanceReconnectObservation is the fresh operator authority for an
// automatic reconnect, observed before any SQL lock like session authority.
type assistanceReconnectObservation struct {
	device        uuid.UUID
	workflow      uuid.UUID
	authorization *identity.Authorization
}

func (s *Service) observeAssistanceReconnect(ctx context.Context, deviceID uuid.UUID, now time.Time) (assistanceReconnectObservation, error) {
	if s.Identity == nil || s.Assistance == nil {
		return assistanceReconnectObservation{}, nil
	}
	workflow, err := devicedb.New(s.Pool).GetAutomaticAssistanceReconnect(ctx, devicedb.GetAutomaticAssistanceReconnectParams{DeviceID: deviceID, Now: core.Timestamptz(now)})
	if errors.Is(err, pgx.ErrNoRows) {
		return assistanceReconnectObservation{}, nil
	}
	if err != nil {
		return assistanceReconnectObservation{}, err
	}
	authorization, err := s.Identity.AuthorizeFresh(ctx, workflow.OperatorID, identity.PermissionViewRemoteAssistance)
	if err != nil {
		// Missing authority ends the workflow inside the sync transaction.
		authorization = nil
	}
	return assistanceReconnectObservation{device: deviceID, workflow: workflow.ID, authorization: authorization}, nil
}

// automaticAssistanceReconnect issues the remembered invitation of an ON
// workflow when its device synchronizes with no open session. The invitation
// is still only a prompt: no screen or input exists before fresh consent.
func (s *Service) automaticAssistanceReconnect(ctx context.Context, tx pgx.Tx, q *devicedb.Queries, observed assistanceReconnectObservation, generation uuid.UUID, now time.Time, revoked *assistanceRevocations) (bool, error) {
	if observed.workflow == uuid.Nil {
		return false, nil
	}
	if _, err := q.LockOpenAssistanceSession(ctx, observed.device); err == nil {
		return false, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	workflow, err := q.LockAssistanceReconnectWorkflow(ctx, observed.workflow)
	if err != nil {
		return false, err
	}
	if workflow.Mode != int16(agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON) || (workflow.NextAttemptAt.Valid && now.Before(workflow.NextAttemptAt.Time)) {
		return false, nil
	}
	previous, err := q.LockAssistanceSession(ctx, workflow.LatestSessionID)
	if err != nil {
		return false, err
	}
	if err := admitAssistanceReconnect(ctx, q, &workflow, previous, now); err != nil {
		var domain *connect.Error
		if errors.As(err, &domain) {
			return false, nil
		}
		return false, err
	}
	authorization := observed.authorization
	if authorization == nil || authorization.ActorID() != workflow.OperatorID {
		return false, endAssistanceReconnect(ctx, q, &workflow, now, nil, "operator_authorization_lost")
	}
	if !automaticReconnectAuthorityUsable(authorization.ExpiresAt(), now) {
		// The authority was observed before this sync's transaction and is
		// nearly spent: an invitation issued with it lapsed two seconds later,
		// before the rebooted device could sync again (layers-fedora44-
		// reconnect-13). The next sync observes authority afresh.
		return false, nil
	}
	if err := s.Identity.LockAuthorization(ctx, tx, authorization, identity.PermissionViewRemoteAssistance); err != nil {
		if errors.Is(err, identity.ErrAuthorizationDenied) || errors.Is(err, identity.ErrAuthorizationChanged) {
			// The next sync observes authority afresh.
			return false, nil
		}
		return false, core.ExecutionError(err)
	}
	requested := reconnectRequested(previous)
	if err := scopeAssistanceCapabilities(ctx, q, authorization.Principal(), previous.DeviceID, agentv1.AssistanceMode(previous.Mode), requested); err != nil {
		return false, endAssistanceReconnect(ctx, q, &workflow, now, nil, "operator_scope_lost")
	}
	effective, err := s.currentAssistancePolicy(ctx, q, previous.DeviceID, requested)
	if err != nil {
		return false, err
	}
	if effective.GetReconnect() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON {
		// Policy no longer remembers workflows: the operator may still issue a
		// LIMITED reconnect explicitly, but nothing is issued automatically.
		if !policyEnabled(effective.GetReconnect()) {
			return false, endAssistanceReconnect(ctx, q, &workflow, now, nil, "policy_changed")
		}
		return false, nil
	}
	requestID := uuid.New()
	slog.Info("assistance reconnect issued automatically", "workflow_id", workflow.ID, "previous_session_id", previous.ID, "now", now, "authorized_until", authorization.ExpiresAt())
	digest, err := core.ActionDigest(&adminv1.ReconnectAssistanceSessionRequest{RequestId: requestID.String(), SessionId: previous.ID.String()})
	if err != nil {
		return false, err
	}
	_, err = s.issueAssistanceInvitation(ctx, q, assistanceInvitation{
		requestID: requestID, digest: digest, deviceID: previous.DeviceID, generationID: generation,
		operatorID: workflow.OperatorID, display: previous.OperatorDisplay, mode: agentv1.AssistanceMode(previous.Mode), reason: previous.Reason,
		target: workflow.TargetUsername, requested: requested, duration: previous.EndsAt.Time.Sub(previous.CreatedAt.Time),
		authorizedUntil: authorization.ExpiresAt(), workflow: &workflow,
	}, now, revoked)
	var domain *connect.Error
	if errors.As(err, &domain) {
		reason := rpcreason.Get(err)
		if reason == "assistance_busy" || reason == "assistance_capacity" {
			workflow.NextAttemptAt = core.Timestamptz(now.Add(assistanceReconnectPacing))
			return false, updateAssistanceReconnect(ctx, q, workflow)
		}
		return false, endAssistanceReconnect(ctx, q, &workflow, now, nil, "policy_changed")
	}
	return err == nil, err
}

// currentAssistancePolicy is the policy a fresh invitation would receive now.
func (s *Service) currentAssistancePolicy(ctx context.Context, q *devicedb.Queries, deviceID uuid.UUID, requested *agentv1.AssistancePolicy) (*agentv1.AssistancePolicy, error) {
	policy, err := loadAssistancePolicy(ctx, q, deviceID)
	if err != nil {
		return nil, err
	}
	_, effective := assistanceInvitationPolicies(requested, intersectAssistancePolicy(policy, s.AssistanceCeiling))
	return effective, nil
}
