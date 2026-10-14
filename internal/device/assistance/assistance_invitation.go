// SPDX-License-Identifier: Apache-2.0

package assistance

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/assistancerecording"
	"lindm/internal/auditkind"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
	"lindm/internal/rpcreason"
)

// assistanceInvitation is one admitted request for a fresh consent prompt:
// an operator's original invitation or a linked reconnect of a workflow.
type assistanceInvitation struct {
	requestID       uuid.UUID
	digest          []byte
	deviceID        uuid.UUID
	generationID    uuid.UUID
	operatorID      uuid.UUID
	display         string
	mode            agentv1.AssistanceMode
	reason          string
	target          string
	requested       *agentv1.AssistancePolicy
	duration        time.Duration
	authorizedUntil time.Time
	// actor is nil only for an automatic reconnect issued by device sync.
	actor *uuid.UUID
	// workflow is the locked waiting workflow this invitation continues.
	workflow *devicedb.AssistanceReconnectWorkflow
	// unattended is the admitted grant and opt-in of an unattended connection.
	unattended *unattendedAdmission
}

func policyEnabled(mode agentv1.AssistancePolicyMode) bool {
	return assistanceMode(mode) > agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
}

// issueAssistanceInvitation admits and inserts one invitation in the caller's
// transaction. The caller has already applied operator, scope and device
// online checks; this applies the device-wide admission, the effective policy
// and the recording and reconnect bindings shared by every invitation path.
func (s *Service) issueAssistanceInvitation(ctx context.Context, q *devicedb.Queries, inv assistanceInvitation, now time.Time, revoked *assistanceRevocations) (devicedb.AssistanceSession, error) {
	var none devicedb.AssistanceSession
	if err := enforceOpenAssistance(ctx, q, inv.deviceID, now, revoked); err != nil {
		return none, err
	}
	if _, err := q.LockOpenAssistanceSession(ctx, inv.deviceID); err == nil {
		return none, rpcreason.Error(connect.CodeFailedPrecondition, "assistance_busy")
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return none, err
	}
	if err := q.LockAssistanceAdmission(ctx); err != nil {
		return none, err
	}
	live, err := q.CountLiveAssistanceSessions(ctx, devicedb.CountLiveAssistanceSessionsParams{Now: core.Timestamptz(now), UnreachableBefore: core.Timestamptz(now.Add(-assistanceUnreachable))})
	if err != nil {
		return none, err
	}
	if live >= int64(s.Assistance.MaxSessions()) {
		return none, rpcreason.Error(connect.CodeFailedPrecondition, "assistance_capacity")
	}
	policy, err := loadAssistancePolicy(ctx, q, inv.deviceID)
	if err != nil {
		return none, err
	}
	requestedPolicy, effectivePolicy := assistanceInvitationPolicies(inv.requested, intersectAssistancePolicy(policy, s.AssistanceCeiling))
	required := assistancerecording.Required(requestedPolicy.GetRecording(), effectivePolicy.GetRecording())
	if requestedPolicy.GetRecording() == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON && !required {
		// Required recording is never silently downgraded to optional.
		return none, rpcreason.Error(connect.CodeFailedPrecondition, "assistance_recording_not_permitted")
	}
	recording := policyEnabled(effectivePolicy.GetRecording())
	if recording && s.AssistanceRecording == nil {
		return none, rpcreason.Error(connect.CodeFailedPrecondition, "assistance_recording_unavailable")
	}
	if inv.workflow != nil && !policyEnabled(effectivePolicy.GetReconnect()) {
		return none, rpcreason.Error(connect.CodeFailedPrecondition, "assistance_reconnect_not_permitted")
	}
	if inv.unattended != nil {
		// Nobody attends an unattended connection to opt in to anything.
		if effectivePolicy.GetRecording() == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED && !required {
			return none, rpcreason.Error(connect.CodeFailedPrecondition, "assistance_unattended_optional_recording")
		}
		effectivePolicy.Unattended, effectivePolicy.UnattendedLimits = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF, nil
		effectivePolicy.Reconnect, effectivePolicy.ReconnectLimits = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF, nil
	} else if policyEnabled(effectivePolicy.GetUnattended()) && policyEnabled(effectivePolicy.GetRecording()) && !required {
		// The prompt offers one opt-in choice at a time: optional recording
		// and the unattended opt-in would need more actions than desktops show.
		return none, rpcreason.Error(connect.CodeFailedPrecondition, "assistance_unattended_enrollment_conflict")
	}
	if inv.workflow == nil {
		// An unrelated invitation supersedes a remembered workflow; one
		// device never has two workflows that could re-prompt its user.
		open, err := q.LockOpenAssistanceReconnectWorkflow(ctx, inv.deviceID)
		if err == nil {
			if err := endAssistanceReconnect(ctx, q, &open, now, inv.actor, "superseded"); err != nil {
				return none, err
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return none, err
		}
	}
	requested, err := proto.Marshal(requestedPolicy)
	if err != nil {
		return none, err
	}
	effective, err := proto.Marshal(effectivePolicy)
	if err != nil {
		return none, err
	}
	id := uuid.New()
	if err := q.InsertAssistanceSession(ctx, devicedb.InsertAssistanceSessionParams{
		ID: id, DeviceID: inv.deviceID, GenerationID: inv.generationID, RequestID: inv.requestID, RequestDigest: inv.digest,
		OperatorID: inv.operatorID, OperatorDisplay: inv.display, Mode: int16(inv.mode), Reason: inv.reason,
		TargetUsername: inv.target, CreatedAt: core.Timestamptz(now),
		ConsentDeadline: core.Timestamptz(now.Add(assistanceConsentWindow)), EndsAt: core.Timestamptz(now.Add(inv.duration)),
	}); err != nil {
		return none, err
	}
	if err := q.SetAssistanceCapabilities(ctx, devicedb.SetAssistanceCapabilitiesParams{ID: id, RequestedCapabilities: requested, EffectiveCapabilities: effective}); err != nil {
		return none, err
	}
	if err := q.AuthorizeAssistanceSession(ctx, devicedb.AuthorizeAssistanceSessionParams{ID: id, AuthorizedUntil: core.Timestamptz(inv.authorizedUntil)}); err != nil {
		return none, err
	}
	if inv.unattended != nil {
		if err := q.SetAssistanceUnattended(ctx, devicedb.SetAssistanceUnattendedParams{ID: id, UnattendedGrantID: &inv.unattended.grant.ID, UnattendedEnrollmentID: &inv.unattended.enrollment.ID}); err != nil {
			return none, err
		}
	} else if err := offerUnattendedEnrollment(ctx, q, id, inv.deviceID, inv.mode, effectivePolicy, now); err != nil {
		return none, err
	}
	recordingMode, err := s.bindAssistanceWorkflow(ctx, q, inv, id, effectivePolicy, required, now)
	if err != nil {
		return none, err
	}
	row, err := q.GetAssistanceSession(ctx, id)
	if err != nil {
		return none, err
	}
	pairs := []string{"target", inv.target, "recording", recordingMode, "reconnect", assistancePolicyModeName(effectivePolicy.GetReconnect()), "unattended_offer", assistancePolicyModeName(effectivePolicy.GetUnattended())}
	if inv.unattended != nil {
		pairs = append(pairs, "unattended_grant", inv.unattended.grant.ID.String(), "unattended_enrollment", inv.unattended.enrollment.ID.String())
	}
	if inv.workflow != nil {
		pairs = append(pairs, "reconnect_of", row.ReconnectOf.String())
	}
	if err := recordAssistanceAudit(ctx, q, inv.actor, auditkind.AssistanceRequest, row, inv.reason, pairs...); err != nil {
		return none, err
	}
	if inv.workflow != nil {
		automatic := "false"
		if inv.actor == nil {
			automatic = "true"
		}
		if err := recordAssistanceReconnectAudit(ctx, q, inv.actor, auditkind.AssistanceReconnectRequest, *inv.workflow, "issued", "", "previous_session", row.ReconnectOf.String(), "session", row.ID.String(), "automatic", automatic); err != nil {
			return none, err
		}
	}
	return row, nil
}

// bindAssistanceWorkflow creates the session's recording authority and links
// it to a new or continued reconnect workflow. It returns the audited
// recording mode.
func (s *Service) bindAssistanceWorkflow(ctx context.Context, q *devicedb.Queries, inv assistanceInvitation, id uuid.UUID, effectivePolicy *agentv1.AssistancePolicy, required bool, now time.Time) (string, error) {
	recording := policyEnabled(effectivePolicy.GetRecording())
	recordingMode := "off"
	if recording {
		limits := effectivePolicy.GetRecordingLimits()
		recordingMode = "optional"
		if required {
			recordingMode = "required"
		}
		if err := q.InsertAssistanceRecording(ctx, devicedb.InsertAssistanceRecordingParams{
			ID: uuid.New(), SessionID: id, DeviceID: inv.deviceID, OperatorID: inv.operatorID, Required: required,
			KeyID: s.AssistanceRecording.KeyID(), MaxBytes: int64(limits.GetMaxBytes()), RetentionDays: int16(limits.GetRetentionDays()), CreatedAt: core.Timestamptz(now),
		}); err != nil {
			return "", err
		}
	}
	switch {
	case inv.workflow != nil:
		previous := inv.workflow.LatestSessionID
		if err := q.SetAssistanceReconnect(ctx, devicedb.SetAssistanceReconnectParams{ID: id, ReconnectWorkflowID: &inv.workflow.ID, ReconnectOf: &previous}); err != nil {
			return "", err
		}
		inv.workflow.LatestSessionID, inv.workflow.Reconnects, inv.workflow.State = id, inv.workflow.Reconnects+1, assistanceReconnectActive
		inv.workflow.NextAttemptAt = core.Timestamptz(now.Add(assistanceReconnectPacing))
		if err := updateAssistanceReconnect(ctx, q, *inv.workflow); err != nil {
			return "", err
		}
	case policyEnabled(effectivePolicy.GetReconnect()):
		workflow := uuid.New()
		limits := effectivePolicy.GetReconnectLimits()
		if err := q.InsertAssistanceReconnectWorkflow(ctx, devicedb.InsertAssistanceReconnectWorkflowParams{
			ID: workflow, DeviceID: inv.deviceID, OperatorID: inv.operatorID, OriginSessionID: id, Mode: int16(effectivePolicy.GetReconnect()),
			WindowSeconds: int32(limits.GetWindowSeconds()), MaxReconnects: int16(limits.GetMaxReconnects()), TargetUsername: inv.target, CreatedAt: core.Timestamptz(now),
		}); err != nil {
			return "", err
		}
		if err := q.SetAssistanceReconnect(ctx, devicedb.SetAssistanceReconnectParams{ID: id, ReconnectWorkflowID: &workflow}); err != nil {
			return "", err
		}
	}
	return recordingMode, nil
}

// assistanceSessionMessage adds the bounded workflow and recording metadata.
// Neither carries content, keys or retrieval authority.
func (s *Service) assistanceSessionMessage(ctx context.Context, q *devicedb.Queries, row devicedb.AssistanceSession) (*adminv1.AssistanceSession, error) {
	session := assistanceMessage(row)
	if row.ReconnectOf != nil {
		session.ReconnectOf = row.ReconnectOf.String()
	}
	if row.ReconnectWorkflowID != nil {
		workflow, err := q.GetAssistanceReconnectWorkflow(ctx, *row.ReconnectWorkflowID)
		if err != nil {
			return nil, err
		}
		session.Reconnect = assistanceReconnectMessage(workflow, s.Now())
	}
	recording, err := q.GetAssistanceRecordingBySession(ctx, row.ID)
	if err == nil {
		session.Recording = assistanceRecordingMessage(recording)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if session.Unattended, err = unattendedConnectionMessage(ctx, q, row); err != nil {
		return nil, err
	}
	if row.UnattendedGrantID == nil {
		offer, err := q.GetAssistanceUnattendedEnrollmentBySession(ctx, row.ID)
		if err == nil {
			session.UnattendedEnrollmentId = offer.ID.String()
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
	}
	return session, nil
}
