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
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/assistanceunattended"
	"lindm/internal/auditkind"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

// Unattended access (docs/architecture.md §9, Tier 3). A connection needs, all
// at once: an unexpired grant consumed from an approval a different person
// decided, the requesting operator's fresh scoped permissions, non-off device
// policy at least as permissive as the grant, a schedule window, and the
// opted-in user's in-force local enrollment. The device independently needs
// the user's own opt-in record, an unlocked session of that UID, a visible
// banner with Stop and the desktop's persistent portal grant.
const (
	enrollmentOffered  = int16(0)
	enrollmentEnrolled = int16(1)
	enrollmentRevoked  = int16(2)
	enrollmentDeclined = int16(3)
)

func unattendedGrantState(row devicedb.AssistanceUnattendedGrant, now time.Time) adminv1.AssistanceUnattendedGrantState {
	switch {
	case row.RevokedAt.Valid:
		return adminv1.AssistanceUnattendedGrantState_ASSISTANCE_UNATTENDED_GRANT_STATE_REVOKED
	case !now.Before(row.NotAfter.Time):
		return adminv1.AssistanceUnattendedGrantState_ASSISTANCE_UNATTENDED_GRANT_STATE_EXPIRED
	default:
		return adminv1.AssistanceUnattendedGrantState_ASSISTANCE_UNATTENDED_GRANT_STATE_ACTIVE
	}
}

func decodeUnattendedSchedule(data []byte) *agentv1.AssistanceUnattendedSchedule {
	if len(data) == 0 {
		return nil
	}
	schedule := &agentv1.AssistanceUnattendedSchedule{}
	if proto.Unmarshal(data, schedule) != nil {
		// A corrupt schedule never widens to "always".
		return &agentv1.AssistanceUnattendedSchedule{TimeZone: "invalid"}
	}
	return schedule
}

func unattendedGrantMessage(row devicedb.AssistanceUnattendedGrant, operator, approver string, now time.Time) *adminv1.AssistanceUnattendedGrant {
	grant := &adminv1.AssistanceUnattendedGrant{
		Id: row.ID.String(), DeviceId: row.DeviceID.String(), OperatorId: row.OperatorID.String(), OperatorDisplay: operator,
		ApproverId: row.ApproverID.String(), ApproverDisplay: approver, ApprovalId: row.ApprovalID.String(),
		Mode: agentv1.AssistanceMode(row.Mode), Reason: row.Reason, TargetUsername: row.TargetUsername,
		NotBefore: core.ProtoTime(row.NotBefore), NotAfter: core.ProtoTime(row.NotAfter), Schedule: decodeUnattendedSchedule(row.Schedule),
		RequestedCapabilities: decodeAssistancePolicy(row.RequestedCapabilities), State: unattendedGrantState(row, now),
		CreatedAt: core.ProtoTime(row.CreatedAt), RevokedAt: core.ProtoTime(row.RevokedAt), RevokeReason: row.RevokeReason,
		PolicyMode: agentv1.AssistancePolicyMode(row.PolicyMode),
	}
	return grant
}

func unattendedEnrollmentMessage(row devicedb.AssistanceUnattendedEnrollment, now time.Time) *adminv1.AssistanceUnattendedEnrollment {
	enrollment := &adminv1.AssistanceUnattendedEnrollment{
		Id: row.ID.String(), DeviceId: row.DeviceID.String(), Username: row.Username, Uid: uint32(row.Uid),
		Mode: agentv1.AssistanceMode(row.Mode), ConsentSessionId: row.SessionID.String(), ConsentedAt: core.ProtoTime(row.ConsentedAt),
		ExpiresAt: core.ProtoTime(row.ExpiresAt), RevokedAt: core.ProtoTime(row.RevokedAt), RevokeReason: row.RevokeReason,
	}
	switch {
	case row.State == enrollmentRevoked:
		enrollment.State = adminv1.AssistanceUnattendedEnrollmentStatus_ASSISTANCE_UNATTENDED_ENROLLMENT_STATUS_REVOKED
	case !now.Before(row.ExpiresAt.Time):
		enrollment.State = adminv1.AssistanceUnattendedEnrollmentStatus_ASSISTANCE_UNATTENDED_ENROLLMENT_STATUS_EXPIRED
	case row.State == enrollmentEnrolled:
		enrollment.State = adminv1.AssistanceUnattendedEnrollmentStatus_ASSISTANCE_UNATTENDED_ENROLLMENT_STATUS_ENROLLED
	}
	return enrollment
}

func recordUnattendedGrantAudit(ctx context.Context, q *devicedb.Queries, actor *uuid.UUID, action auditkind.Kind, grant devicedb.AssistanceUnattendedGrant, result, reason string, pairs ...string) error {
	details := core.AuditDetails(append([]string{
		"grant", grant.ID.String(), "approval", grant.ApprovalID.String(), "operator", grant.OperatorID.String(), "approver", grant.ApproverID.String(),
		"mode", assistanceModeName(grant.Mode), "policy", assistancePolicyModeName(agentv1.AssistancePolicyMode(grant.PolicyMode)),
		"target", grant.TargetUsername, "not_before", grant.NotBefore.Time.UTC().Format(time.RFC3339), "not_after", grant.NotAfter.Time.UTC().Format(time.RFC3339),
		"scheduled", boolText(len(grant.Schedule) != 0), "result", result,
	}, pairs...)...)
	return core.InsertDetailedAudit(ctx, q, devicedb.InsertAuditEventParams{
		ID: uuid.New(), ActorID: actor, Action: action.String(), ResourceID: grant.ID.String(), Reason: reason, TargetDeviceID: &grant.DeviceID,
	}, details)
}

func recordUnattendedEnrollmentAudit(ctx context.Context, q *devicedb.Queries, actor *uuid.UUID, action auditkind.Kind, enrollment devicedb.AssistanceUnattendedEnrollment, result, reason string) error {
	details := core.AuditDetails("enrollment", enrollment.ID.String(), "session", enrollment.SessionID.String(), "mode", assistanceModeName(enrollment.Mode),
		"user", enrollment.Username, "result", result, "reason", reason, "expires_at", enrollment.ExpiresAt.Time.UTC().Format(time.RFC3339))
	return core.InsertDetailedAudit(ctx, q, devicedb.InsertAuditEventParams{
		ID: uuid.New(), ActorID: actor, Action: action.String(), ResourceID: enrollment.ID.String(), TargetDeviceID: &enrollment.DeviceID,
	}, details)
}

// revokeUnattendedGrant ends a grant and any open connection relying on it.
func revokeUnattendedGrant(ctx context.Context, q *devicedb.Queries, grant *devicedb.AssistanceUnattendedGrant, now time.Time, actor *uuid.UUID, reason string, revoked *assistanceRevocations) error {
	if grant.RevokedAt.Valid {
		return nil
	}
	if err := q.RevokeAssistanceUnattendedGrant(ctx, devicedb.RevokeAssistanceUnattendedGrantParams{ID: grant.ID, RevokedAt: core.Timestamptz(now), RevokedBy: actor, RevokeReason: reason}); err != nil {
		return err
	}
	grant.RevokedAt, grant.RevokedBy, grant.RevokeReason = core.Timestamptz(now), actor, reason
	if err := recordUnattendedGrantAudit(ctx, q, actor, auditkind.AssistanceUnattendedRevoke, *grant, "revoked", reason); err != nil {
		return err
	}
	return endUnattendedConnection(ctx, q, grant.DeviceID, func(row devicedb.AssistanceSession) bool {
		return row.UnattendedGrantID != nil && *row.UnattendedGrantID == grant.ID
	}, now, actor, "unattended_grant_revoked", revoked)
}

// revokeUnattendedEnrollment withdraws the server's record of a local opt-in.
// The device refuses any later connection naming it.
func revokeUnattendedEnrollment(ctx context.Context, q *devicedb.Queries, enrollment *devicedb.AssistanceUnattendedEnrollment, now time.Time, actor *uuid.UUID, reason string, revoked *assistanceRevocations) error {
	if enrollment.State != enrollmentEnrolled {
		return nil
	}
	if err := q.RevokeAssistanceUnattendedEnrollment(ctx, devicedb.RevokeAssistanceUnattendedEnrollmentParams{ID: enrollment.ID, RevokedAt: core.Timestamptz(now), Reason: reason}); err != nil {
		return err
	}
	enrollment.State, enrollment.RevokedAt, enrollment.RevokeReason = enrollmentRevoked, core.Timestamptz(now), reason
	if err := recordUnattendedEnrollmentAudit(ctx, q, actor, auditkind.AssistanceUnattendedRevoke, *enrollment, "revoked", reason); err != nil {
		return err
	}
	return endUnattendedConnection(ctx, q, enrollment.DeviceID, func(row devicedb.AssistanceSession) bool {
		return row.UnattendedEnrollmentID != nil && *row.UnattendedEnrollmentID == enrollment.ID
	}, now, actor, "unattended_enrollment_revoked", revoked)
}

func endUnattendedConnection(ctx context.Context, q *devicedb.Queries, deviceID uuid.UUID, matches func(devicedb.AssistanceSession) bool, now time.Time, actor *uuid.UUID, detail string, revoked *assistanceRevocations) error {
	row, err := q.LockOpenAssistanceSession(ctx, deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !matches(row) {
		return nil
	}
	return endAssistance(ctx, q, &row, now, actor, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, detail, false, revoked)
}

// revokeUnattendedForPolicy withdraws grants the new effective policy no longer
// permits: every grant when off, scheduled (ON) grants under limited. Local
// opt-ins end with an off policy; the employee opts in again if re-enabled.
func revokeUnattendedForPolicy(ctx context.Context, q *devicedb.Queries, deviceID uuid.UUID, mode agentv1.AssistancePolicyMode, now time.Time, actor *uuid.UUID, revoked *assistanceRevocations) error {
	grants, err := q.LockLiveAssistanceUnattendedGrants(ctx, devicedb.LockLiveAssistanceUnattendedGrantsParams{DeviceID: deviceID, Now: core.Timestamptz(now)})
	if err != nil {
		return err
	}
	for i := range grants {
		if agentv1.AssistancePolicyMode(grants[i].PolicyMode) > mode {
			if err := revokeUnattendedGrant(ctx, q, &grants[i], now, actor, "policy_changed", revoked); err != nil {
				return err
			}
		}
	}
	if policyEnabled(mode) {
		return nil
	}
	enrollments, err := q.LockEnrolledAssistanceUnattendedForDevice(ctx, deviceID)
	if err != nil {
		return err
	}
	for i := range enrollments {
		if err := revokeUnattendedEnrollment(ctx, q, &enrollments[i], now, actor, "policy_changed", revoked); err != nil {
			return err
		}
	}
	return nil
}

// AuthorizeUnattendedAssistance consumes an approval decided by a different
// person and records the grant in the same transaction.
func (s *Service) AuthorizeUnattendedAssistance(ctx context.Context, req *connect.Request[adminv1.AuthorizeUnattendedAssistanceRequest]) (*connect.Response[adminv1.AuthorizeUnattendedAssistanceResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionAssistanceUnattended)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil || core.HasNUL(req.Msg.GetReason()) {
		return nil, core.Invalid("invalid_assistance_unattended")
	}
	if req.Msg.GetApprovalId() == "" {
		return nil, core.ApprovalError(identity.ErrApprovalRequired)
	}
	if s.Identity == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	if s.Assistance == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "assistance_unconfigured")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	payload := proto.CloneOf(req.Msg)
	payload.ApprovalId = ""
	approvalID, _ := uuid.Parse(req.Msg.GetApprovalId())
	pair, err := s.Identity.PrepareApprovalConsumption(ctx, actor.ID, approvalID, payload)
	if err != nil {
		return nil, core.ApprovalError(err)
	}
	digest, err := core.ActionDigest(payload)
	if err != nil {
		return nil, core.MapErr(err)
	}
	requestID, _ := uuid.Parse(payload.GetRequestId())
	var grant *adminv1.AssistanceUnattendedGrant
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.Identity.LockAndConsumeApproval(ctx, tx, pair, s.ApprovalScope); err != nil {
		return nil, core.ApprovalError(err)
	}
	q := devicedb.New(tx)
	requester := pair.Requester().Principal()
	now := s.Now()
	row, err := q.GetAssistanceUnattendedGrantByRequest(ctx, requestID)
	switch {
	case err == nil:
		if row.OperatorID != actor.ID || row.ApprovalID != approvalID || !bytes.Equal(row.RequestDigest, digest) {
			return nil, core.MapErr(core.ErrIdempotencyConflict)
		}
	case errors.Is(err, pgx.ErrNoRows):
		row, err = s.insertUnattendedGrant(ctx, q, requester, pair.Approver().ActorID(), approvalID, requestID, digest, payload, now)
		if err != nil {
			return nil, err
		}
	default:
		return nil, core.MapErr(err)
	}
	view, err := q.GetAssistanceUnattendedGrantView(ctx, row.ID)
	if err != nil {
		return nil, core.MapErr(err)
	}
	grant = unattendedGrantMessage(view.AssistanceUnattendedGrant, view.OperatorDisplay, view.ApproverDisplay, now)
	if err := tx.Commit(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	return core.NoStore(&adminv1.AuthorizeUnattendedAssistanceResponse{Grant: grant}), nil
}

func (s *Service) insertUnattendedGrant(ctx context.Context, q *devicedb.Queries, requester identity.Principal, approver, approvalID, requestID uuid.UUID, digest []byte, request *adminv1.AuthorizeUnattendedAssistanceRequest, now time.Time) (devicedb.AssistanceUnattendedGrant, error) {
	var none devicedb.AssistanceUnattendedGrant
	deviceID, _ := uuid.Parse(request.GetDeviceId())
	device, err := core.LockDeviceScope(ctx, q, requester, identity.PermissionAssistanceUnattended, deviceID)
	if err != nil {
		return none, core.MapErr(err)
	}
	if device.State != core.StateActive {
		return none, rpcreason.Error(connect.CodeFailedPrecondition, "device_inactive")
	}
	stored, err := loadAssistancePolicy(ctx, q, deviceID)
	if err != nil {
		return none, core.MapErr(err)
	}
	policy := intersectAssistancePolicy(stored, s.AssistanceCeiling)
	mode, limits := policy.GetUnattended(), policy.GetUnattendedLimits()
	if !policyEnabled(mode) || limits == nil {
		return none, rpcreason.Error(connect.CodeFailedPrecondition, "assistance_unattended_not_permitted")
	}
	if err := assistanceunattended.CheckSchedule(mode, request.GetSchedule()); err != nil {
		return none, rpcreason.Error(connect.CodeFailedPrecondition, err.Error())
	}
	if request.GetDurationSeconds() > limits.GetMaxApprovalSeconds() {
		return none, rpcreason.Error(connect.CodeFailedPrecondition, "assistance_unattended_approval_too_long")
	}
	notBefore := request.GetNotBefore().AsTime()
	notAfter := notBefore.Add(time.Duration(request.GetDurationSeconds()) * time.Second)
	// No backdating beyond clock skew, and nothing already over.
	if notBefore.Before(now.Add(-5*time.Minute)) || !notAfter.After(now) || notBefore.After(now.Add(30*24*time.Hour)) {
		return none, rpcreason.Error(connect.CodeFailedPrecondition, "assistance_unattended_window_invalid")
	}
	requested := intersectAssistancePolicy(assistancePolicy(request.GetRequestedCapabilities()), policy)
	requested.Unattended, requested.UnattendedLimits = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF, nil
	requested.Reconnect, requested.ReconnectLimits = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF, nil
	if requested.GetRecording() == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED {
		// Nobody attends to opt in to optional recording.
		requested.Recording, requested.RecordingLimits = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF, nil
	}
	if err := scopeAssistanceCapabilities(ctx, q, requester, deviceID, request.GetMode(), requested); err != nil {
		return none, err
	}
	encoded, err := proto.Marshal(requested)
	if err != nil {
		return none, core.MapErr(err)
	}
	// Empty, never NULL: the columns are NOT NULL and an empty schedule
	// is the LIMITED time-bounded window.
	schedule := []byte{}
	if encoded == nil {
		encoded = []byte{}
	}
	if request.GetSchedule() != nil {
		if schedule, err = proto.Marshal(request.GetSchedule()); err != nil {
			return none, core.MapErr(err)
		}
	}
	row := devicedb.InsertAssistanceUnattendedGrantParams{
		ID: uuid.New(), RequestID: requestID, RequestDigest: digest, ApprovalID: approvalID, DeviceID: deviceID,
		OperatorID: requester.ID, ApproverID: approver, Mode: int16(request.GetMode()), PolicyMode: int16(mode),
		Reason: request.GetReason(), TargetUsername: request.GetTargetUsername(), NotBefore: core.Timestamptz(notBefore),
		NotAfter: core.Timestamptz(notAfter), Schedule: schedule, RequestedCapabilities: encoded,
		MaxSessionSeconds: int32(limits.GetMaxSessionSeconds()), CreatedAt: core.Timestamptz(now),
	}
	if err := q.InsertAssistanceUnattendedGrant(ctx, row); err != nil {
		return none, core.MapErr(err)
	}
	grant, err := q.LockAssistanceUnattendedGrant(ctx, row.ID)
	if err != nil {
		return none, core.MapErr(err)
	}
	if err := recordUnattendedGrantAudit(ctx, q, &requester.ID, auditkind.AssistanceUnattendedAuthorize, grant, "authorized", request.GetReason()); err != nil {
		return none, core.MapErr(err)
	}
	return grant, nil
}

func (s *Service) ListUnattendedAssistance(ctx context.Context, req *connect.Request[adminv1.ListUnattendedAssistanceRequest]) (*connect.Response[adminv1.ListUnattendedAssistanceResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_assistance_unattended")
	}
	deviceID, _ := uuid.Parse(req.Msg.GetDeviceId())
	response := &adminv1.ListUnattendedAssistanceResponse{}
	err = s.assistanceTx(ctx, nil, "", func(q *devicedb.Queries, _ *assistanceRevocations) error {
		if err := core.RequireDeviceScope(ctx, q, actor, identity.PermissionReadFleet, deviceID); err != nil {
			return core.MapErr(err)
		}
		now := s.Now()
		grants, err := q.ListAssistanceUnattendedGrants(ctx, deviceID)
		if err != nil {
			return err
		}
		for _, row := range grants {
			response.Grants = append(response.Grants, unattendedGrantMessage(row.AssistanceUnattendedGrant, row.OperatorDisplay, row.ApproverDisplay, now))
		}
		enrollments, err := q.ListAssistanceUnattendedEnrollments(ctx, deviceID)
		if err != nil {
			return err
		}
		for _, row := range enrollments {
			if row.State == enrollmentDeclined {
				continue
			}
			response.Enrollments = append(response.Enrollments, unattendedEnrollmentMessage(row, now))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return core.NoStore(response), nil
}

// RevokeUnattendedAssistance is de-escalation: the grant's operator, an
// unattended approver or a policy manager in the device's scope may revoke.
func (s *Service) RevokeUnattendedAssistance(ctx context.Context, req *connect.Request[adminv1.RevokeUnattendedAssistanceRequest]) (*connect.Response[adminv1.RevokeUnattendedAssistanceResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	permissions := []identity.Permission{identity.PermissionAssistanceUnattended, identity.PermissionApproveAssistanceUnattended, identity.PermissionManageAssistancePolicy}
	var actor identity.Principal
	var held []identity.Permission
	var firstErr error
	for _, permission := range permissions {
		principal, err := s.Require(ctx, permission)
		if err != nil {
			firstErr = cmpErr(firstErr, err)
			continue
		}
		actor, held = principal, append(held, permission)
	}
	if len(held) == 0 {
		return nil, firstErr
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil || core.HasNUL(req.Msg.GetReason()) {
		return nil, core.Invalid("invalid_assistance_unattended")
	}
	deviceID, _ := uuid.Parse(req.Msg.GetDeviceId())
	response := &adminv1.RevokeUnattendedAssistanceResponse{}
	err := s.assistanceTx(ctx, nil, "", func(q *devicedb.Queries, revoked *assistanceRevocations) error {
		scoped := false
		for _, permission := range held {
			if _, err := core.LockDeviceScope(ctx, q, actor, permission, deviceID); err == nil {
				scoped = true
				break
			}
		}
		if !scoped {
			return rpcreason.Error(connect.CodeNotFound, "not_found")
		}
		now := s.Now()
		if id := req.Msg.GetGrantId(); id != "" {
			grantID, _ := uuid.Parse(id)
			grant, err := q.LockAssistanceUnattendedGrant(ctx, grantID)
			if errors.Is(err, pgx.ErrNoRows) || (err == nil && grant.DeviceID != deviceID) {
				return rpcreason.Error(connect.CodeNotFound, "not_found")
			}
			if err != nil {
				return err
			}
			if err := revokeUnattendedGrant(ctx, q, &grant, now, &actor.ID, req.Msg.GetReason(), revoked); err != nil {
				return err
			}
			view, err := q.GetAssistanceUnattendedGrantView(ctx, grant.ID)
			if err != nil {
				return err
			}
			response.Grant = unattendedGrantMessage(view.AssistanceUnattendedGrant, view.OperatorDisplay, view.ApproverDisplay, now)
			return nil
		}
		enrollmentID, _ := uuid.Parse(req.Msg.GetEnrollmentId())
		enrollment, err := q.LockAssistanceUnattendedEnrollment(ctx, enrollmentID)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && (enrollment.DeviceID != deviceID || enrollment.State == enrollmentOffered || enrollment.State == enrollmentDeclined)) {
			return rpcreason.Error(connect.CodeNotFound, "not_found")
		}
		if err != nil {
			return err
		}
		if err := revokeUnattendedEnrollment(ctx, q, &enrollment, now, &actor.ID, "operator_revoked", revoked); err != nil {
			return err
		}
		response.Enrollment = unattendedEnrollmentMessage(enrollment, now)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return core.NoStore(response), nil
}

func cmpErr(first, next error) error {
	if first != nil {
		return first
	}
	return next
}

// unattendedAdmission is a locked, in-force grant and opt-in for one connection.
type unattendedAdmission struct {
	grant      devicedb.AssistanceUnattendedGrant
	enrollment devicedb.AssistanceUnattendedEnrollment
	until      time.Time
}

// admitUnattended checks the grant, the device policy, the schedule and the
// local opt-in for a new connection in the caller's transaction.
func (s *Service) admitUnattended(ctx context.Context, q *devicedb.Queries, principal identity.Principal, deviceID, grantID uuid.UUID, mode agentv1.AssistanceMode, target string, now time.Time) (unattendedAdmission, error) {
	var admission unattendedAdmission
	if !identity.Authorize(principal, identity.PermissionAssistanceUnattended) {
		return admission, rpcreason.Error(connect.CodePermissionDenied, "permission_denied")
	}
	if err := core.RequireDeviceScope(ctx, q, principal, identity.PermissionAssistanceUnattended, deviceID); err != nil {
		return admission, core.MapErr(err)
	}
	grant, err := q.LockAssistanceUnattendedGrant(ctx, grantID)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && grant.DeviceID != deviceID) {
		return admission, rpcreason.Error(connect.CodeNotFound, "assistance_unattended_grant_not_found")
	}
	if err != nil {
		return admission, err
	}
	deny := func(reason string) error {
		if err := recordUnattendedGrantAudit(ctx, q, &principal.ID, auditkind.AssistanceUnattendedStart, grant, "denied", reason); err != nil {
			return err
		}
		return rpcreason.Error(connect.CodeFailedPrecondition, "assistance_"+reason)
	}
	switch {
	case grant.OperatorID != principal.ID:
		// The grant is the requester's own authority; another operator cannot borrow it.
		return admission, rpcreason.Error(connect.CodePermissionDenied, "assistance_not_creator")
	case grant.RevokedAt.Valid:
		return admission, deny("unattended_grant_revoked")
	case int16(mode) != grant.Mode:
		return admission, deny("unattended_mode_mismatch")
	case target != "" && target != grant.TargetUsername:
		return admission, deny("unattended_target_mismatch")
	}
	stored, err := loadAssistancePolicy(ctx, q, deviceID)
	if err != nil {
		return admission, err
	}
	policy := intersectAssistancePolicy(stored, s.AssistanceCeiling)
	if !policyEnabled(policy.GetUnattended()) || agentv1.AssistancePolicyMode(grant.PolicyMode) > policy.GetUnattended() {
		return admission, deny("unattended_not_permitted")
	}
	until, err := assistanceunattended.Window(grant.NotBefore.Time, grant.NotAfter.Time, decodeUnattendedSchedule(grant.Schedule), now)
	if err != nil {
		return admission, deny(err.Error())
	}
	enrollment, err := q.LockEnrolledAssistanceUnattended(ctx, devicedb.LockEnrolledAssistanceUnattendedParams{DeviceID: deviceID, Username: grant.TargetUsername})
	if errors.Is(err, pgx.ErrNoRows) {
		return admission, deny("unattended_not_enrolled")
	}
	if err != nil {
		return admission, err
	}
	if !now.Before(enrollment.ExpiresAt.Time) {
		return admission, deny("unattended_enrollment_expired")
	}
	if enrollment.Mode != grant.Mode {
		return admission, deny("unattended_enrollment_mode_mismatch")
	}
	if enrollment.ExpiresAt.Time.Before(until) {
		until = enrollment.ExpiresAt.Time
	}
	return unattendedAdmission{grant: grant, enrollment: enrollment, until: until}, nil
}

// checkUnattendedConnection rechecks an open connection's grant, opt-in,
// policy and operator scope on every authority refresh.
func (s *Service) checkUnattendedConnection(ctx context.Context, q *devicedb.Queries, row devicedb.AssistanceSession, principal identity.Principal, policy *agentv1.AssistancePolicy, now time.Time) (string, error) {
	if row.UnattendedGrantID == nil || row.UnattendedEnrollmentID == nil {
		return "", nil
	}
	if err := core.RequireDeviceScope(ctx, q, principal, identity.PermissionAssistanceUnattended, row.DeviceID); err != nil {
		return "operator_scope_lost", nil
	}
	grant, err := q.LockAssistanceUnattendedGrant(ctx, *row.UnattendedGrantID)
	if err != nil {
		return "", err
	}
	if grant.RevokedAt.Valid || !now.Before(grant.NotAfter.Time) {
		return "unattended_grant_ended", nil
	}
	if !policyEnabled(policy.GetUnattended()) || agentv1.AssistancePolicyMode(grant.PolicyMode) > policy.GetUnattended() {
		return "policy_changed", nil
	}
	enrollment, err := q.LockAssistanceUnattendedEnrollment(ctx, *row.UnattendedEnrollmentID)
	if err != nil {
		return "", err
	}
	if enrollment.State != enrollmentEnrolled || !now.Before(enrollment.ExpiresAt.Time) {
		return "unattended_enrollment_ended", nil
	}
	return "", nil
}

// unattendedInvitation adds the opt-in offer or the connection authority to a
// directive's invitation.
func unattendedInvitation(ctx context.Context, q *devicedb.Queries, row devicedb.AssistanceSession, invitation *agentv1.AssistanceInvitation) error {
	if row.UnattendedGrantID != nil && row.UnattendedEnrollmentID != nil {
		view, err := q.GetAssistanceUnattendedGrantView(ctx, *row.UnattendedGrantID)
		if err != nil {
			return err
		}
		approver := view.ApproverDisplay
		if approver == "" {
			approver = view.AssistanceUnattendedGrant.ApproverID.String()
		}
		invitation.Unattended = &agentv1.AssistanceUnattendedAuthority{
			GrantId: row.UnattendedGrantID.String(), EnrollmentId: row.UnattendedEnrollmentID.String(),
			ApproverDisplay: truncateDisplay(approver), ApprovedUntil: timestamppb.New(row.EndsAt.Time),
		}
		return nil
	}
	enrollment, err := q.GetAssistanceUnattendedEnrollmentBySession(ctx, row.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	invitation.UnattendedEnrollment = &agentv1.AssistanceUnattendedEnrollmentOffer{EnrollmentId: enrollment.ID.String(), ExpiresAt: timestamppb.New(enrollment.ExpiresAt.Time)}
	return nil
}

func truncateDisplay(display string) string {
	count := 0
	for index := range display {
		if count == 256 {
			return display[:index]
		}
		count++
	}
	return display
}

// offerUnattendedEnrollment records the opt-in an attended invitation may ask
// for. Only the local user's choice and the desktop's persistent grant turn
// it into an enrollment.
func offerUnattendedEnrollment(ctx context.Context, q *devicedb.Queries, id, deviceID uuid.UUID, mode agentv1.AssistanceMode, policy *agentv1.AssistancePolicy, now time.Time) error {
	if !policyEnabled(policy.GetUnattended()) || policy.GetUnattendedLimits() == nil {
		return nil
	}
	days := time.Duration(policy.GetUnattendedLimits().GetMaxEnrollmentDays()) * 24 * time.Hour
	return q.InsertAssistanceUnattendedEnrollment(ctx, devicedb.InsertAssistanceUnattendedEnrollmentParams{
		ID: uuid.New(), DeviceID: deviceID, SessionID: id, Mode: int16(mode), CreatedAt: core.Timestamptz(now), ExpiresAt: core.Timestamptz(now.Add(days)),
	})
}

// applyUnattendedReport applies the employee's opt-in decision or local
// turn-off. It returns a non-empty detail when the report is invalid.
func applyUnattendedReport(ctx context.Context, q *devicedb.Queries, row devicedb.AssistanceSession, report *agentv1.AssistanceUnattendedReport, grant *agentv1.AssistancePolicy, now time.Time, revoked *assistanceRevocations) (string, error) {
	if report == nil {
		return "", nil
	}
	enrollmentID, _ := uuid.Parse(report.GetEnrollmentId())
	enrollment, err := q.LockAssistanceUnattendedEnrollment(ctx, enrollmentID)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && enrollment.DeviceID != row.DeviceID) {
		return "unattended_report_invalid", nil
	}
	if err != nil {
		return "", err
	}
	connection := row.UnattendedEnrollmentID != nil && *row.UnattendedEnrollmentID == enrollment.ID
	switch report.GetState() {
	case agentv1.AssistanceUnattendedEnrollmentState_ASSISTANCE_UNATTENDED_ENROLLMENT_STATE_ENROLLED:
		if enrollment.SessionID != row.ID || connection {
			return "unattended_report_invalid", nil
		}
		if enrollment.State != enrollmentOffered {
			return "", nil
		}
		if !policyEnabled(grant.GetUnattended()) || row.LocalUsername == "" || row.LocalUid <= 0 || !now.Before(enrollment.ExpiresAt.Time) {
			return "unattended_report_invalid", nil
		}
		// One opt-in per user and device: a fresh one supersedes the old.
		previous, err := q.LockEnrolledAssistanceUnattended(ctx, devicedb.LockEnrolledAssistanceUnattendedParams{DeviceID: row.DeviceID, Username: row.LocalUsername})
		if err == nil {
			if err := revokeUnattendedEnrollment(ctx, q, &previous, now, nil, "superseded", revoked); err != nil {
				return "", err
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return "", err
		}
		if err := q.ConsentAssistanceUnattendedEnrollment(ctx, devicedb.ConsentAssistanceUnattendedEnrollmentParams{ID: enrollment.ID, Username: row.LocalUsername, Uid: row.LocalUid, ConsentedAt: core.Timestamptz(now)}); err != nil {
			return "", err
		}
		enrollment.State, enrollment.Username, enrollment.Uid = enrollmentEnrolled, row.LocalUsername, row.LocalUid
		return "", recordUnattendedEnrollmentAudit(ctx, q, nil, auditkind.AssistanceUnattendedEnroll, enrollment, "enrolled", report.GetReason())
	case agentv1.AssistanceUnattendedEnrollmentState_ASSISTANCE_UNATTENDED_ENROLLMENT_STATE_DECLINED:
		if enrollment.SessionID != row.ID || connection {
			return "unattended_report_invalid", nil
		}
		if enrollment.State != enrollmentOffered {
			return "", nil
		}
		reason := report.GetReason()
		if reason == "" {
			reason = "user_declined"
		}
		if err := q.DeclineAssistanceUnattendedEnrollment(ctx, devicedb.DeclineAssistanceUnattendedEnrollmentParams{ID: enrollment.ID, Reason: reason}); err != nil {
			return "", err
		}
		enrollment.State = enrollmentDeclined
		return "", recordUnattendedEnrollmentAudit(ctx, q, nil, auditkind.AssistanceUnattendedEnroll, enrollment, "declined", reason)
	default:
		// The employee turned unattended access off, or the device lost or
		// could not restore its persistent grant.
		if enrollment.SessionID != row.ID && !connection {
			return "unattended_report_invalid", nil
		}
		reason := report.GetReason()
		if reason == "" {
			reason = "user_revoked"
		}
		return "", revokeUnattendedEnrollment(ctx, q, &enrollment, now, nil, reason, revoked)
	}
}

// recordUnattendedStart audits the connection once the device shows the banner
// and restored the persistent grant; there is no consent click to record.
func recordUnattendedStart(ctx context.Context, q *devicedb.Queries, row devicedb.AssistanceSession) error {
	if row.UnattendedGrantID == nil {
		return nil
	}
	grant, err := q.LockAssistanceUnattendedGrant(ctx, *row.UnattendedGrantID)
	if err != nil {
		return err
	}
	pairs := append([]string{"session", row.ID.String(), "enrollment", row.UnattendedEnrollmentID.String(), "banner", "shown", "offer", row.OfferFingerprint, "control_granted", boolText(row.ControlGranted)}, assistanceLocalAudit(row)...)
	return recordUnattendedGrantAudit(ctx, q, nil, auditkind.AssistanceUnattendedStart, grant, "started", "", pairs...)
}

// recordUnattendedStop audits the end of an unattended connection.
func recordUnattendedStop(ctx context.Context, q *devicedb.Queries, row devicedb.AssistanceSession, actor *uuid.UUID) error {
	if row.UnattendedGrantID == nil {
		return nil
	}
	grant, err := q.LockAssistanceUnattendedGrant(ctx, *row.UnattendedGrantID)
	if err != nil {
		return err
	}
	return recordUnattendedGrantAudit(ctx, q, actor, auditkind.AssistanceUnattendedStop, grant, "stopped", "", "session", row.ID.String(), "cause", assistanceCauseName(agentv1.AssistanceEndCause(row.EndCause)), "detail", row.EndDetail)
}

// unattendedDeviceRefusal maps a device end detail that proves the local
// opt-in no longer holds to the enrollment it names.
func unattendedDeviceRefusal(ctx context.Context, q *devicedb.Queries, row devicedb.AssistanceSession, now time.Time, revoked *assistanceRevocations) error {
	if row.UnattendedEnrollmentID == nil {
		return nil
	}
	switch row.EndDetail {
	case "unattended_enrollment_missing", "unattended_portal_grant_missing", "unattended_turned_off":
	default:
		return nil
	}
	enrollment, err := q.LockAssistanceUnattendedEnrollment(ctx, *row.UnattendedEnrollmentID)
	if err != nil {
		return err
	}
	return revokeUnattendedEnrollment(ctx, q, &enrollment, now, nil, row.EndDetail, revoked)
}

func unattendedConnectionMessage(ctx context.Context, q *devicedb.Queries, row devicedb.AssistanceSession) (*adminv1.AssistanceUnattendedConnection, error) {
	if row.UnattendedGrantID == nil || row.UnattendedEnrollmentID == nil {
		return nil, nil
	}
	view, err := q.GetAssistanceUnattendedGrantView(ctx, *row.UnattendedGrantID)
	if err != nil {
		return nil, err
	}
	return &adminv1.AssistanceUnattendedConnection{
		GrantId: row.UnattendedGrantID.String(), EnrollmentId: row.UnattendedEnrollmentID.String(),
		ApproverId: view.AssistanceUnattendedGrant.ApproverID.String(), ApproverDisplay: view.ApproverDisplay, ApprovedUntil: core.ProtoTime(row.EndsAt),
	}, nil
}
