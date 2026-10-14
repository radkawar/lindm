// SPDX-License-Identifier: Apache-2.0

//go:build integration

package assistance

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/identity"
)

// unattendedEvidence is the decision-time admission for unattended
// approvals: like the directory's admitApproval for any request other than
// an advisory acceptance, they bind no evidence that could go stale.
func unattendedEvidence(context.Context, pgx.Tx, *adminv1.Approval) error { return nil }

func unattendedLimits() *agentv1.AssistanceUnattendedPolicy {
	return &agentv1.AssistanceUnattendedPolicy{MaxApprovalSeconds: 8 * 3600, MaxEnrollmentDays: 30, MaxSessionSeconds: 1200}
}

func unattendedPolicy(mode agentv1.AssistancePolicyMode) *agentv1.AssistancePolicy {
	return &agentv1.AssistancePolicy{Unattended: mode, UnattendedLimits: unattendedLimits(), Elevation: tier2Limited, Annotation: tier2On}
}

// newUnattendedFixture enables LIMITED unattended access on the device.
func newUnattendedFixture(t *testing.T, mode agentv1.AssistancePolicyMode) *assistanceFixture {
	t.Helper()
	f := newAssistanceFixture(t, 0)
	f.svc.AssistanceCeiling = assistancePolicy(unattendedPolicy(tier2On))
	if _, err := f.svc.UpdateAssistancePolicy(f.creatorCtx, connect.NewRequest(&adminv1.UpdateAssistancePolicyRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Policy: unattendedPolicy(mode)})); err != nil {
		t.Fatal(err)
	}
	return f
}

// optIn runs an attended session that offers the opt-in and reports the
// employee's choice, then stops it. It returns the enrollment ID.
func (f *assistanceFixture) optIn(t *testing.T, state agentv1.AssistanceUnattendedEnrollmentState) string {
	t.Helper()
	request := f.createRequest(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, "")
	request.RequestedCapabilities = &agentv1.AssistancePolicy{Unattended: tier2Limited, UnattendedLimits: unattendedLimits()}
	created, err := f.svc.CreateAssistanceSession(f.creatorCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	session := created.Msg.GetSession()
	offerID := session.GetUnattendedEnrollmentId()
	var offer *agentv1.AssistanceUnattendedEnrollmentOffer
	for _, directive := range f.sync(t, report(session.GetId(), agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED, localSession("2"), "")) {
		if directive.GetInvitation().GetSessionId() == session.GetId() {
			offer = directive.GetInvitation().GetUnattendedEnrollment()
		}
	}
	if offer.GetEnrollmentId() != offerID || offerID == "" {
		t.Fatalf("attended invitation offered %v, session names %q", offer, offerID)
	}
	granted := &agentv1.AssistancePolicy{}
	if state == agentv1.AssistanceUnattendedEnrollmentState_ASSISTANCE_UNATTENDED_ENROLLMENT_STATE_ENROLLED {
		granted = &agentv1.AssistancePolicy{Unattended: tier2Limited, UnattendedLimits: unattendedLimits()}
	}
	observation := report(session.GetId(), agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED, localSession("2"), f.sdp(testFingerprint))
	observation.ControlGranted = false
	observation.RequestedCapabilities, observation.EffectiveCapabilities = proto.CloneOf(session.GetRequestedCapabilities()), proto.CloneOf(session.GetEffectiveCapabilities())
	observation.GrantedCapabilities = &agentv1.AssistanceCapabilities{Policy: granted}
	observation.Unattended = &agentv1.AssistanceUnattendedReport{EnrollmentId: offerID, State: state}
	f.sync(t, observation)
	if _, err := f.svc.StopAssistanceSession(f.creatorCtx, connect.NewRequest(&adminv1.StopAssistanceSessionRequest{SessionId: session.GetId()})); err != nil {
		t.Fatal(err)
	}
	f.sync(t, ended(session.GetId(), agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED))
	return offerID
}

func (f *assistanceFixture) grantRequest() *adminv1.AuthorizeUnattendedAssistanceRequest {
	return &adminv1.AuthorizeUnattendedAssistanceRequest{
		RequestId: uuid.NewString(), DeviceId: f.deviceID, Mode: agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW,
		Reason: "after-hours printer maintenance", NotBefore: timestamppb.New(f.now), DurationSeconds: 4 * 3600,
		TargetUsername: "alice", RequestedCapabilities: &agentv1.AssistancePolicy{Elevation: tier2Limited},
	}
}

func (f *assistanceFixture) requestApproval(t *testing.T, request *adminv1.AuthorizeUnattendedAssistanceRequest) *adminv1.Approval {
	t.Helper()
	approval, err := f.svc.Identity.CreateApproval(f.ctx, f.creator.ID, &adminv1.CreateApprovalRequest{LifetimeSeconds: 3600, Payload: &adminv1.CreateApprovalRequest_AuthorizeUnattendedAssistance{AuthorizeUnattendedAssistance: request}}, f.svc.ApprovalScope)
	if err != nil {
		t.Fatal(err)
	}
	return approval
}

func (f *assistanceFixture) unattendedSession(t *testing.T, grantID string) (*adminv1.AssistanceSession, error) {
	t.Helper()
	request := f.createRequest(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, "")
	request.UnattendedGrantId = grantID
	request.RequestedCapabilities = &agentv1.AssistancePolicy{Elevation: tier2Limited}
	response, err := f.svc.CreateAssistanceSession(f.creatorCtx, connect.NewRequest(request))
	if err != nil {
		return nil, err
	}
	return response.Msg.GetSession(), nil
}

func (f *assistanceFixture) unattendedGrant(t *testing.T) *adminv1.AssistanceUnattendedGrant {
	t.Helper()
	request := f.grantRequest()
	approval := f.requestApproval(t, request)
	other, ok := identity.PrincipalFromContext(f.otherCtx)
	if !ok {
		t.Fatal("missing approver principal")
	}
	if _, err := f.svc.Identity.DecideApproval(f.ctx, other.ID, uuid.MustParse(approval.GetId()), true, "covered by change ticket", f.svc.ApprovalScope, unattendedEvidence); err != nil {
		t.Fatal(err)
	}
	request.ApprovalId = approval.GetId()
	response, err := f.svc.AuthorizeUnattendedAssistance(f.creatorCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg.GetGrant()
}

func TestUnattendedAccessNeedsOptInIndependentApprovalAndTheEnrolledAccount(t *testing.T) {
	f := newUnattendedFixture(t, tier2Limited)
	enrollmentID := f.optIn(t, agentv1.AssistanceUnattendedEnrollmentState_ASSISTANCE_UNATTENDED_ENROLLMENT_STATE_ENROLLED)
	listed, err := f.svc.ListUnattendedAssistance(f.ownerCtx, connect.NewRequest(&adminv1.ListUnattendedAssistanceRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	if enrollments := listed.Msg.GetEnrollments(); len(enrollments) != 1 || enrollments[0].GetId() != enrollmentID || enrollments[0].GetUsername() != "alice" || enrollments[0].GetUid() != 1000 || enrollments[0].GetState() != adminv1.AssistanceUnattendedEnrollmentStatus_ASSISTANCE_UNATTENDED_ENROLLMENT_STATUS_ENROLLED {
		t.Fatalf("enrollments = %v", enrollments)
	}

	request := f.grantRequest()
	approval := f.requestApproval(t, request)
	// The requester can neither decide nor use an undecided approval.
	if _, err := f.svc.Identity.DecideApproval(f.ctx, f.creator.ID, uuid.MustParse(approval.GetId()), true, "self approval", f.svc.ApprovalScope, unattendedEvidence); !errors.Is(err, identity.ErrAuthorizationDenied) {
		t.Fatalf("requester approved their own unattended access: %v", err)
	}
	early := proto.CloneOf(request)
	early.ApprovalId = approval.GetId()
	if _, err := f.svc.AuthorizeUnattendedAssistance(f.creatorCtx, connect.NewRequest(early)); err == nil {
		t.Fatal("an undecided approval authorized unattended access")
	}
	other, _ := identity.PrincipalFromContext(f.otherCtx)
	if _, err := f.svc.Identity.DecideApproval(f.ctx, other.ID, uuid.MustParse(approval.GetId()), true, "covered by change ticket", f.svc.ApprovalScope, unattendedEvidence); err != nil {
		t.Fatal(err)
	}
	// A changed payload never consumes the approval.
	changed := proto.CloneOf(early)
	changed.DurationSeconds += 60
	if _, err := f.svc.AuthorizeUnattendedAssistance(f.creatorCtx, connect.NewRequest(changed)); err == nil {
		t.Fatal("a changed request consumed the approval")
	}
	response, err := f.svc.AuthorizeUnattendedAssistance(f.creatorCtx, connect.NewRequest(early))
	if err != nil {
		t.Fatal(err)
	}
	grant := response.Msg.GetGrant()
	if grant.GetState() != adminv1.AssistanceUnattendedGrantState_ASSISTANCE_UNATTENDED_GRANT_STATE_ACTIVE || grant.GetApproverId() != other.ID.String() || grant.GetOperatorId() != f.creator.ID.String() {
		t.Fatalf("grant = %v", grant)
	}
	replay, err := f.svc.AuthorizeUnattendedAssistance(f.creatorCtx, connect.NewRequest(early))
	if err != nil || replay.Msg.GetGrant().GetId() != grant.GetId() {
		t.Fatalf("exact replay = %v, %v", replay, err)
	}

	// The grant is the requester's own; another operator cannot borrow it.
	borrowed := f.createRequest(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, "")
	borrowed.UnattendedGrantId = grant.GetId()
	_, err = f.svc.CreateAssistanceSession(f.otherCtx, connect.NewRequest(borrowed))
	wantReason(t, err, connect.CodePermissionDenied, "assistance_not_creator")

	// A different UID under the enrolled name is refused at binding.
	session, err := f.unattendedSession(t, grant.GetId())
	if err != nil {
		t.Fatal(err)
	}
	if session.GetUnattended().GetGrantId() != grant.GetId() || session.GetUnattended().GetEnrollmentId() != enrollmentID || session.GetTargetUsername() != "alice" {
		t.Fatalf("connection = %v", session)
	}
	if !session.GetEndsAt().AsTime().Equal(f.now.Add(1200 * time.Second)) {
		t.Fatalf("connection ends %v, want the policy's single-connection bound", session.GetEndsAt().AsTime())
	}
	recycled := localSession("4")
	recycled.Uid = 1001
	f.sync(t, report(session.GetId(), agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED, recycled, ""))
	if got := f.get(t, session.GetId()); got.GetEndCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_NO_ELIGIBLE_SESSION || got.GetEndDetail() != "unattended_uid_changed" {
		t.Fatalf("recycled account = %v %q", got.GetEndCause(), got.GetEndDetail())
	}

	session, err = f.unattendedSession(t, grant.GetId())
	if err != nil {
		t.Fatal(err)
	}
	var invitation *agentv1.AssistanceInvitation
	for _, directive := range f.sync(t, report(session.GetId(), agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED, localSession("5"), "")) {
		if directive.GetInvitation().GetSessionId() == session.GetId() {
			invitation = directive.GetInvitation()
		}
	}
	if invitation.GetUnattended().GetEnrollmentId() != enrollmentID || invitation.GetUnattendedEnrollment() != nil {
		t.Fatalf("unattended invitation = %v", invitation)
	}
	offered := report(session.GetId(), agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED, localSession("5"), f.sdp(testFingerprint))
	offered.ControlGranted = false
	offered.RequestedCapabilities, offered.EffectiveCapabilities = proto.CloneOf(session.GetRequestedCapabilities()), proto.CloneOf(session.GetEffectiveCapabilities())
	offered.GrantedCapabilities = &agentv1.AssistanceCapabilities{Policy: &agentv1.AssistancePolicy{Elevation: tier2Limited}}
	f.sync(t, offered)
	if got := f.get(t, session.GetId()); got.GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_OFFERED {
		t.Fatalf("unattended connection state = %v (%s)", got.GetState(), got.GetEndDetail())
	}
	if actions := f.auditActions(t, session.GetId()); slices.Contains(actions, "assistance.consent") {
		t.Fatalf("an unattended connection was audited as a local consent: %v", actions)
	}

	// Revocation by the approver ends the open connection and every later one.
	if _, err := f.svc.RevokeUnattendedAssistance(f.otherCtx, connect.NewRequest(&adminv1.RevokeUnattendedAssistanceRequest{DeviceId: f.deviceID, GrantId: grant.GetId(), Reason: "maintenance finished early"})); err != nil {
		t.Fatal(err)
	}
	if got := f.get(t, session.GetId()); got.GetEndCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST || got.GetEndDetail() != "unattended_grant_revoked" {
		t.Fatalf("revoked connection = %v %q", got.GetEndCause(), got.GetEndDetail())
	}
	_, err = f.unattendedSession(t, grant.GetId())
	wantReason(t, err, connect.CodeFailedPrecondition, "assistance_unattended_grant_revoked")
	var audits []string
	rows, err := f.conn.Query(f.ctx, "SELECT action FROM audit_events WHERE action LIKE 'assistance.unattended.%' ORDER BY occurred_at, action")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var action string
		if err := rows.Scan(&action); err != nil {
			t.Fatal(err)
		}
		audits = append(audits, action)
	}
	rows.Close()
	for _, want := range []string{"assistance.unattended.enroll", "assistance.unattended.request", "assistance.unattended.approve", "assistance.unattended.authorize", "assistance.unattended.start", "assistance.unattended.stop", "assistance.unattended.revoke"} {
		if !slices.Contains(audits, want) {
			t.Fatalf("missing %s in %v", want, audits)
		}
	}
}

func TestUnattendedAccessRefusesWithoutOptInScheduleOrPolicy(t *testing.T) {
	f := newUnattendedFixture(t, tier2Limited)
	// No local opt-in: an approved grant still cannot connect.
	grant := f.unattendedGrant(t)
	_, err := f.unattendedSession(t, grant.GetId())
	wantReason(t, err, connect.CodeFailedPrecondition, "assistance_unattended_not_enrolled")

	// A declined opt-in is no opt-in.
	f.optIn(t, agentv1.AssistanceUnattendedEnrollmentState_ASSISTANCE_UNATTENDED_ENROLLMENT_STATE_DECLINED)
	_, err = f.unattendedSession(t, grant.GetId())
	wantReason(t, err, connect.CodeFailedPrecondition, "assistance_unattended_not_enrolled")

	enrollmentID := f.optIn(t, agentv1.AssistanceUnattendedEnrollmentState_ASSISTANCE_UNATTENDED_ENROLLMENT_STATE_ENROLLED)
	session, err := f.unattendedSession(t, grant.GetId())
	if err != nil {
		t.Fatal(err)
	}
	// The employee turns unattended access off from the banner: the device's
	// end detail revokes the opt-in.
	turnedOff := ended(session.GetId(), agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED)
	turnedOff.EndDetail = "unattended_turned_off"
	f.sync(t, turnedOff)
	_, err = f.unattendedSession(t, grant.GetId())
	wantReason(t, err, connect.CodeFailedPrecondition, "assistance_unattended_not_enrolled")
	listed, err := f.svc.ListUnattendedAssistance(f.ownerCtx, connect.NewRequest(&adminv1.ListUnattendedAssistanceRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	for _, enrollment := range listed.Msg.GetEnrollments() {
		if enrollment.GetId() == enrollmentID && enrollment.GetState() != adminv1.AssistanceUnattendedEnrollmentStatus_ASSISTANCE_UNATTENDED_ENROLLMENT_STATUS_REVOKED {
			t.Fatalf("turned-off opt-in = %v", enrollment)
		}
	}

	// LIMITED policy refuses a recurring schedule; OFF revokes every grant.
	scheduled := f.grantRequest()
	scheduled.Schedule = &agentv1.AssistanceUnattendedSchedule{TimeZone: "UTC", Windows: []*agentv1.AssistanceUnattendedWindow{{Weekday: 1, StartMinute: 540, DurationMinutes: 60}}}
	approval := f.requestApproval(t, scheduled)
	other, _ := identity.PrincipalFromContext(f.otherCtx)
	if _, err := f.svc.Identity.DecideApproval(f.ctx, other.ID, uuid.MustParse(approval.GetId()), true, "covered", f.svc.ApprovalScope, unattendedEvidence); err != nil {
		t.Fatal(err)
	}
	scheduled.ApprovalId = approval.GetId()
	_, err = f.svc.AuthorizeUnattendedAssistance(f.creatorCtx, connect.NewRequest(scheduled))
	wantReason(t, err, connect.CodeFailedPrecondition, "unattended_schedule_not_permitted")

	live := f.unattendedGrant(t)
	if _, err := f.svc.UpdateAssistancePolicy(f.creatorCtx, connect.NewRequest(&adminv1.UpdateAssistancePolicyRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Policy: &agentv1.AssistancePolicy{}})); err != nil {
		t.Fatal(err)
	}
	listed, err = f.svc.ListUnattendedAssistance(f.ownerCtx, connect.NewRequest(&adminv1.ListUnattendedAssistanceRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	for _, listedGrant := range listed.Msg.GetGrants() {
		if listedGrant.GetId() == live.GetId() && listedGrant.GetState() != adminv1.AssistanceUnattendedGrantState_ASSISTANCE_UNATTENDED_GRANT_STATE_REVOKED {
			t.Fatalf("policy off left a grant in force: %v", listedGrant)
		}
	}
}

// activeGuidance brings a CONTROL session with elevation, overlay and sound
// granted (as reported by the device) to ACTIVE.
func activeGuidance(t *testing.T, grant *agentv1.AssistancePolicy) (*assistanceFixture, *agentv1.AssistanceReport) {
	t.Helper()
	f := newUnattendedFixture(t, tier2Limited)
	f.svc.AssistanceCeiling.Audio, f.svc.AssistanceCeiling.Elevation = tier2On, tier2On
	if _, err := f.svc.UpdateAssistancePolicy(f.creatorCtx, connect.NewRequest(&adminv1.UpdateAssistancePolicyRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Policy: &agentv1.AssistancePolicy{Elevation: tier2On, Annotation: tier2On, Audio: tier2Limited}})); err != nil {
		t.Fatal(err)
	}
	request := f.createRequest(agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, 0, "")
	request.RequestedCapabilities = &agentv1.AssistancePolicy{Elevation: tier2On, Annotation: tier2On, Audio: tier2Limited}
	created, err := f.svc.CreateAssistanceSession(f.creatorCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	session := created.Msg.GetSession()
	f.sync(t, report(session.GetId(), agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED, localSession("2"), ""))
	observation := report(session.GetId(), agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED, localSession("2"), f.sdp(testFingerprint))
	observation.RequestedCapabilities, observation.EffectiveCapabilities = proto.CloneOf(session.GetRequestedCapabilities()), proto.CloneOf(session.GetEffectiveCapabilities())
	observation.GrantedCapabilities = &agentv1.AssistanceCapabilities{Policy: grant}
	f.sync(t, observation)
	activateAssistanceFiles(t, f, observation)
	return f, observation
}

func TestGuidanceStateIsAuditedAndBoundToTheGrant(t *testing.T) {
	f, observation := activeGuidance(t, &agentv1.AssistancePolicy{Elevation: tier2Limited, Annotation: tier2On, Audio: tier2Limited})
	id := observation.GetSessionId()
	step := func(change func(*agentv1.AssistanceReport)) {
		t.Helper()
		change(observation)
		f.sync(t, observation)
		if state := f.get(t, id); state.GetState() == adminv1.AssistanceState_ASSISTANCE_STATE_ENDED {
			t.Fatalf("valid guidance report ended the session: %s", state.GetEndDetail())
		}
	}
	step(func(r *agentv1.AssistanceReport) {
		r.InputState = &agentv1.AssistanceInputState{Epoch: 2, Paused: true, Pause: agentv1.AssistanceInputPause_ASSISTANCE_INPUT_PAUSE_ELEVATION}
	})
	if state := f.get(t, id).GetInputState(); state.GetPause() != agentv1.AssistanceInputPause_ASSISTANCE_INPUT_PAUSE_ELEVATION {
		t.Fatalf("operator does not see the elevation pause: %v", state)
	}
	// The server refuses every command while the employee holds the pause.
	_, err := f.svc.RunAssistanceCommand(f.creatorCtx, connect.NewRequest(commandRequest(id, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_ELEVATION_GUIDANCE, "")))
	wantReason(t, err, connect.CodeFailedPrecondition, "assistance_input_paused")
	step(func(r *agentv1.AssistanceReport) { r.InputState = &agentv1.AssistanceInputState{Epoch: 3} })
	step(func(r *agentv1.AssistanceReport) {
		r.Audio = &agentv1.AssistanceAudioReport{State: agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_SHARING, OutputSource: "Speakers"}
	})
	step(func(r *agentv1.AssistanceReport) {
		r.Audio = &agentv1.AssistanceAudioReport{State: agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_MUTED, OutputSource: "Speakers"}
	})
	step(func(r *agentv1.AssistanceReport) {
		r.Audio = &agentv1.AssistanceAudioReport{State: agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_STOPPED}
	})
	step(func(r *agentv1.AssistanceReport) {
		r.Annotation = &agentv1.AssistanceAnnotationReport{Hidden: true, Clears: 1}
	})
	actions := f.auditActions(t, id)
	for _, want := range []string{"assistance.elevation.pause", "assistance.elevation.resume", "assistance.audio.consent", "assistance.audio.mute", "assistance.audio.stop", "assistance.annotation.disable", "assistance.annotation.clear"} {
		if !slices.Contains(actions, want) {
			t.Fatalf("missing %s in %v", want, actions)
		}
	}
	// A report beyond the grant ends the session: no microphone under LIMITED.
	observation.Audio = &agentv1.AssistanceAudioReport{State: agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_SHARING, MicrophoneSource: "Microphone"}
	f.sync(t, observation)
	if state := f.get(t, id); state.GetEndCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST {
		t.Fatalf("over-grant report = %v %q", state.GetEndCause(), state.GetEndDetail())
	}
}

func TestElevationPauseWithoutTheGrantEndsTheSession(t *testing.T) {
	f, observation := activeGuidance(t, &agentv1.AssistancePolicy{Annotation: tier2On})
	observation.InputState = &agentv1.AssistanceInputState{Epoch: 2, Paused: true, Pause: agentv1.AssistanceInputPause_ASSISTANCE_INPUT_PAUSE_ELEVATION}
	f.sync(t, observation)
	if state := f.get(t, observation.GetSessionId()); state.GetEndDetail() != "elevation_without_grant" {
		t.Fatalf("ungranted pause = %v %q", state.GetEndCause(), state.GetEndDetail())
	}
}
