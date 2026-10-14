// SPDX-License-Identifier: Apache-2.0

package orgapply

import (
	"context"
	"errors"
	"strconv"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	adminv1connect "lindm/gen/lindm/admin/v1/adminv1connect"
	orgv1 "lindm/gen/lindm/org/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/rpcreason"
)

const groupID = "00000000-0000-4000-8000-000000000011"
const profileID = "00000000-0000-4000-8000-000000000012"
const assignmentID = "00000000-0000-4000-8000-000000000013"

func organizationFixture() *orgv1.Organization {
	return &orgv1.Organization{Name: "test", Groups: []*orgv1.StaticGroup{{Id: groupID, Name: "Engineering"}}, Profiles: []*orgv1.Profile{{Id: profileID, Spec: &policyv1.ResourceProfile{Name: "baseline", Resources: []*policyv1.ProfileResource{{ResourceId: "00000000-0000-4000-8000-000000000014", Desired: &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: "cups.service"}, State: &resourcev1.ResourceDesiredState_SystemdService{SystemdService: &resourcev1.SystemdServiceDesired{Unit: "cups.service", Runtime: resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE, Enablement: resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_DISABLED}}}, Ownership: &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN}, Verification: &resourcev1.VerificationPolicy{MaxAgeSeconds: 300, Checks: []resourcev1.HealthCheck{resourcev1.HealthCheck_HEALTH_CHECK_NATIVE_STATE}}}}}}}, Assignments: []*orgv1.Assignment{{ProfileId: profileID, Assignment: &policyv1.TargetAssignment{AssignmentId: assignmentID, Target: &policyv1.TargetRef{Target: &policyv1.TargetRef_StaticGroupId{StaticGroupId: groupID}}}}}, ProvisioningTokens: []*orgv1.ProvisioningToken{{Name: "engineering", Request: &adminv1.CreateProvisioningTokenRequest{LifetimeSeconds: 3600, MaxUses: 10, GroupIds: []string{groupID}}}}, Grants: []*orgv1.EnrollmentGrant{{Name: "one-time", Request: &adminv1.CreateEnrollmentGrantRequest{LifetimeSeconds: 600}}}}
}

type fakeAdmin struct {
	adminv1connect.AdminServiceClient
	authorization   *adminv1.AuthorizationState
	groups          []*adminv1.DeviceGroup
	profiles        map[string]*adminv1.ProfileRevision
	assignments     []*policyv1.TargetCandidate
	tokens          []*adminv1.ProvisioningToken
	grants          []*adminv1.EnrollmentGrant
	requests        []proto.Message
	failGrant       bool
	fleet           []*adminv1.Device
	rollouts        []*adminv1.RolloutState
	impactChanged   bool
	staleStarts     int
	noDevices       bool
	requireApproval bool
	approvals       []*adminv1.Approval
	findings        []*adminv1.AdvisoryFinding
	principalID     string
	// findingSnapshotChanges makes the next N continuation pages abort as a
	// newer host observation replacing the cursor's evidence snapshot would.
	findingSnapshotChanges int
	findingCalls           int
}

func newFakeAdmin() *fakeAdmin {
	return &fakeAdmin{profiles: make(map[string]*adminv1.ProfileRevision)}
}
func (f *fakeAdmin) GetAuthorization(context.Context, *connect.Request[adminv1.GetAuthorizationRequest]) (*connect.Response[adminv1.GetAuthorizationResponse], error) {
	return connect.NewResponse(&adminv1.GetAuthorizationResponse{Authorization: proto.CloneOf(f.authorization)}), nil
}
func (f *fakeAdmin) UpdateAuthorization(_ context.Context, request *connect.Request[adminv1.UpdateAuthorizationRequest]) (*connect.Response[adminv1.UpdateAuthorizationResponse], error) {
	if request.Msg.GetExpectedRevision() != f.authorization.GetRevision() {
		return nil, connect.NewError(connect.CodeAborted, errors.New("stale authorization"))
	}
	f.requests = append(f.requests, proto.CloneOf(request.Msg))
	f.authorization = &adminv1.AuthorizationState{Policy: proto.CloneOf(request.Msg.GetPolicy()), Runtime: true, Revision: request.Msg.GetExpectedRevision() + 1}
	return connect.NewResponse(&adminv1.UpdateAuthorizationResponse{Authorization: proto.CloneOf(f.authorization)}), nil
}
func (f *fakeAdmin) ListDeviceGroups(context.Context, *connect.Request[adminv1.ListDeviceGroupsRequest]) (*connect.Response[adminv1.ListDeviceGroupsResponse], error) {
	return connect.NewResponse(&adminv1.ListDeviceGroupsResponse{Groups: f.groups}), nil
}
func (f *fakeAdmin) SetDeviceGroup(_ context.Context, r *connect.Request[adminv1.SetDeviceGroupRequest]) (*connect.Response[adminv1.SetDeviceGroupResponse], error) {
	f.requests = append(f.requests, proto.CloneOf(r.Msg))
	g := &adminv1.DeviceGroup{Id: r.Msg.GetGroupId(), Name: r.Msg.GetName(), DeviceIds: r.Msg.GetDeviceIds()}
	f.groups = append(f.groups, g)
	return connect.NewResponse(&adminv1.SetDeviceGroupResponse{Group: g}), nil
}
func (f *fakeAdmin) GetProfileRevision(_ context.Context, r *connect.Request[adminv1.GetProfileRevisionRequest]) (*connect.Response[adminv1.GetProfileRevisionResponse], error) {
	p := f.profiles[r.Msg.GetProfileId()]
	if p == nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("missing profile"))
	}
	return connect.NewResponse(&adminv1.GetProfileRevisionResponse{Revision: p}), nil
}
func (f *fakeAdmin) PublishProfileRevision(_ context.Context, r *connect.Request[adminv1.PublishProfileRevisionRequest]) (*connect.Response[adminv1.PublishProfileRevisionResponse], error) {
	old := f.profiles[r.Msg.GetProfileId()]
	if old.GetRevisionId() != r.Msg.GetExpectedRevisionId() {
		return nil, connect.NewError(connect.CodeAborted, errors.New("stale head"))
	}
	f.requests = append(f.requests, proto.CloneOf(r.Msg))
	p := &adminv1.ProfileRevision{ProfileId: r.Msg.GetProfileId(), RevisionId: uuid.NewString(), RevisionNumber: old.GetRevisionNumber() + 1, Spec: proto.CloneOf(r.Msg.GetSpec())}
	f.profiles[p.ProfileId] = p
	return connect.NewResponse(&adminv1.PublishProfileRevisionResponse{Revision: p}), nil
}
func (f *fakeAdmin) ListTargetAssignments(context.Context, *connect.Request[adminv1.ListTargetAssignmentsRequest]) (*connect.Response[adminv1.ListTargetAssignmentsResponse], error) {
	return connect.NewResponse(&adminv1.ListTargetAssignmentsResponse{Assignments: f.assignments}), nil
}
func (f *fakeAdmin) ListProvisioningTokens(context.Context, *connect.Request[adminv1.ListProvisioningTokensRequest]) (*connect.Response[adminv1.ListProvisioningTokensResponse], error) {
	return connect.NewResponse(&adminv1.ListProvisioningTokensResponse{Tokens: f.tokens}), nil
}
func (f *fakeAdmin) CreateProvisioningToken(_ context.Context, r *connect.Request[adminv1.CreateProvisioningTokenRequest]) (*connect.Response[adminv1.CreateProvisioningTokenResponse], error) {
	f.requests = append(f.requests, proto.CloneOf(r.Msg))
	now := time.Unix(1700000000, 0)
	token := &adminv1.ProvisioningToken{TokenId: uuid.NewString(), Name: r.Msg.GetName(), MaxUses: r.Msg.GetMaxUses(), ApprovalRequired: r.Msg.GetApprovalRequired(), Metadata: r.Msg.GetMetadata(), GroupIds: r.Msg.GetGroupIds(), ProfileRevisionIds: r.Msg.GetProfileRevisionIds(), CreatedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(time.Duration(r.Msg.GetLifetimeSeconds()) * time.Second))}
	f.tokens = append(f.tokens, token)
	return connect.NewResponse(&adminv1.CreateProvisioningTokenResponse{TokenId: token.TokenId, Secret: "private-token", ExpiresAt: token.ExpiresAt}), nil
}
func (f *fakeAdmin) ListEnrollmentGrants(context.Context, *connect.Request[adminv1.ListEnrollmentGrantsRequest]) (*connect.Response[adminv1.ListEnrollmentGrantsResponse], error) {
	return connect.NewResponse(&adminv1.ListEnrollmentGrantsResponse{Grants: f.grants}), nil
}
func (f *fakeAdmin) CreateEnrollmentGrant(_ context.Context, r *connect.Request[adminv1.CreateEnrollmentGrantRequest]) (*connect.Response[adminv1.CreateEnrollmentGrantResponse], error) {
	if f.failGrant {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("grant unavailable"))
	}
	f.requests = append(f.requests, proto.CloneOf(r.Msg))
	now := time.Unix(1700000000, 0)
	g := &adminv1.EnrollmentGrant{GrantId: uuid.NewString(), Name: r.Msg.GetName(), Status: adminv1.EnrollmentGrantStatus_ENROLLMENT_GRANT_STATUS_ACTIVE, CreatedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(time.Duration(r.Msg.GetLifetimeSeconds()) * time.Second))}
	f.grants = append(f.grants, g)
	return connect.NewResponse(&adminv1.CreateEnrollmentGrantResponse{GrantId: g.GrantId, Secret: "private-grant", ExpiresAt: g.ExpiresAt}), nil
}
func (f *fakeAdmin) ListDevices(context.Context, *connect.Request[adminv1.ListDevicesRequest]) (*connect.Response[adminv1.ListDevicesResponse], error) {
	return connect.NewResponse(&adminv1.ListDevicesResponse{Devices: f.fleet}), nil
}

// PreviewTargetAssignmentImpact reports one included device whose change is
// controlled by impactChanged; a SYSCTL adoption requires approval.
func (f *fakeAdmin) PreviewTargetAssignmentImpact(_ context.Context, r *connect.Request[adminv1.PreviewTargetAssignmentImpactRequest]) (*connect.Response[adminv1.PreviewTargetAssignmentImpactResponse], error) {
	saved := f.assignment(r.Msg.GetAssignment().GetAssignmentId())
	if saved.GetRevision() != r.Msg.GetExpectedRevision() {
		return nil, rpcreason.Error(connect.CodeAborted, "targeting_revision_conflict")
	}
	report := &adminv1.PreviewTargetAssignmentImpactResponse{PreviewId: uuid.NewString(), Assignment: proto.CloneOf(r.Msg.GetAssignment()), ExpectedRevision: r.Msg.GetExpectedRevision(), Complete: true, ReviewSha256: make([]byte, 32), IncludedCount: 1, Devices: []*adminv1.TargetAssignmentDeviceImpact{{DeviceId: uuid.NewString(), Hostname: "laptop", Match: policyv1.TargetMatch_TARGET_MATCH_INCLUDED, Changed: saved == nil || f.impactChanged || f.profileChanged(r.Msg.GetAssignment())}}}
	if f.requireApproval {
		report.ApprovalRequired, report.AdoptingCount = true, 1
	}
	if report.Devices[0].Changed {
		report.ChangedCount = 1
	}
	if f.noDevices {
		report.Devices, report.IncludedCount = nil, 0
	}
	return connect.NewResponse(report), nil
}
func (f *fakeAdmin) assignment(id string) *policyv1.TargetCandidate {
	for _, a := range f.assignments {
		if a.GetAssignment().GetAssignmentId() == id {
			return a
		}
	}
	return nil
}
func (f *fakeAdmin) profileChanged(a *policyv1.TargetAssignment) bool {
	return f.assignment(a.GetAssignmentId()).GetAssignment().GetProfileRevisionId() != a.GetProfileRevisionId()
}

// StartRollout models the server: an approval-free rollout saves the assignment
// at once; one needing approval saves nothing until it is decided.
func (f *fakeAdmin) StartRollout(_ context.Context, r *connect.Request[adminv1.StartRolloutRequest]) (*connect.Response[adminv1.StartRolloutResponse], error) {
	if f.staleStarts > 0 {
		f.staleStarts--
		return nil, rpcreason.Error(connect.CodeAborted, "targeting_impact_stale")
	}
	if f.noDevices {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "targeting_not_ready")
	}
	for _, existing := range f.rollouts {
		if existing.GetRollout().GetRolloutId() == r.Msg.GetRollout().GetRolloutId() {
			return nil, rpcreason.Error(connect.CodeAborted, "targeting_revision_conflict")
		}
	}
	saved := f.assignment(r.Msg.GetAssignment().GetAssignmentId())
	if saved.GetRevision() != r.Msg.GetExpectedRevision() {
		return nil, rpcreason.Error(connect.CodeAborted, "targeting_revision_conflict")
	}
	f.requests = append(f.requests, proto.CloneOf(r.Msg))
	state := &adminv1.RolloutState{Rollout: proto.CloneOf(r.Msg.GetRollout()), Assignment: proto.CloneOf(r.Msg.GetAssignment()), Status: adminv1.RolloutStatus_ROLLOUT_STATUS_ACTIVE, PlannedCount: 1, ActivatedCount: 1, CreatedAt: timestamppb.New(time.Unix(1700000000+int64(len(f.rollouts)), 0))}
	if f.requireApproval {
		state.Status, state.ApprovalRequired, state.Paused = adminv1.RolloutStatus_ROLLOUT_STATUS_AWAITING_APPROVAL, true, true
		state.ActivatedCount, state.WaitingCount = 0, 1
	} else {
		assignment := proto.CloneOf(r.Msg.GetAssignment())
		assignment.RolloutId = proto.String(r.Msg.GetRollout().GetRolloutId())
		candidate := &policyv1.TargetCandidate{Assignment: assignment, Revision: r.Msg.GetExpectedRevision() + 1}
		if saved == nil {
			f.assignments = append(f.assignments, candidate)
		} else {
			saved.Assignment, saved.Revision = candidate.Assignment, candidate.Revision
		}
	}
	f.rollouts = append(f.rollouts, state)
	return connect.NewResponse(&adminv1.StartRolloutResponse{Rollout: proto.CloneOf(state)}), nil
}
func (f *fakeAdmin) PutTargetAssignment(_ context.Context, r *connect.Request[adminv1.PutTargetAssignmentRequest]) (*connect.Response[adminv1.PutTargetAssignmentResponse], error) {
	saved := f.assignment(r.Msg.GetAssignment().GetAssignmentId())
	if saved.GetRevision() != r.Msg.GetExpectedRevision() {
		return nil, rpcreason.Error(connect.CodeAborted, "targeting_revision_conflict")
	}
	f.requests = append(f.requests, proto.CloneOf(r.Msg))
	candidate := &policyv1.TargetCandidate{Assignment: proto.CloneOf(r.Msg.GetAssignment()), Revision: r.Msg.GetExpectedRevision() + 1}
	if saved == nil {
		f.assignments = append(f.assignments, candidate)
	} else {
		saved.Assignment, saved.Revision = candidate.Assignment, candidate.Revision
	}
	return connect.NewResponse(&adminv1.PutTargetAssignmentResponse{Assignment: candidate}), nil
}
func (f *fakeAdmin) ListRollouts(context.Context, *connect.Request[adminv1.ListRolloutsRequest]) (*connect.Response[adminv1.ListRolloutsResponse], error) {
	out := make([]*adminv1.RolloutState, 0, len(f.rollouts))
	for _, r := range f.rollouts {
		out = append(out, proto.CloneOf(r))
	}
	return connect.NewResponse(&adminv1.ListRolloutsResponse{Rollouts: out}), nil
}
func (f *fakeAdmin) ListApprovals(context.Context, *connect.Request[adminv1.ListApprovalsRequest]) (*connect.Response[adminv1.ListApprovalsResponse], error) {
	return connect.NewResponse(&adminv1.ListApprovalsResponse{Approvals: f.approvals, CurrentPrincipalId: f.principalID}), nil
}
func (f *fakeAdmin) CreateApproval(_ context.Context, r *connect.Request[adminv1.CreateApprovalRequest]) (*connect.Response[adminv1.CreateApprovalResponse], error) {
	f.requests = append(f.requests, proto.CloneOf(r.Msg))
	a := &adminv1.Approval{Id: uuid.NewString(), RequesterId: f.principalID, State: adminv1.ApprovalState_APPROVAL_STATE_PENDING, ExpiresAt: timestamppb.New(time.Now().Add(time.Hour))}
	switch {
	case r.Msg.GetAcceptAdvisoryFinding() != nil:
		a.Payload = &adminv1.Approval_AcceptAdvisoryFinding{AcceptAdvisoryFinding: proto.CloneOf(r.Msg.GetAcceptAdvisoryFinding())}
	case r.Msg.GetStartRollout() != nil:
		request := r.Msg.GetStartRollout()
		a.Payload = &adminv1.Approval_StartRollout{StartRollout: proto.CloneOf(request)}
		for _, state := range f.rollouts {
			if state.GetRollout().GetRolloutId() == request.GetRollout().GetRolloutId() {
				state.ApprovalId = a.Id
			}
		}
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("unexpected approval payload"))
	}
	f.approvals = append(f.approvals, a)
	return connect.NewResponse(&adminv1.CreateApprovalResponse{Approval: a}), nil
}

var _ adminv1connect.AdminServiceClient = (*fakeAdmin)(nil)

// ListDeviceFindings pages like the product: at most page_size findings and an
// opaque cursor (here the decimal offset) until the device's list is exhausted.
func (f *fakeAdmin) ListDeviceFindings(_ context.Context, request *connect.Request[adminv1.ListDeviceFindingsRequest]) (*connect.Response[adminv1.ListDeviceFindingsResponse], error) {
	f.findingCalls++
	start := 0
	if token := request.Msg.GetPageToken(); token != "" {
		if f.findingSnapshotChanges > 0 {
			f.findingSnapshotChanges--
			return nil, rpcreason.Error(connect.CodeAborted, "advisory_evidence_changed")
		}
		var err error
		if start, err = strconv.Atoi(token); err != nil || start < 0 || start > len(f.findings) {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid page token"))
		}
	}
	end := min(start+int(request.Msg.GetPageSize()), len(f.findings))
	response := &adminv1.ListDeviceFindingsResponse{Findings: f.findings[start:end]}
	if end < len(f.findings) {
		response.NextPageToken = strconv.Itoa(end)
	}
	return connect.NewResponse(response), nil
}
func (f *fakeAdmin) AcceptAdvisoryFinding(_ context.Context, request *connect.Request[adminv1.AcceptAdvisoryFindingRequest]) (*connect.Response[adminv1.AcceptAdvisoryFindingResponse], error) {
	f.requests = append(f.requests, proto.CloneOf(request.Msg))
	exception := &adminv1.AdvisoryException{Reason: request.Msg.GetReason(), ExpiresAt: timestamppb.New(request.Msg.GetExpiresAt().AsTime().Truncate(time.Microsecond))}
	for _, finding := range f.findings {
		if finding.GetId() == request.Msg.GetFindingId() {
			finding.Exception = exception
			finding.State = adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_ACCEPTED
		}
	}
	return connect.NewResponse(&adminv1.AcceptAdvisoryFindingResponse{Exception: exception}), nil
}
