package orgapply

import (
	"context"
	"errors"
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
	groups          []*adminv1.DeviceGroup
	profiles        map[string]*adminv1.ProfileRevision
	assignments     []*policyv1.TargetCandidate
	tokens          []*adminv1.ProvisioningToken
	grants          []*adminv1.EnrollmentGrant
	requests        []proto.Message
	failGrant       bool
	fleet           []*adminv1.Device
	preview         *policyv1.TargetPreview
	active          *policyv1.TargetPreview
	requireApproval bool
	approvals       []*adminv1.Approval
	findings        []*adminv1.AdvisoryFinding
	principalID     string
}

func newFakeAdmin() *fakeAdmin {
	return &fakeAdmin{profiles: make(map[string]*adminv1.ProfileRevision)}
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
func (f *fakeAdmin) PutTargetAssignment(_ context.Context, r *connect.Request[adminv1.PutTargetAssignmentRequest]) (*connect.Response[adminv1.PutTargetAssignmentResponse], error) {
	f.requests = append(f.requests, proto.CloneOf(r.Msg))
	candidate := &policyv1.TargetCandidate{Assignment: proto.CloneOf(r.Msg.GetAssignment()), Revision: r.Msg.GetExpectedRevision() + 1}
	for i, a := range f.assignments {
		if a.GetAssignment().GetAssignmentId() == candidate.GetAssignment().GetAssignmentId() {
			if a.GetRevision() != r.Msg.GetExpectedRevision() {
				return nil, connect.NewError(connect.CodeAborted, errors.New("stale assignment"))
			}
			f.assignments[i] = candidate
			return connect.NewResponse(&adminv1.PutTargetAssignmentResponse{Assignment: candidate}), nil
		}
	}
	f.assignments = append(f.assignments, candidate)
	return connect.NewResponse(&adminv1.PutTargetAssignmentResponse{Assignment: candidate}), nil
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
func (f *fakeAdmin) GetDeviceResourceState(context.Context, *connect.Request[adminv1.GetDeviceResourceStateRequest]) (*connect.Response[adminv1.GetDeviceResourceStateResponse], error) {
	return connect.NewResponse(&adminv1.GetDeviceResourceStateResponse{ActiveTargetPreview: f.active}), nil
}
func (f *fakeAdmin) PreviewTargetAssignments(context.Context, *connect.Request[adminv1.PreviewTargetAssignmentsRequest]) (*connect.Response[adminv1.PreviewTargetAssignmentsResponse], error) {
	return connect.NewResponse(&adminv1.PreviewTargetAssignmentsResponse{Preview: f.preview}), nil
}
func (f *fakeAdmin) ActivateTargetPreview(_ context.Context, r *connect.Request[adminv1.ActivateTargetPreviewRequest]) (*connect.Response[adminv1.ActivateTargetPreviewResponse], error) {
	if f.requireApproval && r.Msg.GetApprovalId() == "" {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "approval_required")
	}
	f.requests = append(f.requests, proto.CloneOf(r.Msg))
	f.active = proto.CloneOf(f.preview)
	return connect.NewResponse(&adminv1.ActivateTargetPreviewResponse{Preview: f.active}), nil
}
func (f *fakeAdmin) ListApprovals(context.Context, *connect.Request[adminv1.ListApprovalsRequest]) (*connect.Response[adminv1.ListApprovalsResponse], error) {
	return connect.NewResponse(&adminv1.ListApprovalsResponse{Approvals: f.approvals, CurrentPrincipalId: f.principalID}), nil
}
func (f *fakeAdmin) CreateApproval(_ context.Context, r *connect.Request[adminv1.CreateApprovalRequest]) (*connect.Response[adminv1.CreateApprovalResponse], error) {
	f.requests = append(f.requests, proto.CloneOf(r.Msg))
	a := &adminv1.Approval{Id: uuid.NewString(), RequesterId: f.principalID, State: adminv1.ApprovalState_APPROVAL_STATE_PENDING, ExpiresAt: timestamppb.New(f.preview.GetEvaluatedAt().AsTime().Add(900 * time.Second)), TargetPreview: proto.CloneOf(f.preview), Payload: &adminv1.Approval_ActivateTargetPreview{ActivateTargetPreview: proto.CloneOf(r.Msg.GetActivateTargetPreview())}}
	f.approvals = append(f.approvals, a)
	return connect.NewResponse(&adminv1.CreateApprovalResponse{Approval: a}), nil
}

var _ adminv1connect.AdminServiceClient = (*fakeAdmin)(nil)

func (f *fakeAdmin) ListDeviceFindings(context.Context, *connect.Request[adminv1.ListDeviceFindingsRequest]) (*connect.Response[adminv1.ListDeviceFindingsResponse], error) {
	return connect.NewResponse(&adminv1.ListDeviceFindingsResponse{Findings: f.findings}), nil
}
func (f *fakeAdmin) AcceptAdvisoryFinding(_ context.Context, request *connect.Request[adminv1.AcceptAdvisoryFindingRequest]) (*connect.Response[adminv1.AcceptAdvisoryFindingResponse], error) {
	f.requests = append(f.requests, proto.CloneOf(request.Msg))
	exception := &adminv1.AdvisoryException{Reason: request.Msg.GetReason(), ExpiresAt: request.Msg.GetExpiresAt()}
	for _, finding := range f.findings {
		if finding.GetId() == request.Msg.GetFindingId() {
			finding.Exception = exception
			finding.State = adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_ACCEPTED
		}
	}
	return connect.NewResponse(&adminv1.AcceptAdvisoryFindingResponse{Exception: exception}), nil
}
