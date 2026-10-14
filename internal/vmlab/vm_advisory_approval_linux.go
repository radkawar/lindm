// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/devlab"
	"lindm/internal/identity"
	"lindm/internal/platform"
	"lindm/internal/rpcreason"
)

// VMAdvisoryApprovalEvidence binds actual installed inventory and vendor findings
// to two independently authenticated humans and the exact acceptance result.
type VMAdvisoryApprovalEvidence struct {
	Native              VMResourceNativeRecord      `json:"native"`
	ControlPlaneOS      string                      `json:"control_plane_os"`
	Finding             *adminv1.AdvisoryFinding    `json:"finding"`
	AcceptedFinding     *adminv1.AdvisoryFinding    `json:"accepted_finding"`
	Freshness           *adminv1.AdvisoryFreshness  `json:"freshness"`
	Approval            *adminv1.Approval           `json:"approval"`
	Exception           *adminv1.AdvisoryException  `json:"exception"`
	Refusals            map[string]string           `json:"refusals"`
	ExactRetry          bool                        `json:"exact_retry"`
	Consumed            bool                        `json:"consumed"`
	AuthorizationBefore *adminv1.AuthorizationState `json:"authorization_before"`
	AuthorizationAfter  *adminv1.AuthorizationState `json:"authorization_after"`
}

func exerciseAdvisoryApproval(ctx context.Context, vm *guestVM, control *vmControlPlane, fixture *devlab.AuthorityFixture, result *VMDispatchResult, release *platform.Release, architecture, cache string) error {
	evidence := result.AdvisoryExceptions
	hostOS, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return err
	}
	evidence.ControlPlaneOS = string(hostOS)
	cfg, err := devlab.HeldAdvisories(*release, architecture)
	if err != nil {
		return err
	}
	if err := fixture.EnableAdvisories(ctx, cfg, cache); err != nil {
		return err
	}
	if _, err := devlab.WaitDeviceFindings(ctx, control.session, result.DeviceID, 5*time.Minute); err != nil {
		return err
	}
	list, err := control.session.Admin.ListDeviceFindings(ctx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: result.DeviceID, PageSize: 200}))
	if err != nil {
		return err
	}
	for _, finding := range list.Msg.GetFindings() {
		if finding.GetState() == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED {
			evidence.Finding = finding
			break
		}
	}
	if evidence.Finding == nil {
		return errors.New("native inventory has no affected vendor finding; no approval qualification claimed")
	}
	evidence.Freshness = list.Msg.GetFreshness()
	evidence.Native, err = resourceOracle(ctx, vm, "native-advisory-platform", "cat /etc/os-release; uname -m")
	if err != nil {
		return err
	}
	evidence.Refusals = make(map[string]string)
	request := &adminv1.AcceptAdvisoryFindingRequest{RequestId: uuid.NewString(), DeviceId: result.DeviceID, FindingId: evidence.Finding.GetId(), Reason: "Disposable native two-human exception qualification", ExpiresAt: timestamppb.New(time.Now().Add(time.Hour))}
	// The requester is already authenticated. Enable the persisted policy through
	// another owner session, then keep this original session for every refusal and
	// acceptance. This catches cached startup-policy/no-approval branches.
	before, err := control.session.Admin.GetAuthorization(ctx, connect.NewRequest(&adminv1.GetAuthorizationRequest{}))
	if err != nil {
		return err
	}
	evidence.AuthorizationBefore = before.Msg.GetAuthorization()
	permission := string(identity.PermissionManageAdvisoryExceptions)
	if slices.Contains(evidence.AuthorizationBefore.GetPolicy().GetApprovalRequiredPermissions(), permission) {
		return errors.New("advisory gate was already enabled; runtime transition is not qualified")
	}
	if err := fixture.RequireAdvisoryApproval(ctx); err != nil {
		return err
	}
	after, err := control.session.Admin.GetAuthorization(ctx, connect.NewRequest(&adminv1.GetAuthorizationRequest{}))
	if err != nil {
		return err
	}
	evidence.AuthorizationAfter = after.Msg.GetAuthorization()
	if !evidence.AuthorizationAfter.GetRuntime() ||
		evidence.AuthorizationAfter.GetRevision() != evidence.AuthorizationBefore.GetRevision()+1 ||
		!slices.Contains(evidence.AuthorizationAfter.GetPolicy().GetApprovalRequiredPermissions(), permission) {
		return errors.New("runtime advisory gate replacement was not observed by the original requester session")
	}
	refuse := func(name string, err error) error {
		if connect.CodeOf(err) != connect.CodePermissionDenied {
			return fmt.Errorf("%s did not refuse authority: %w", name, err)
		}
		evidence.Refusals[name] = rpcreason.Get(err)
		return nil
	}
	_, err = control.session.Admin.AcceptAdvisoryFinding(ctx, connect.NewRequest(request))
	if err := refuse("missing_approval", err); err != nil {
		return err
	}
	proposal := &adminv1.CreateApprovalRequest{LifetimeSeconds: 3600, Payload: &adminv1.CreateApprovalRequest_AcceptAdvisoryFinding{AcceptAdvisoryFinding: request}}
	created, err := control.session.Admin.CreateApproval(ctx, connect.NewRequest(proposal))
	if err != nil {
		return err
	}
	request.ApprovalId = created.Msg.GetApproval().GetId()
	_, err = control.session.Admin.AcceptAdvisoryFinding(ctx, connect.NewRequest(request))
	if err := refuse("pending_approval", err); err != nil {
		return err
	}
	_, err = control.session.Admin.ApproveApproval(ctx, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: request.ApprovalId, Reason: "Self approval must be refused"}))
	if err := refuse("self_approval", err); err != nil {
		return err
	}
	approver, err := control.openApprover(ctx)
	if err != nil {
		return err
	}
	control.approver = approver
	evidence.Approval, err = approver.Approve(ctx, control.session, proposal)
	if err != nil {
		return err
	}
	for _, change := range []struct {
		name   string
		mutate func(*adminv1.AcceptAdvisoryFindingRequest)
	}{
		{"reason_substitution", func(r *adminv1.AcceptAdvisoryFindingRequest) { r.Reason += " changed" }},
		{"expiry_substitution", func(r *adminv1.AcceptAdvisoryFindingRequest) { r.ExpiresAt.Seconds++ }},
		{"finding_substitution", func(r *adminv1.AcceptAdvisoryFindingRequest) { r.FindingId = uuid.NewString() }},
	} {
		changed := proto.CloneOf(request)
		change.mutate(changed)
		_, err := control.session.Admin.AcceptAdvisoryFinding(ctx, connect.NewRequest(changed))
		if err := refuse(change.name, err); err != nil {
			return err
		}
	}
	accepted, err := control.session.Admin.AcceptAdvisoryFinding(ctx, connect.NewRequest(request))
	if err != nil {
		return err
	}
	evidence.Exception = accepted.Msg.GetException()
	replayed, err := control.session.Admin.AcceptAdvisoryFinding(ctx, connect.NewRequest(request))
	if err != nil {
		return err
	}
	evidence.ExactRetry = proto.Equal(accepted.Msg, replayed.Msg)
	approvals, err := control.session.Admin.ListApprovals(ctx, connect.NewRequest(&adminv1.ListApprovalsRequest{PageSize: 200}))
	if err != nil {
		return err
	}
	for _, approval := range approvals.Msg.GetApprovals() {
		if approval.GetId() == request.ApprovalId {
			evidence.Consumed = approval.GetState() == adminv1.ApprovalState_APPROVAL_STATE_CONSUMED
		}
	}
	if !evidence.ExactRetry || !evidence.Consumed {
		return errors.New("exact exception retry or atomic approval consumption unproven")
	}
	updated, err := control.session.Admin.ListDeviceFindings(ctx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: result.DeviceID, PageSize: 200}))
	if err != nil {
		return err
	}
	for _, finding := range updated.Msg.GetFindings() {
		if finding.GetId() == request.GetFindingId() {
			evidence.AcceptedFinding = finding
			if finding.GetState() == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_ACCEPTED && proto.Equal(finding.GetException(), evidence.Exception) {
				return nil
			}
		}
	}
	return errors.New("accepted risk is not reflected on the exact native finding")

}
