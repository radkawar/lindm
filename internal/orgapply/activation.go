package orgapply

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	adminv1connect "lindm/gen/lindm/admin/v1/adminv1connect"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/rpcreason"
)

func activate(ctx context.Context, client adminv1connect.AdminServiceClient, plan *ChangePlan, result *Result) error {
	fleet, err := devices(ctx, client)
	if err != nil {
		return fmt.Errorf("list activation devices: %w", err)
	}
	// The desired document identity keeps a pending exact request from being reused
	// after Git changes the requested organization. Membership/head changes remain
	// fenced by ActivateTargetPreview on the server, never bypassed here.
	identity, err := requestID(plan.spec.GetName(), "activation", "organization", plan.spec)
	if err != nil {
		return err
	}
	activationReason := reason(plan.spec) + " targeting " + identity
	own := make(map[string]bool, len(plan.spec.GetAssignments()))
	for _, a := range plan.spec.GetAssignments() {
		own[a.GetAssignment().GetAssignmentId()] = true
	}
	var approvals []*adminv1.Approval
	var currentPrincipal string
	for _, device := range fleet {
		if device.GetLifecycleState() != adminv1.DeviceState_DEVICE_STATE_ACTIVE {
			continue
		}
		outcome := Outcome{Kind: "activation", Name: device.GetHostname(), ID: device.GetId()}
		current, err := client.GetDeviceResourceState(ctx, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: device.GetId()}))
		if err != nil {
			return fmt.Errorf("get activation state: %w", err)
		}
		response, err := client.PreviewTargetAssignments(ctx, connect.NewRequest(&adminv1.PreviewTargetAssignmentsRequest{DeviceId: device.GetId()}))
		if err != nil {
			return fmt.Errorf("preview target assignments: %w", err)
		}
		preview := response.Msg.GetPreview()
		active := current.Msg.GetActiveTargetPreview()
		if !hasOwnedCandidate(preview, own) && !hasOwnedCandidate(active, own) {
			continue
		}
		if sameActivation(active, preview) {
			outcome.Status = "unchanged"
			result.Outcomes = append(result.Outcomes, outcome)
			continue
		}
		if blockedPreview(preview, own) {
			outcome.Status = "pending"
			outcome.Detail = "target membership or resource resolution is not ready"
			result.Outcomes = append(result.Outcomes, outcome)
			continue
		}
		request := &adminv1.ActivateTargetPreviewRequest{DeviceId: device.GetId(), PreviewId: preview.GetPreviewId(), PreviewSha256: preview.GetPreviewSha256(), Reason: activationReason}
		if err := completeRequest(plan.spec.GetName(), "activation", device.GetId(), request); err != nil {
			return err
		}
		_, err = client.ActivateTargetPreview(ctx, connect.NewRequest(request))
		if err == nil {
			outcome.Status = "updated"
			result.Outcomes = append(result.Outcomes, outcome)
			continue
		}
		if rpcreason.Get(err) != "approval_required" {
			return fmt.Errorf("activate target preview: %w", err)
		}
		// Only query the approval inbox when the server requires approval. Operators
		// who need no approval must not acquire approvals.manage just to apply profiles.
		if approvals == nil {
			approvals, err = pages(func(token string) ([]*adminv1.Approval, string, error) {
				r, e := client.ListApprovals(ctx, connect.NewRequest(&adminv1.ListApprovalsRequest{PageSize: 200, PageToken: token}))
				if e != nil {
					return nil, "", e
				}
				if r.Msg.GetCurrentPrincipalId() == "" || (currentPrincipal != "" && currentPrincipal != r.Msg.GetCurrentPrincipalId()) {
					return nil, "", errors.New("orgapply: approval page lacks a stable authenticated principal")
				}
				currentPrincipal = r.Msg.GetCurrentPrincipalId()
				return r.Msg.GetApprovals(), r.Msg.GetNextPageToken(), nil
			})
			if err != nil {
				return fmt.Errorf("list target approvals: %w", err)
			}
		}
		var retained *adminv1.Approval
		for _, a := range approvals {
			if reusableApproval(a, preview, currentPrincipal, activationReason) {
				retained = a
				break
			}
		}
		if retained != nil {
			if retained.GetState() == adminv1.ApprovalState_APPROVAL_STATE_APPROVED {
				approved := proto.CloneOf(retained.GetActivateTargetPreview())
				approved.ApprovalId = proto.String(retained.GetId())
				if _, err := client.ActivateTargetPreview(ctx, connect.NewRequest(approved)); err != nil {
					return fmt.Errorf("activate approved target preview: %w", err)
				}
				outcome.Status = "updated"
				result.Outcomes = append(result.Outcomes, outcome)
				continue
			}
			outcome.Status = "pending"
			outcome.Detail = "requires independent approval " + retained.GetId()
			result.Outcomes = append(result.Outcomes, outcome)
			continue
		}
		created, err := client.CreateApproval(ctx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 900, Payload: &adminv1.CreateApprovalRequest_ActivateTargetPreview{ActivateTargetPreview: request}}))
		if err != nil {
			return fmt.Errorf("request target approval: %w", err)
		}
		approvals = append(approvals, created.Msg.GetApproval())
		outcome.Status = "pending"
		outcome.Detail = "requires independent approval " + created.Msg.GetApproval().GetId()
		result.Outcomes = append(result.Outcomes, outcome)
	}
	return nil
}

func hasOwnedCandidate(preview *policyv1.TargetPreview, own map[string]bool) bool {
	for _, c := range preview.GetCandidates() {
		if own[c.GetAssignment().GetAssignmentId()] && c.GetMatch() != policyv1.TargetMatch_TARGET_MATCH_EXCLUDED {
			return true
		}
	}
	return false
}
func blockedPreview(preview *policyv1.TargetPreview, own map[string]bool) bool {
	for _, c := range preview.GetCandidates() {
		if own[c.GetAssignment().GetAssignmentId()] && c.GetMatch() == policyv1.TargetMatch_TARGET_MATCH_UNKNOWN {
			return true
		}
	}
	for _, r := range preview.GetResolution().GetResources() {
		if r.GetDisposition() != policyv1.ResourceResolutionDisposition_RESOURCE_RESOLUTION_DISPOSITION_READY {
			return true
		}
	}
	return false
}
func sameActivation(active, preview *policyv1.TargetPreview) bool {
	return active != nil && active.GetGenerationId() == preview.GetGenerationId() && bytes.Equal(active.GetResolutionSha256(), preview.GetResolutionSha256()) && proto.Equal(active.GetResolution(), preview.GetResolution()) && slices.EqualFunc(active.GetCandidates(), preview.GetCandidates(), func(a, b *policyv1.TargetCandidate) bool { return proto.Equal(a, b) })
}

func reusableApproval(approval *adminv1.Approval, current *policyv1.TargetPreview, principal, reason string) bool {
	request, retained := approval.GetActivateTargetPreview(), approval.GetTargetPreview()
	if principal == "" || approval.GetRequesterId() != principal || request.GetDeviceId() != current.GetDeviceId() || request.GetReason() != reason {
		return false
	}
	if approval.GetState() != adminv1.ApprovalState_APPROVAL_STATE_PENDING && approval.GetState() != adminv1.ApprovalState_APPROVAL_STATE_APPROVED {
		return false
	}
	if retained == nil || retained.GetValidUntil() == nil || current.GetEvaluatedAt() == nil || approval.GetExpiresAt() == nil || len(current.GetInputSha256()) != 32 {
		return false
	}
	now := current.GetEvaluatedAt().AsTime()
	return retained.GetValidUntil().AsTime().After(now) && approval.GetExpiresAt().AsTime().After(now) &&
		retained.GetDeviceId() == current.GetDeviceId() && retained.GetGenerationId() == current.GetGenerationId() &&
		retained.GetPreviewId() == request.GetPreviewId() && bytes.Equal(retained.GetPreviewSha256(), request.GetPreviewSha256()) &&
		bytes.Equal(retained.GetInputSha256(), current.GetInputSha256())
}
