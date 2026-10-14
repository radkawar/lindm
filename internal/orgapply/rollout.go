// SPDX-License-Identifier: Apache-2.0

package orgapply

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	adminv1connect "lindm/gen/lindm/admin/v1/adminv1connect"
	orgv1 "lindm/gen/lindm/org/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/rpcreason"
)

// latestRollout is the newest reviewed rollout of one assignment.
func latestRollout(rollouts []*adminv1.RolloutState, assignmentID string) *adminv1.RolloutState {
	var latest *adminv1.RolloutState
	for _, r := range rollouts {
		if r.GetAssignment().GetAssignmentId() != assignmentID || r.GetCreatedAt() == nil {
			continue
		}
		if latest == nil || r.GetCreatedAt().AsTime().After(latest.GetCreatedAt().AsTime()) {
			latest = r
		}
	}
	return latest
}

// rolloutHeld reports how an unchanged declaration stands while its latest
// rollout is in flight: "pending" when it needs an administrator (approval or
// a paused rollout), "unchanged" while devices are still being admitted.
func rolloutHeld(r *adminv1.RolloutState) (string, string) {
	switch {
	case r == nil:
		return "", ""
	case r.GetStatus() == adminv1.RolloutStatus_ROLLOUT_STATUS_AWAITING_APPROVAL:
		if r.GetApprovalId() == "" {
			return "pending", "rollout awaits an approval request; it expires unless requested in the console"
		}
		return "pending", "requires independent approval " + r.GetApprovalId()
	case r.GetStatus() == adminv1.RolloutStatus_ROLLOUT_STATUS_ACTIVE && r.GetPaused() && r.GetWaitingCount()+r.GetStartingCount() > 0:
		// A paused rollout needs an administrator's decision; apply never
		// replaces it with a new one.
		return "pending", "rollout paused (" + r.GetPauseReason() + "); resume or roll out again in the console"
	case r.GetStatus() == adminv1.RolloutStatus_ROLLOUT_STATUS_ACTIVE && r.GetWaitingCount()+r.GetStartingCount() > 0:
		return "unchanged", fmt.Sprintf("rolling out: %d devices waiting, %d starting", r.GetWaitingCount(), r.GetStartingCount())
	}
	return "", ""
}

// rolloutPlan is a declared stage template with every cohort forced to the
// assignment target, or one stage for every targeted device.
func rolloutPlan(spec *orgv1.Organization, declared *orgv1.Assignment, assignment *policyv1.TargetAssignment, template *policyv1.RolloutSpec) *policyv1.RolloutSpec {
	out := &policyv1.RolloutSpec{Name: rolloutName(spec, declared, assignment)}
	if template != nil {
		for _, ring := range template.GetRings() {
			ring = proto.CloneOf(ring)
			ring.Cohort = proto.CloneOf(assignment.GetTarget())
			out.Rings = append(out.Rings, ring)
		}
		return out
	}
	out.Rings = []*policyv1.RolloutRing{{
		Name: "everyone", Cohort: proto.CloneOf(assignment.GetTarget()), CumulativeBasisPoints: 10000,
		MinimumCanaries: 1, MinimumObserved: 1, SoakSeconds: 3600, HealthMaxAgeSeconds: 86400,
		// One stage has no successor to protect, and a pause would withhold
		// remediation from every device of a declared baseline: failures are
		// reported per device instead of pausing it.
		FailureBasisPoints: 10000, UnknownBasisPoints: 10000, UnavailableBasisPoints: 10000,
	}}
	return out
}

func rolloutName(spec *orgv1.Organization, declared *orgv1.Assignment, assignment *policyv1.TargetAssignment) string {
	profile := declared.GetProfileId()
	for _, p := range spec.GetProfiles() {
		if p.GetId() == declared.GetProfileId() {
			profile = p.GetSpec().GetName()
		}
	}
	target := "one device"
	switch t := assignment.GetTarget(); {
	case t.GetDynamicGroupId() != "":
		target = t.GetDynamicGroupId()
		for _, g := range spec.GetDynamicGroups() {
			if g.GetGroupId() == t.GetDynamicGroupId() {
				target = g.GetName()
			}
		}
	case t.GetStaticGroupId() != "":
		target = t.GetStaticGroupId()
		for _, g := range spec.GetGroups() {
			if g.GetId() == t.GetStaticGroupId() {
				target = g.GetName()
			}
		}
	}
	name := profile + " to " + target
	if len(name) > 128 {
		name = name[:128]
	}
	return name
}

// applyRollout reviews the assignment's current impact and starts one rollout of
// that exact review. A required approval yields a pending outcome and one
// approval request, never an apply failure.
func applyRollout(ctx context.Context, client adminv1connect.AdminServiceClient, org string, op operation, revision string, outcome *Outcome) error {
	// Concurrent check-ins or membership changes can invalidate a review between
	// reading and starting it. Review afresh a bounded number of times, then
	// report the assignment pending rather than failing the whole apply.
	for attempt := 0; ; attempt++ {
		err := reviewAndStart(ctx, client, org, op, revision, outcome)
		switch rpcreason.Get(err) {
		case "targeting_revision_conflict", "targeting_impact_stale":
			if attempt < 2 {
				continue
			}
			outcome.Status, outcome.Detail = "pending", "targeting inputs kept changing during review; apply again"
			return nil
		}
		return err
	}
}

func reviewAndStart(ctx context.Context, client adminv1connect.AdminServiceClient, org string, op operation, revision string, outcome *Outcome) error {
	planned, ok := op.request.(*adminv1.StartRolloutRequest)
	if !ok {
		return errors.New("orgapply: rollout operation without a rollout request")
	}
	request := proto.CloneOf(planned)
	request.Assignment.ProfileRevisionId = revision
	review, err := client.PreviewTargetAssignmentImpact(ctx, connect.NewRequest(&adminv1.PreviewTargetAssignmentImpactRequest{Assignment: request.GetAssignment(), ExpectedRevision: request.GetExpectedRevision(), PageSize: 20}))
	if err != nil {
		return fmt.Errorf("review impact: %w", err)
	}
	report := review.Msg
	if !report.GetComplete() {
		outcome.Status, outcome.Detail = "pending", fmt.Sprintf("impact review incomplete: %v", report.GetReasons())
		return nil
	}
	if op.reviewOnly {
		// Counts cover the complete report: included devices whose settings
		// change, and devices whose settings this assignment would remove. An
		// unchanged declaration never overrides a direct per-device assignment
		// an administrator made on the device; changing it does, after review.
		if report.GetChangedCount()+report.GetRemovingCount() <= report.GetReplacingDirectCount() {
			if report.GetReplacingDirectCount() > 0 {
				outcome.Detail = fmt.Sprintf("%d devices keep a direct assignment", report.GetReplacingDirectCount())
			}
			return nil
		}
		outcome.Status, outcome.Detail = "updated", "devices changed since the last rollout"
	}
	request.PreviewId, request.ReviewSha256 = report.GetPreviewId(), report.GetReviewSha256()
	// The rollout identity binds the assignment, its saved revision, the desired
	// definition and the rollout it follows, so a re-run cannot fork a second plan.
	identity, err := requestID(org, "rollout", op.outcome.ID+"\x00"+op.predecessorID, &adminv1.StartRolloutRequest{Assignment: request.GetAssignment(), ExpectedRevision: request.GetExpectedRevision(), Rollout: request.GetRollout()})
	if err != nil {
		return err
	}
	salt := sha256.Sum256([]byte("lindm.orgapply.rollout.salt.v1\x00" + identity))
	request.Rollout.RolloutId, request.Rollout.Salt = identity, salt[:]
	request.RequestId = uuid.NewSHA1(uuid.NameSpaceURL, []byte("lindm.orgapply.rollout.request.v1\x00"+identity+"\x00"+report.GetPreviewId())).String()
	started, err := client.StartRollout(ctx, connect.NewRequest(request))
	if rpcreason.Get(err) == "targeting_not_ready" {
		// No active device would change: there is nothing to roll out or approve.
		// Save the declared assignment so it is in effect when devices match;
		// a later apply rolls those devices out after reviewing them.
		if op.reviewOnly {
			return nil
		}
		return saveAssignment(ctx, client, org, op, request, outcome)
	}
	if err != nil {
		return fmt.Errorf("start rollout: %w", err)
	}
	state := started.Msg.GetRollout()
	outcome.ID = state.GetRollout().GetRolloutId()
	if state.GetStatus() != adminv1.RolloutStatus_ROLLOUT_STATUS_AWAITING_APPROVAL {
		outcome.Detail = fmt.Sprintf("rolling out to %d devices", state.GetPlannedCount())
		return nil
	}
	approval := state.GetApprovalId()
	if approval == "" {
		created, err := client.CreateApproval(ctx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 3600, Payload: &adminv1.CreateApprovalRequest_StartRollout{StartRollout: request}}))
		if err != nil {
			return fmt.Errorf("request rollout approval: %w", err)
		}
		approval = created.Msg.GetApproval().GetId()
	}
	outcome.Status, outcome.Detail = "pending", "requires independent approval "+approval
	return nil
}

func saveAssignment(ctx context.Context, client adminv1connect.AdminServiceClient, org string, op operation, reviewed *adminv1.StartRolloutRequest, outcome *Outcome) error {
	put := &adminv1.PutTargetAssignmentRequest{Assignment: reviewed.GetAssignment(), ExpectedRevision: reviewed.GetExpectedRevision(), Reason: reviewed.GetReason()}
	if err := completeRequest(org, "assignment", op.outcome.ID, put); err != nil {
		return err
	}
	if _, err := client.PutTargetAssignment(ctx, connect.NewRequest(put)); err != nil {
		return fmt.Errorf("save assignment: %w", err)
	}
	outcome.Detail = "saved; no enrolled device matches yet"
	return nil
}
