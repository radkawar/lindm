//go:build integration

package device

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/device/core"
	"lindm/internal/orgapply"
	"lindm/internal/targeting"
)

func TestOrganizationTargetsEnrolledDeviceIdempotently(t *testing.T) {
	// Runtime organization policy requires an actual browser session, not the
	// database-inserted principal used by isolated device-service fixtures.
	f := newSecretFixture(t)
	encoded, err := os.ReadFile(filepath.Join("..", "..", "lab", "demo", "org.json"))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := orgapply.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := orgapply.Plan(f.stepUp, f.svc, spec)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := orgapply.Apply(f.stepUp, f.svc, plan, orgapply.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var token string
	for _, secret := range initial.Secrets {
		if secret.Kind == "provisioning_token" && secret.Name == "engineering" {
			token = secret.Value
		}
	}
	if token == "" {
		t.Fatal("engineering enrollment token missing")
	}
	request, key := provisionIntent(t, token)
	enrolled, err := f.svc.Provision(t.Context(), connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	principal, err := f.svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), parseCertPEM(t, enrolled.Msg.GetCertificatePem()))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := f.svc.Authority.Sign(t.Context(), &agentv1.SessionAcquisition{
		DeploymentId: f.svc.DeploymentID.String(), DeviceId: principal.DeviceID.String(), EnrollmentGeneration: principal.GenerationID.String(),
		RequestId: uuid.NewString(), Incarnation: uuid.NewString(), BootId: uuid.NewString(), InstallationId: request.GetInstallationId(),
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.AcquireSession(core.WithDevicePrincipal(t.Context(), principal), connect.NewRequest(&devicev1.AcquireSessionRequest{AuthorityProof: proof})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ReportHostObservation(core.WithDevicePrincipal(t.Context(), principal), connect.NewRequest(hostObservation(enrolled.Msg.GetEnrollmentGeneration(), 1, "org-engineering"))); err != nil {
		t.Fatal(err)
	}
	// A second Engineering device enrolls but never reports inventory, so it
	// stays pending: no rollout can plan it, and it must not make every apply
	// start (and request approval for) another rollout.
	pendingRequest, _ := provisionIntent(t, token)
	pendingEnrollment, err := f.svc.Provision(t.Context(), connect.NewRequest(pendingRequest))
	if err != nil {
		t.Fatal(err)
	}
	plan, err = orgapply.Plan(f.stepUp, f.svc, spec)
	if err != nil {
		t.Fatal(err)
	}
	result, err := orgapply.Apply(f.stepUp, f.svc, plan, orgapply.Options{})
	if err != nil {
		t.Fatal(err)
	}
	// The organization's baseline and Engineering tools adopt existing native
	// state, so each rollout for the enrolled device waits for one approval
	// that apply requested; nothing is saved or activated before it. Both are
	// reviewed against the device's head before either is approved, so the
	// second to activate finds the device changed and holds it for review. The
	// next apply reviews it again in a follow-up rollout with its own approval.
	// Activation is the promoter's.
	reviewer := approvalReviewer(t, f.svc, t.Context())
	promoter, err := targeting.NewPromoter(f.svc.Pool, f.svc.Identity, f.svc.Targeting, f.svc.RolloutHooks())
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; ; round++ {
		awaiting := 0
		for _, o := range result.Outcomes {
			if o.Kind == "assignment" && o.Status == "pending" && strings.HasPrefix(o.Detail, "requires independent approval ") {
				awaiting++
			}
		}
		if round == 0 && awaiting == 0 {
			t.Fatalf("matching enrolled device did not start an adoption rollout: %+v", result.Outcomes)
		}
		if awaiting == 0 {
			break
		}
		if round > len(spec.GetAssignments()) {
			t.Fatalf("organization rollouts still requested approval after %d rounds: %+v", round, result.Outcomes)
		}
		pending, err := f.svc.ListRollouts(f.stepUp, connect.NewRequest(&adminv1.ListRolloutsRequest{PageSize: 100}))
		if err != nil {
			t.Fatal(err)
		}
		approved := 0
		for _, r := range pending.Msg.GetRollouts() {
			if r.GetStatus() != adminv1.RolloutStatus_ROLLOUT_STATUS_AWAITING_APPROVAL {
				continue
			}
			if _, err := f.svc.ApproveApproval(reviewer, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: r.GetApprovalId(), Reason: "Reviewed the organization's adoption rollout"})); err != nil {
				t.Fatal(err)
			}
			approved++
		}
		if approved != awaiting {
			t.Fatalf("approved %d rollouts, apply reported %d awaiting approval", approved, awaiting)
		}
		for range 3 {
			if err := promoter.RunOnce(f.stepUp); err != nil {
				t.Fatal(err)
			}
		}
		plan, err = orgapply.Plan(f.stepUp, f.svc, spec)
		if err != nil {
			t.Fatal(err)
		}
		if result, err = orgapply.Apply(f.stepUp, f.svc, plan, orgapply.Options{}); err != nil {
			t.Fatal(err)
		}
	}
	for range 3 {
		if err := promoter.RunOnce(f.stepUp); err != nil {
			t.Fatal(err)
		}
	}
	state, err := f.svc.GetDeviceResourceState(f.stepUp, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: enrolled.Msg.GetDeviceId()}))
	if err != nil {
		t.Fatal(err)
	}
	head := state.Msg.GetAssignment().GetAssignmentId()
	if head == "" || state.Msg.GetActiveTargetPreview() == nil {
		t.Fatal("active target evidence missing")
	}
	before, err := f.svc.ListRollouts(f.stepUp, connect.NewRequest(&adminv1.ListRolloutsRequest{PageSize: 100}))
	if err != nil {
		t.Fatal(err)
	}
	plan, err = orgapply.Plan(f.stepUp, f.svc, spec)
	if err != nil {
		t.Fatal(err)
	}
	result, err = orgapply.Apply(f.stepUp, f.svc, plan, orgapply.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range result.Outcomes {
		// Assignments whose groups have no device are saved, never rolled out.
		if o.Kind == "assignment" && o.Status != "unchanged" {
			t.Fatalf("target reapplied: %+v", o)
		}
	}
	rollouts, err := f.svc.ListRollouts(f.stepUp, connect.NewRequest(&adminv1.ListRolloutsRequest{PageSize: 100}))
	if err != nil {
		t.Fatal(err)
	}
	if len(rollouts.Msg.GetRollouts()) != len(before.Msg.GetRollouts()) {
		t.Fatalf("unchanged apply started %d rollouts", len(rollouts.Msg.GetRollouts())-len(before.Msg.GetRollouts()))
	}
	// A rollout whose held device a follow-up rollout reviewed again is no
	// longer active; every active one has activated its devices.
	for _, r := range rollouts.Msg.GetRollouts() {
		if r.GetStatus() == adminv1.RolloutStatus_ROLLOUT_STATUS_ACTIVE && (r.GetNeedsReviewCount() != 0 || r.GetStartingCount() != 0) {
			t.Fatalf("organization rollouts left a device for review: %v", r)
		}
	}
	if len(result.Secrets) != 0 {
		t.Fatal("second apply reissued secrets")
	}
	state, err = f.svc.GetDeviceResourceState(f.stepUp, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: enrolled.Msg.GetDeviceId()}))
	if err != nil {
		t.Fatal(err)
	}
	if state.Msg.GetAssignment().GetAssignmentId() != head {
		t.Fatal("identical second apply advanced execution head")
	}
	// An absent-group plan may race enrollment. The create-only API guard must not
	// rewrite the now-populated group's authorization membership.
	group := spec.GetGroups()[0]
	membershipBefore, err := f.svc.ListDeviceGroups(f.stepUp, connect.NewRequest(&adminv1.ListDeviceGroupsRequest{GroupIds: []string{group.GetId()}}))
	if err != nil {
		t.Fatal(err)
	}
	expectedMembers := []string{enrolled.Msg.GetDeviceId(), pendingEnrollment.Msg.GetDeviceId()}
	slices.Sort(expectedMembers)
	if len(membershipBefore.Msg.GetGroups()) != 1 || !slices.Equal(membershipBefore.Msg.GetGroups()[0].GetDeviceIds(), expectedMembers) {
		t.Fatalf("enrollment did not retain both Engineering memberships: %v", membershipBefore.Msg)
	}
	_, err = f.svc.SetDeviceGroup(f.stepUp, connect.NewRequest(&adminv1.SetDeviceGroupRequest{RequestId: uuid.NewString(), GroupId: group.GetId(), Name: group.GetName(), CreateOnly: true, Reason: "stale absent group plan regression"}))
	if connect.CodeOf(err) != connect.CodeAborted {
		t.Fatalf("create-only existing group: %v", err)
	}
	groups, err := f.svc.ListDeviceGroups(f.stepUp, connect.NewRequest(&adminv1.ListDeviceGroupsRequest{GroupIds: []string{group.GetId()}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(groups.Msg.GetGroups()) != 1 || !slices.Equal(groups.Msg.GetGroups()[0].GetDeviceIds(), membershipBefore.Msg.GetGroups()[0].GetDeviceIds()) {
		t.Fatalf("create-only race erased enrolled RBAC membership: before %v, after %v", membershipBefore.Msg, groups.Msg)
	}
}
