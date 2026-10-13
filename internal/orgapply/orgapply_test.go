package orgapply

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	orgv1 "lindm/gen/lindm/org/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func TestApplyIdempotencyAndProfileRevision(t *testing.T) {
	spec := organizationFixture()
	client := newFakeAdmin()
	first, err := Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(client.requests) != 0 {
		t.Fatal("planning mutated the server")
	}
	result, err := Apply(t.Context(), client, first, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Secrets) != 2 {
		t.Fatalf("issued %d secrets, want 2", len(result.Secrets))
	}
	head := client.profiles[profileID].GetRevisionId()
	if client.assignments[0].GetAssignment().GetProfileRevisionId() != head {
		t.Fatal("assignment did not pin newly published revision")
	}
	mutations := len(client.requests)
	second, err := Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	result, err = Apply(t.Context(), client, second, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range result.Outcomes {
		if o.Status != "unchanged" {
			t.Fatalf("second outcome = %+v", o)
		}
	}
	if len(result.Secrets) != 0 || len(client.requests) != mutations {
		t.Fatal("second apply reissued credentials or mutated catalog")
	}
	spec.Profiles[0].Spec.Description = "changed"
	changed, err := Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(t.Context(), client, changed, Options{}); err != nil {
		t.Fatal(err)
	}
	if client.profiles[profileID].GetRevisionNumber() != 2 || client.assignments[0].GetRevision() != 2 {
		t.Fatal("changed profile did not advance exactly one profile and assignment revision")
	}
	if _, err := Apply(t.Context(), client, changed, Options{}); connect.CodeOf(err) != connect.CodeAborted {
		t.Fatalf("stale plan must surface CAS conflict, got %v", err)
	}
}

func TestApplySSHBannerUsesTypedProfileAndTracksTextChanges(t *testing.T) {
	spec := organizationFixture()
	item := spec.Profiles[0].Spec.Resources[0]
	item.Desired = &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SSH_SERVER, CanonicalKey: "system"}, State: &resourcev1.ResourceDesiredState_SshServer{SshServer: &resourcev1.SSHServerDesired{BannerText: proto.String("Company managed device.\nAuthorized use only.\n")}}}
	item.Ownership.Release = resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED
	client := newFakeAdmin()
	first, err := Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(t.Context(), client, first, Options{}); err != nil {
		t.Fatal(err)
	}
	second, err := Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	count := len(client.requests)
	if _, err := Apply(t.Context(), client, second, Options{}); err != nil {
		t.Fatal(err)
	}
	if len(client.requests) != count {
		t.Fatal("identical banner republished")
	}
	item.Desired.GetSshServer().BannerText = proto.String("Revised public notice.\n")
	changed, err := Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(t.Context(), client, changed, Options{}); err != nil {
		t.Fatal(err)
	}
	if client.profiles[profileID].GetRevisionNumber() != 2 {
		t.Fatal("banner change did not publish immutable revision")
	}
}

func TestDeterministicRequestIdentity(t *testing.T) {
	a := &adminv1.PublishProfileRevisionRequest{ProfileId: profileID, Spec: organizationFixture().Profiles[0].Spec, Reason: "apply baseline"}
	b := proto.CloneOf(a)
	if err := completeRequest("org", "profile", profileID, a); err != nil {
		t.Fatal(err)
	}
	if err := completeRequest("org", "profile", profileID, b); err != nil {
		t.Fatal(err)
	}
	if a.RequestId != b.RequestId {
		t.Fatal("same desired object changed replay ID")
	}
	if _, err := uuid.Parse(a.RequestId); err != nil {
		t.Fatal(err)
	}
	b.ExpectedRevisionId = proto.String(uuid.NewString())
	if err := completeRequest("org", "profile", profileID, b); err != nil {
		t.Fatal(err)
	}
	if a.RequestId == b.RequestId {
		t.Fatal("observed CAS version not bound to replay ID")
	}
	original := a.RequestId
	if err := completeRequest("org", "profile", profileID, a); err != nil {
		t.Fatal(err)
	}
	if original != a.RequestId {
		t.Fatal("completion incorporated its own previous request ID")
	}
}

func TestPartialFailurePreservesSecretsWithoutJSONLeak(t *testing.T) {
	client := newFakeAdmin()
	client.failGrant = true
	plan, err := Plan(t.Context(), client, organizationFixture())
	if err != nil {
		t.Fatal(err)
	}
	result, err := Apply(t.Context(), client, plan, Options{})
	if connect.CodeOf(err) != connect.CodeUnavailable || len(result.Secrets) != 1 {
		t.Fatalf("partial result did not preserve one secret: error=%v count=%d", err, len(result.Secrets))
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("private-token")) || bytes.Contains(encoded, []byte("secret")) {
		t.Fatal("ordinary result JSON exposed secret material")
	}
}

func TestStrictValidationAndBrowserBoundary(t *testing.T) {
	for _, input := range []string{`{"name":"org","unknown":true}`, `{"name":"org","grants":[{"name":"grant","request":{"lifetimeSeconds":1}}]}`, `{"name":"org","assignments":[{"profileId":"bad","assignment":{}}]}`} {
		if _, err := Decode([]byte(input)); err == nil {
			t.Fatalf("accepted invalid document %s", input)
		}
	}
	spec := &orgv1.Organization{Name: "org", Accounts: []*authv1.CreateAccountRequest{{Username: "auditor", Role: "auditor"}}, Authorization: &authv1.AuthorizationPolicy{}}
	plan, err := Plan(t.Context(), newFakeAdmin(), spec)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Apply(t.Context(), newFakeAdmin(), plan, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcomes[0].Status != "updated" || result.Outcomes[1].Status != "pending" || !strings.Contains(result.Outcomes[1].Detail, "browser session") {
		t.Fatal("CLI failed runtime policy or claimed browser account authority")
	}
}

func TestAssistancePermissionAuthorityDecode(t *testing.T) {
	for _, test := range []struct {
		name        string
		permissions []string
		valid       bool
	}{
		{"view-only helpdesk", []string{"fleet.read", "remote_assistance.view"}, true},
		{"control does not imply view", []string{"remote_assistance.control"}, true},
		{"view and control", []string{"remote_assistance.view", "remote_assistance.control"}, true},
		{"legacy combined authority rejected", []string{"remote_assistance.run"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			want := &orgv1.Organization{
				Name: "org",
				Authorization: &authv1.AuthorizationPolicy{
					Roles: []*authv1.RoleDefinition{
						{Name: "assistance", Permissions: test.permissions},
						{Name: "controller", Permissions: []string{"remote_assistance.control"}},
					},
					GroupBindings: []*authv1.GroupBinding{
						{Group: "/helpdesk", Role: "assistance", Scopes: []*authv1.DeviceScope{{Labels: []string{"department/helpdesk"}}}},
						{Group: "/control", Role: "controller", Scopes: []*authv1.DeviceScope{{Labels: []string{"department/operations"}}}},
					},
				},
			}
			body, err := protojson.Marshal(want)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Decode(body)
			if !test.valid {
				if err == nil {
					t.Fatal("accepted removed permission through declarative apply")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(got, want) {
				t.Fatal("decoding changed explicit permissions or device scopes")
			}
		})
	}
}

func TestStaticGroupRenameCannotRestoreStaleMembership(t *testing.T) {
	client := newFakeAdmin()
	client.groups = []*adminv1.DeviceGroup{{Id: groupID, Name: "old name", DeviceIds: []string{uuid.NewString()}}}
	spec := &orgv1.Organization{Name: "org", Groups: []*orgv1.StaticGroup{{Id: groupID, Name: "new name"}}}
	plan, err := Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Apply(t.Context(), client, plan, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcomes[0].Status != "unsupported" || len(client.requests) != 0 {
		t.Fatal("unsafe static group rename was applied")
	}
}

func TestAssignmentsRollOutAndRequireOneApproval(t *testing.T) {
	for _, approval := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "adoption_approval"}[approval], func(t *testing.T) {
			spec := organizationFixture()
			client := newFakeAdmin()
			client.principalID = uuid.NewString()
			client.requireApproval = approval
			plan, err := Plan(t.Context(), client, spec)
			if err != nil {
				t.Fatal(err)
			}
			first, err := Apply(t.Context(), client, plan, Options{})
			if err != nil {
				t.Fatalf("apply failed instead of reporting the rollout: %v", err)
			}
			last := assignmentOutcome(t, first)
			if len(client.rollouts) != 1 {
				t.Fatalf("started %d rollouts, want 1", len(client.rollouts))
			}
			start := client.rollouts[0]
			if start.GetAssignment().GetRolloutId() != "" || start.GetRollout().GetName() != "baseline to Engineering" || len(start.GetRollout().GetRings()) != 1 || !proto.Equal(start.GetRollout().GetRings()[0].GetCohort(), spec.Assignments[0].GetAssignment().GetTarget()) {
				t.Fatalf("rollout plan does not deliver the declared assignment: %v", start)
			}
			if approval {
				if last.Status != "pending" || len(client.approvals) != 1 || client.approvals[0].GetStartRollout() == nil || len(client.assignments) != 0 {
					t.Fatalf("adoption did not yield one pending rollout approval: %+v %v", last, client.approvals)
				}
				if !strings.Contains(last.Detail, client.approvals[0].GetId()) {
					t.Fatalf("pending outcome does not name its approval: %+v", last)
				}
			} else if last.Status != "created" || len(client.assignments) != 1 {
				t.Fatalf("approval-free rollout did not start: %+v", last)
			}
			// A re-run never forks a second rollout or approval.
			again, err := Plan(t.Context(), client, spec)
			if err != nil {
				t.Fatal(err)
			}
			result, err := Apply(t.Context(), client, again, Options{})
			if err != nil {
				t.Fatal(err)
			}
			last = assignmentOutcome(t, result)
			if len(client.rollouts) != 1 || len(client.approvals) != map[bool]int{false: 0, true: 1}[approval] {
				t.Fatalf("re-run repeated the rollout or approval: %d rollouts %d approvals", len(client.rollouts), len(client.approvals))
			}
			want := map[bool]string{false: "unchanged", true: "pending"}[approval]
			if last.Status != want {
				t.Fatalf("re-run outcome %+v, want %s", last, want)
			}
		})
	}
}

func assignmentOutcome(t *testing.T, result *Result) Outcome {
	t.Helper()
	for _, o := range result.Outcomes {
		if o.Kind == "assignment" {
			return o
		}
	}
	t.Fatal("no assignment outcome")
	return Outcome{}
}

func TestUnchangedAssignmentRollsOutAgainOnlyForChangedDevices(t *testing.T) {
	spec := organizationFixture()
	client := newFakeAdmin()
	plan, err := Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(t.Context(), client, plan, Options{}); err != nil {
		t.Fatal(err)
	}
	client.impactChanged = true
	again, err := Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Apply(t.Context(), client, again, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if last := assignmentOutcome(t, result); last.Status != "updated" || len(client.rollouts) != 2 || client.rollouts[0].GetRollout().GetRolloutId() == client.rollouts[1].GetRollout().GetRolloutId() {
		t.Fatalf("a newly matching device was not rolled out under a new rollout: %+v", last)
	}
}

func TestProfileCanonicalOrderDoesNotPublish(t *testing.T) {
	spec := organizationFixture()
	second := proto.CloneOf(spec.Profiles[0].Spec.Resources[0])
	second.ResourceId = uuid.NewString()
	second.Desired.Ref.CanonicalKey = "other.service"
	second.Desired.GetSystemdService().Unit = "other.service"
	spec.Profiles[0].Spec.Resources = append(spec.Profiles[0].Spec.Resources, second)
	client := newFakeAdmin()
	plan, err := Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(t.Context(), client, plan, Options{}); err != nil {
		t.Fatal(err)
	}
	spec.Profiles[0].Spec.Resources[0], spec.Profiles[0].Spec.Resources[1] = spec.Profiles[0].Spec.Resources[1], spec.Profiles[0].Spec.Resources[0]
	plan, err = Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range plan.Outcomes {
		if o.Status != "unchanged" {
			t.Fatalf("order-only change: %+v", o)
		}
	}
}

func TestExceptionsRemainPendingUntilExactFindingExists(t *testing.T) {
	client := newFakeAdmin()
	desired := &orgv1.AdvisoryException{Hostname: "laptop", AdvisoryId: "vendor-advisory", PackageName: "package", Request: &adminv1.AcceptAdvisoryFindingRequest{Reason: "temporary compatibility exception", ExpiresAt: timestamppb.New(time.Now().Add(time.Hour))}}
	spec := &orgv1.Organization{Name: "exceptions", AdvisoryExceptions: []*orgv1.AdvisoryException{desired}}
	plan, err := Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Outcomes[0].Status != "pending" {
		t.Fatal("missing device was not pending")
	}
	client.fleet = []*adminv1.Device{{Id: uuid.NewString(), Hostname: "laptop"}}
	plan, err = Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Outcomes[0].Status != "pending" {
		t.Fatal("missing finding was not pending")
	}
	client.findings = []*adminv1.AdvisoryFinding{{Id: uuid.NewString(), AdvisoryId: desired.AdvisoryId, PackageName: desired.PackageName, State: adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED}}
	plan, err = Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(t.Context(), client, plan, Options{}); err != nil {
		t.Fatal(err)
	}
	request, ok := client.requests[0].(*adminv1.AcceptAdvisoryFindingRequest)
	if !ok {
		t.Fatal("acceptance did not use product request")
	}
	if request.GetDeviceId() != client.fleet[0].GetId() || request.GetFindingId() != client.findings[0].GetId() {
		t.Fatal("selector did not resolve exact product identities")
	}
	plan, err = Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Outcomes[0].Status != "unchanged" {
		t.Fatal("identical acceptance changed")
	}
	client.fleet = append(client.fleet, &adminv1.Device{Id: uuid.NewString(), Hostname: "laptop"})
	plan, err = Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Outcomes[0].Status != "pending" || !strings.Contains(plan.Outcomes[0].Detail, "ambiguous") {
		t.Fatal("ambiguous hostname selected an arbitrary device")
	}
}

// A real Ubuntu desktop reports more than 33,000 findings; resolving one declared
// exception must not depend on retaining the whole list under the catalog cap.
func TestExceptionResolvesFindingBeyondCatalogCap(t *testing.T) {
	client := newFakeAdmin()
	desired := &orgv1.AdvisoryException{Hostname: "laptop", AdvisoryId: "vendor-advisory", PackageName: "package", Request: &adminv1.AcceptAdvisoryFindingRequest{Reason: "temporary compatibility exception", ExpiresAt: timestamppb.New(time.Now().Add(time.Hour))}}
	spec := &orgv1.Organization{Name: "exceptions", AdvisoryExceptions: []*orgv1.AdvisoryException{desired}}
	client.fleet = []*adminv1.Device{{Id: uuid.NewString(), Hostname: "laptop"}}
	for i := range 33509 {
		client.findings = append(client.findings, &adminv1.AdvisoryFinding{Id: uuid.NewString(), AdvisoryId: fmt.Sprintf("other-%d", i), PackageName: desired.PackageName, State: adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED})
	}
	target := &adminv1.AdvisoryFinding{Id: uuid.NewString(), AdvisoryId: desired.AdvisoryId, PackageName: desired.PackageName, State: adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED}
	client.findings = append(client.findings, target)
	plan, err := Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Outcomes[0].Status != "created" || plan.Outcomes[0].ID != target.GetId() {
		t.Fatalf("declared finding on the last page was not resolved: %+v", plan.Outcomes[0])
	}
}

func TestRolloutReviewRetriesConcurrentChangesThenReportsPending(t *testing.T) {
	for _, stale := range []int{2, 3} {
		client := newFakeAdmin()
		client.staleStarts = stale
		plan, err := Plan(t.Context(), client, organizationFixture())
		if err != nil {
			t.Fatal(err)
		}
		result, err := Apply(t.Context(), client, plan, Options{})
		if err != nil {
			t.Fatalf("a concurrently changing review failed the apply: %v", err)
		}
		got := assignmentOutcome(t, result)
		if stale == 2 && (got.Status != "created" || len(client.rollouts) != 1) {
			t.Fatalf("bounded retry did not start the fresh review: %+v", got)
		}
		if stale == 3 && (got.Status != "pending" || len(client.rollouts) != 0) {
			t.Fatalf("exhausted retries were not reported pending: %+v", got)
		}
	}
}

func TestAssignmentWithoutMatchingDevicesIsSavedThenUnchanged(t *testing.T) {
	client := newFakeAdmin()
	client.noDevices = true
	for _, want := range []string{"created", "unchanged"} {
		plan, err := Plan(t.Context(), client, organizationFixture())
		if err != nil {
			t.Fatal(err)
		}
		result, err := Apply(t.Context(), client, plan, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if got := assignmentOutcome(t, result); got.Status != want || len(client.assignments) != 1 || len(client.rollouts) != 0 {
			t.Fatalf("assignment with no matching device: %+v, want %s", got, want)
		}
	}
}

func TestUnchangedAssignmentInFlightIsNotRolledOutAgain(t *testing.T) {
	client := newFakeAdmin()
	plan, err := Plan(t.Context(), client, organizationFixture())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(t.Context(), client, plan, Options{}); err != nil {
		t.Fatal(err)
	}
	client.rollouts[0].StartingCount, client.impactChanged = 1, true
	again, err := Plan(t.Context(), client, organizationFixture())
	if err != nil {
		t.Fatal(err)
	}
	result, err := Apply(t.Context(), client, again, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := assignmentOutcome(t, result); got.Status != "unchanged" || !strings.Contains(got.Detail, "rolling out") || len(client.rollouts) != 1 {
		t.Fatalf("in-flight rollout was forked or reported as drift: %+v", got)
	}
}
