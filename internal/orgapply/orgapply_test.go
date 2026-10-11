package orgapply

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	orgv1 "lindm/gen/lindm/org/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
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

func TestTargetActivationApprovalAndExactHash(t *testing.T) {
	for _, approval := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "approval"}[approval], func(t *testing.T) {
			spec := organizationFixture()
			client := newFakeAdmin()
			deviceID, generationID := uuid.NewString(), uuid.NewString()
			client.fleet = []*adminv1.Device{{Id: deviceID, Hostname: "laptop", LifecycleState: adminv1.DeviceState_DEVICE_STATE_ACTIVE}}
			client.preview = &policyv1.TargetPreview{PreviewId: uuid.NewString(), DeviceId: deviceID, GenerationId: generationID, PreviewSha256: bytes.Repeat([]byte{1}, 32), ResolutionSha256: bytes.Repeat([]byte{2}, 32), Resolution: &policyv1.TargetResolution{}, Candidates: []*policyv1.TargetCandidate{{Assignment: spec.Assignments[0].Assignment, Revision: 1, Match: policyv1.TargetMatch_TARGET_MATCH_INCLUDED}}}
			client.principalID = uuid.NewString()
			client.preview.InputSha256 = bytes.Repeat([]byte{3}, 32)
			client.preview.EvaluatedAt = timestamppb.New(time.Unix(1700000000, 0))
			client.preview.ValidUntil = timestamppb.New(time.Unix(1700000600, 0))
			client.requireApproval = approval
			plan, err := Plan(t.Context(), client, spec)
			if err != nil {
				t.Fatal(err)
			}
			first, err := Apply(t.Context(), client, plan, Options{})
			if err != nil {
				t.Fatal(err)
			}
			last := first.Outcomes[len(first.Outcomes)-1]
			if approval {
				if last.Status != "pending" || len(client.approvals) != 1 || client.active != nil {
					t.Fatal("approval bypassed or not requested")
				}
				again, err := Plan(t.Context(), client, spec)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Apply(t.Context(), client, again, Options{}); err != nil {
					t.Fatal(err)
				}
				if len(client.approvals) != 1 {
					t.Fatal("pending approval duplicated")
				}
				client.approvals[0].State = adminv1.ApprovalState_APPROVAL_STATE_APPROVED
				if _, err := Apply(t.Context(), client, again, Options{}); err != nil {
					t.Fatal(err)
				}
			} else if last.Status != "updated" {
				t.Fatal("target not activated")
			}
			var activation *adminv1.ActivateTargetPreviewRequest
			for _, r := range client.requests {
				if a, ok := r.(*adminv1.ActivateTargetPreviewRequest); ok {
					activation = a
				}
			}
			if activation == nil || activation.GetPreviewId() != client.preview.GetPreviewId() || !bytes.Equal(activation.GetPreviewSha256(), client.preview.GetPreviewSha256()) {
				t.Fatal("activation lost exact preview identity")
			}
			again, err := Plan(t.Context(), client, spec)
			if err != nil {
				t.Fatal(err)
			}
			result, err := Apply(t.Context(), client, again, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if result.Outcomes[len(result.Outcomes)-1].Status != "unchanged" {
				t.Fatal("identical active snapshot activated again")
			}
		})
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

func TestTargetApprovalReuseRejectsOtherActorsAndStaleInputs(t *testing.T) {
	spec := organizationFixture()
	client := newFakeAdmin()
	deviceID := uuid.NewString()
	client.fleet = []*adminv1.Device{{Id: deviceID, Hostname: "laptop", LifecycleState: adminv1.DeviceState_DEVICE_STATE_ACTIVE}}
	client.principalID = uuid.NewString()
	client.requireApproval = true
	client.preview = &policyv1.TargetPreview{PreviewId: uuid.NewString(), DeviceId: deviceID, GenerationId: uuid.NewString(), InputSha256: bytes.Repeat([]byte{1}, 32), PreviewSha256: bytes.Repeat([]byte{2}, 32), ResolutionSha256: bytes.Repeat([]byte{3}, 32), EvaluatedAt: timestamppb.New(time.Unix(1700000000, 0)), ValidUntil: timestamppb.New(time.Unix(1700000600, 0)), Resolution: &policyv1.TargetResolution{}, Candidates: []*policyv1.TargetCandidate{{Assignment: spec.Assignments[0].Assignment, Match: policyv1.TargetMatch_TARGET_MATCH_INCLUDED}}}
	applyPending := func(want int) {
		t.Helper()
		plan, err := Plan(t.Context(), client, spec)
		if err != nil {
			t.Fatal(err)
		}
		result, err := Apply(t.Context(), client, plan, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(client.approvals) != want || client.active != nil || result.Outcomes[len(result.Outcomes)-1].Status != "pending" {
			t.Fatalf("approval count %d, want %d without activation", len(client.approvals), want)
		}
	}
	applyPending(1)
	firstActor := client.principalID
	client.approvals[0].State = adminv1.ApprovalState_APPROVAL_STATE_APPROVED
	client.principalID = uuid.NewString()
	applyPending(2)
	if client.approvals[0].GetRequesterId() != firstActor || client.approvals[1].GetRequesterId() != client.principalID {
		t.Fatal("second administrator adopted first administrator's approval")
	}
	applyPending(2)
	client.preview.InputSha256[0] ^= 1
	client.preview.PreviewId = uuid.NewString()
	client.preview.PreviewSha256[0] ^= 1
	applyPending(3)
	client.preview.EvaluatedAt = timestamppb.New(time.Unix(1700000601, 0))
	client.preview.ValidUntil = timestamppb.New(time.Unix(1700001200, 0))
	client.preview.PreviewId = uuid.NewString()
	client.preview.PreviewSha256[0] ^= 1
	applyPending(4)
}
