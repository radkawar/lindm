//go:build integration

package device

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/device/core"
	"lindm/internal/orgapply"
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
	plan, err = orgapply.Plan(f.stepUp, f.svc, spec)
	if err != nil {
		t.Fatal(err)
	}
	result, err := orgapply.Apply(f.stepUp, f.svc, plan, orgapply.Options{})
	if err != nil {
		t.Fatal(err)
	}
	activated := false
	for _, o := range result.Outcomes {
		if o.Kind == "activation" && o.ID == enrolled.Msg.GetDeviceId() && o.Status == "updated" {
			activated = true
		}
	}
	if !activated {
		t.Fatal("matching enrolled device not activated")
	}
	state, err := f.svc.GetDeviceResourceState(f.stepUp, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: enrolled.Msg.GetDeviceId()}))
	if err != nil {
		t.Fatal(err)
	}
	head := state.Msg.GetAssignment().GetAssignmentId()
	if head == "" || state.Msg.GetActiveTargetPreview() == nil {
		t.Fatal("active target evidence missing")
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
		if o.Kind == "activation" && o.Status != "unchanged" {
			t.Fatalf("target reapplied: %+v", o)
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
	_, err = f.svc.SetDeviceGroup(f.stepUp, connect.NewRequest(&adminv1.SetDeviceGroupRequest{RequestId: uuid.NewString(), GroupId: group.GetId(), Name: group.GetName(), CreateOnly: true, Reason: "stale absent group plan regression"}))
	if connect.CodeOf(err) != connect.CodeAborted {
		t.Fatalf("create-only existing group: %v", err)
	}
	groups, err := f.svc.ListDeviceGroups(f.stepUp, connect.NewRequest(&adminv1.ListDeviceGroupsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range groups.Msg.GetGroups() {
		if g.GetId() == group.GetId() && (len(g.GetDeviceIds()) != 1 || g.GetDeviceIds()[0] != enrolled.Msg.GetDeviceId()) {
			t.Fatal("create-only race erased enrolled RBAC membership")
		}
	}
}
