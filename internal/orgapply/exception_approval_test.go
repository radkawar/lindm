package orgapply

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	orgv1 "lindm/gen/lindm/org/v1"
)

func TestExceptionProposalNeverAcceptsOrApproves(t *testing.T) {
	client := newFakeAdmin()
	deviceID, findingID := uuid.NewString(), uuid.NewString()
	client.fleet = []*adminv1.Device{{Id: deviceID, Hostname: "laptop"}}
	client.findings = []*adminv1.AdvisoryFinding{{Id: findingID, AdvisoryId: "vendor-advisory", PackageName: "package", State: adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED}}
	spec := &orgv1.Organization{Name: "exceptions", AdvisoryExceptions: []*orgv1.AdvisoryException{{Hostname: "laptop", AdvisoryId: "vendor-advisory", PackageName: "package", ProposeApproval: true, Request: &adminv1.AcceptAdvisoryFindingRequest{Reason: "temporary compatibility exception", ExpiresAt: timestamppb.New(time.Now().Add(time.Hour))}}}}
	plan, err := Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Apply(t.Context(), client, plan, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(client.requests) != 1 {
		t.Fatalf("unexpected mutations: %v", client.requests)
	}
	proposal, ok := client.requests[0].(*adminv1.CreateApprovalRequest)
	if !ok {
		t.Fatal("proposal bypassed approval API")
	}
	request := proposal.GetAcceptAdvisoryFinding()
	if request.GetDeviceId() != deviceID || request.GetFindingId() != findingID || request.GetRequestId() == "" || request.GetApprovalId() != "" {
		t.Fatal("proposal lost engine-resolved exact identity")
	}
	if client.findings[0].GetException() != nil || result.Outcomes[0].Status != "pending" {
		t.Fatal("proposal represented as accepted risk")
	}
	if _, err := Apply(t.Context(), client, plan, Options{}); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(client.requests[0], client.requests[1]) {
		t.Fatal("retry changed approval payload")
	}
}

func TestExceptionCanonicalExpiryDoesNotReissueApproval(t *testing.T) {
	client := newFakeAdmin()
	deviceID, findingID := uuid.NewString(), uuid.NewString()
	expires := timestamppb.New(time.Now().Add(time.Hour))
	expires.Nanos = 446777608
	reason := "Reviewed temporary compatibility exception"
	client.fleet = []*adminv1.Device{{Id: deviceID, Hostname: "laptop"}}
	client.findings = []*adminv1.AdvisoryFinding{{Id: findingID, AdvisoryId: "vendor-advisory", PackageName: "package", State: adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_ACCEPTED, Exception: &adminv1.AdvisoryException{Reason: reason, ExpiresAt: timestamppb.New(expires.AsTime().Truncate(time.Microsecond))}}}
	spec := &orgv1.Organization{Name: "exceptions", AdvisoryExceptions: []*orgv1.AdvisoryException{{Hostname: "laptop", AdvisoryId: "vendor-advisory", PackageName: "package", ProposeApproval: true, Request: &adminv1.AcceptAdvisoryFindingRequest{Reason: reason, ExpiresAt: expires}}}}
	plan, err := Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Apply(t.Context(), client, plan, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(client.requests) != 0 || len(result.Outcomes) != 1 || result.Outcomes[0].Status != "unchanged" {
		t.Fatalf("canonical expiry reissued an approval: %+v", result)
	}
	spec.AdvisoryExceptions[0].Request.ExpiresAt.Nanos += 1000
	changed, err := Plan(t.Context(), client, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(t.Context(), client, changed, Options{}); err != nil {
		t.Fatal(err)
	}
	if len(client.requests) != 1 {
		t.Fatal("one-microsecond expiry change was silently tolerated")
	}
}
