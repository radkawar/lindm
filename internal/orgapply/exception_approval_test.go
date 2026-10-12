package orgapply

import (
	"strconv"
	"testing"
	"testing/synctest"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	orgv1 "lindm/gen/lindm/org/v1"
	"lindm/internal/rpcreason"
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

// A managed package install publishes a new host observation while a long
// finding scan is paging; the server aborts the stale cursor and the scan
// restarts from the first page instead of failing the whole apply.
func TestExceptionScanRestartsWhenAdvisoryEvidenceChanges(t *testing.T) {
	setup := func(changes int) (*fakeAdmin, *orgv1.Organization) {
		client := newFakeAdmin()
		deviceID := uuid.NewString()
		client.fleet = []*adminv1.Device{{Id: deviceID, Hostname: "laptop"}}
		// The declared finding is on the second page, so a stale cursor matters.
		for i := range 250 {
			client.findings = append(client.findings, &adminv1.AdvisoryFinding{Id: uuid.NewString(), AdvisoryId: "advisory-" + strconv.Itoa(i), PackageName: "package", State: adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED})
		}
		client.findingSnapshotChanges = changes
		return client, &orgv1.Organization{Name: "exceptions", AdvisoryExceptions: []*orgv1.AdvisoryException{{Hostname: "laptop", AdvisoryId: "advisory-249", PackageName: "package", ProposeApproval: true, Request: &adminv1.AcceptAdvisoryFindingRequest{Reason: "temporary compatibility exception", ExpiresAt: timestamppb.New(time.Now().Add(time.Hour))}}}}
	}
	synctest.Test(t, func(t *testing.T) {
		client, spec := setup(findingScanAttempts - 1)
		plan, err := Plan(t.Context(), client, spec)
		if err != nil {
			t.Fatalf("a changed evidence snapshot must restart the scan: %v", err)
		}
		if client.findingCalls != 2*findingScanAttempts {
			t.Fatalf("scan made %d list calls, want %d", client.findingCalls, 2*findingScanAttempts)
		}
		result, err := Apply(t.Context(), client, plan, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Outcomes) != 1 || result.Outcomes[0].Status != "pending" || result.Outcomes[0].Detail == "finding not found" {
			t.Fatalf("restarted scan lost the finding: %+v", result.Outcomes)
		}
	})
	synctest.Test(t, func(t *testing.T) {
		client, spec := setup(findingScanAttempts)
		if _, err := Plan(t.Context(), client, spec); connect.CodeOf(err) != connect.CodeAborted || rpcreason.Get(err) != "advisory_evidence_changed" {
			t.Fatalf("persistent evidence churn must surface after %d scans, got %v", findingScanAttempts, err)
		}
	})
}
