//go:build integration

package device

import (
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/identity"
)

func TestAdvisoryExceptionRequiresExactIndependentApproval(t *testing.T) {
	parallelDeviceIntegration(t)
	f, request := advisoryAcceptanceFixture(t)
	authority, err := identity.New(f.ctx, f.svc.Pool, identity.Config{Local: true, PublicURL: "https://admin.example", Policy: &authv1.AuthorizationPolicy{ApprovalRequiredPermissions: []string{string(identity.PermissionManageAdvisoryExceptions)}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := authority.Close(); err != nil {
			t.Error(err)
		}
	})
	f.svc.Identity = authority
	if _, err := f.svc.AcceptAdvisoryFinding(f.ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("missing approval accepted: %v", err)
	}
	created, err := f.svc.CreateApproval(f.ownerCtx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 3600, Payload: &adminv1.CreateApprovalRequest_AcceptAdvisoryFinding{AcceptAdvisoryFinding: request}}))
	if err != nil {
		t.Fatal(err)
	}
	approval := created.Msg.GetApproval()
	if approval.GetAdvisoryFinding().GetId() != request.GetFindingId() || approval.GetAcceptAdvisoryFinding().GetReason() != request.GetReason() {
		t.Fatal("approval lost exact finding or reason")
	}
	request.ApprovalId = approval.GetId()
	if _, err := f.svc.AcceptAdvisoryFinding(f.ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("pending approval accepted: %v", err)
	}
	decision := &adminv1.ApproveApprovalRequest{ApprovalId: approval.GetId(), Reason: "Reviewed exact vulnerable package and expiry"}
	if _, err := f.svc.ApproveApproval(f.ownerCtx, connect.NewRequest(decision)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("self approval accepted: %v", err)
	}
	reviewer := approvalReviewer(t, f.svc, f.ctx)
	if _, err := f.svc.ApproveApproval(reviewer, connect.NewRequest(decision)); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*adminv1.AcceptAdvisoryFindingRequest)
	}{
		{"device", func(r *adminv1.AcceptAdvisoryFindingRequest) { r.DeviceId = uuid.NewString() }},
		{"finding", func(r *adminv1.AcceptAdvisoryFindingRequest) { r.FindingId = uuid.NewString() }},
		{"request", func(r *adminv1.AcceptAdvisoryFindingRequest) { r.RequestId = uuid.NewString() }},
		{"reason", func(r *adminv1.AcceptAdvisoryFindingRequest) { r.Reason = "Substituted acceptance reason" }},
		{"expiry", func(r *adminv1.AcceptAdvisoryFindingRequest) { r.ExpiresAt.Seconds++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := proto.CloneOf(request)
			test.change(changed)
			if _, err := f.svc.AcceptAdvisoryFinding(f.ownerCtx, connect.NewRequest(changed)); err == nil {
				t.Fatal("changed payload reused approval")
			}
		})
	}
	accepted, err := f.svc.AcceptAdvisoryFinding(f.ownerCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	replay, err := f.svc.AcceptAdvisoryFinding(f.ownerCtx, connect.NewRequest(request))
	if err != nil || !proto.Equal(accepted.Msg, replay.Msg) {
		t.Fatalf("exact retry changed result: %v", err)
	}
	var state string
	if err := f.conn.QueryRow(f.ctx, "SELECT state FROM approval_requests WHERE id=$1", approval.GetId()).Scan(&state); err != nil || state != "consumed" {
		t.Fatalf("approval not consumed: %s %v", state, err)
	}
	var count int
	if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM advisory_exceptions").Scan(&count); err != nil || count != 1 {
		t.Fatalf("exception count %d: %v", count, err)
	}
	if _, err := f.conn.Exec(f.ctx, "UPDATE approval_requests SET created_at=clock_timestamp()-interval '1 hour', expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", approval.GetId()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.AcceptAdvisoryFinding(f.ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("expired approval replay accepted: %v", err)
	}
}

// A pending risk acceptance whose finding newer inventory no longer reports is
// shown as unavailable and cannot be approved; it can still be rejected.
func TestAdvisoryApprovalRefusedOnceFindingEvidenceIsGone(t *testing.T) {
	parallelDeviceIntegration(t)
	f, request := advisoryAcceptanceFixture(t)
	created, err := f.svc.CreateApproval(f.ownerCtx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 3600, Payload: &adminv1.CreateApprovalRequest_AcceptAdvisoryFinding{AcceptAdvisoryFinding: request}}))
	if err != nil {
		t.Fatal(err)
	}
	id := created.Msg.GetApproval().GetId()
	evidence := func() *adminv1.Approval {
		t.Helper()
		listed, err := f.svc.ListApprovals(f.ownerCtx, connect.NewRequest(&adminv1.ListApprovalsRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		for _, approval := range listed.Msg.GetApprovals() {
			if approval.GetId() == id {
				return approval
			}
		}
		t.Fatal("approval not listed")
		return nil
	}
	if got := created.Msg.GetApproval().GetEvidenceState(); got != adminv1.ApprovalEvidenceState_APPROVAL_EVIDENCE_STATE_CURRENT {
		t.Fatalf("created approval evidence %v", got)
	}
	if got := evidence().GetEvidenceState(); got != adminv1.ApprovalEvidenceState_APPROVAL_EVIDENCE_STATE_CURRENT {
		t.Fatalf("listed approval evidence %v", got)
	}

	// Newer inventory without the vulnerable package supersedes the finding,
	// reported after the routine admission interval.
	f.now = f.now.Add(10 * time.Minute)
	batch := packageBatch(t, &inventoryv1.Package{Name: "bash", Version: "5.2.21-2ubuntu4", Architecture: "amd64", Manager: "dpkg", SourceName: "bash", SourceVersion: "5.2.21-2ubuntu4"})
	manifest := snapshotManifest(t, f.generation, 2, f.now, [][]byte{batch})
	manifest.Backend = "dpkg"
	if _, err := f.begin(t, manifest, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.put(t, manifest.SnapshotId, 0, batch, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.commit(t, manifest, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Advisories.EvaluatePending(f.ctx, 32); err != nil {
		t.Fatal(err)
	}
	stale := evidence()
	if stale.GetEvidenceState() != adminv1.ApprovalEvidenceState_APPROVAL_EVIDENCE_STATE_UNAVAILABLE || stale.GetAdvisoryFinding() != nil || stale.GetState() != adminv1.ApprovalState_APPROVAL_STATE_PENDING {
		t.Fatalf("superseded finding still projected as current: %v %v %v", stale.GetEvidenceState(), stale.GetAdvisoryFinding(), stale.GetState())
	}

	reviewer := approvalReviewer(t, f.svc, f.ctx)
	_, err = f.svc.ApproveApproval(reviewer, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: id, Reason: "Approve despite missing evidence"}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || rpcReason(err) != "approval_evidence_unavailable" {
		t.Fatalf("approval of unavailable evidence not refused: %v", err)
	}
	var state string
	if err := f.conn.QueryRow(f.ctx, "SELECT state FROM approval_requests WHERE id=$1", id).Scan(&state); err != nil || state != "pending" {
		t.Fatalf("refused approval changed state: %s %v", state, err)
	}
	rejected, err := f.svc.RejectApproval(reviewer, connect.NewRequest(&adminv1.RejectApprovalRequest{ApprovalId: id, Reason: "Finding evidence is gone"}))
	if err != nil || rejected.Msg.GetApproval().GetState() != adminv1.ApprovalState_APPROVAL_STATE_REJECTED {
		t.Fatalf("unavailable evidence could not be rejected: %v", err)
	}
}

// A risk acceptance that has already ended is refused before it can be
// proposed for approval or accepted directly.
func TestAdvisoryAcceptanceRefusesPastExpiry(t *testing.T) {
	parallelDeviceIntegration(t)
	f, request := advisoryAcceptanceFixture(t)
	request.ExpiresAt = timestamppb.New(time.Now().Add(-time.Hour))
	if _, err := f.svc.CreateApproval(f.ownerCtx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 3600, Payload: &adminv1.CreateApprovalRequest_AcceptAdvisoryFinding{AcceptAdvisoryFinding: request}})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("past-dated risk acceptance proposed: %v", err)
	}
	if _, err := f.svc.AcceptAdvisoryFinding(f.ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("past-dated risk acceptance accepted: %v", err)
	}
	var count int
	if err := f.conn.QueryRow(f.ctx, "SELECT (SELECT count(*) FROM approval_requests) + (SELECT count(*) FROM advisory_exceptions)").Scan(&count); err != nil || count != 0 {
		t.Fatalf("refused past expiry left %d rows: %v", count, err)
	}
}

func TestAdvisoryApprovalConsumptionRollsBackWithInvalidExpiry(t *testing.T) {
	parallelDeviceIntegration(t)
	f, request := advisoryAcceptanceFixture(t)
	// Beyond the 366-day acceptance bound, which only the acceptance itself
	// enforces after the approval is consumed in the same transaction.
	request.ExpiresAt = timestamppb.New(time.Now().Add(400 * 24 * time.Hour))
	created, err := f.svc.CreateApproval(f.ownerCtx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 3600, Payload: &adminv1.CreateApprovalRequest_AcceptAdvisoryFinding{AcceptAdvisoryFinding: request}}))
	if err != nil {
		t.Fatal(err)
	}
	request.ApprovalId = created.Msg.GetApproval().GetId()
	if _, err := f.svc.ApproveApproval(approvalReviewer(t, f.svc, f.ctx), connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: request.ApprovalId, Reason: "Review exact request"})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.AcceptAdvisoryFinding(f.ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("expired exception accepted: %v", err)
	}
	var state string
	if err := f.conn.QueryRow(f.ctx, "SELECT state FROM approval_requests WHERE id=$1", request.ApprovalId).Scan(&state); err != nil || state != "approved" {
		t.Fatalf("failed mutation consumed approval: %s %v", state, err)
	}
}
