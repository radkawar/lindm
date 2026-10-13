//go:build integration

package device

import (
	"context"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func TestProposedImpactUsesCanonicalConflictResolverAndActualHead(t *testing.T) {
	f := newDispatchFixture(t)
	if _, err := f.service.ReportHostObservation(f.deviceCtx, connect.NewRequest(hostObservation(f.principal.GenerationID.String(), 1, "finance-laptop"))); err != nil {
		t.Fatal(err)
	}
	actual := f.assign(t, nil)
	service := proto.CloneOf(f.revision.GetSpec().GetResources()[1])
	service.DependsOn = nil
	publishDispatchResources(t, f, service)
	target := &policyv1.TargetRef{Target: &policyv1.TargetRef_DeviceId{DeviceId: f.principal.DeviceID.String()}}
	if _, err := f.service.PutTargetAssignment(f.adminCtx, connect.NewRequest(&adminv1.PutTargetAssignmentRequest{RequestId: uuid.NewString(), Reason: "Existing baseline service", Assignment: &policyv1.TargetAssignment{AssignmentId: uuid.NewString(), ProfileRevisionId: f.revision.RevisionId, Target: target}})); err != nil {
		t.Fatal(err)
	}
	conflicting := proto.CloneOf(service)
	conflicting.ResourceId = uuid.NewString()
	conflicting.GetDesired().GetSystemdService().Runtime = resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE
	publishDispatchResources(t, f, conflicting)
	request := &adminv1.PreviewTargetAssignmentImpactRequest{Assignment: &policyv1.TargetAssignment{AssignmentId: uuid.NewString(), ProfileRevisionId: f.revision.RevisionId, Target: target}, PageSize: 20}
	preview, err := f.service.PreviewTargetAssignmentImpact(f.adminCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Msg.Devices) != 1 || preview.Msg.Devices[0].Hostname != "finance-laptop" || !preview.Msg.Complete {
		t.Fatalf("named proposed device missing: %v", preview.Msg)
	}
	row := preview.Msg.Devices[0]
	// The current head has the original two resources, not the one-resource
	// catalog targeting preview. This catches a misleading 'current' projection.
	if len(row.CurrentResolution.Resources) != 2 || len(row.ProposedResolution.Resources) != 1 || !row.Changed {
		t.Fatalf("impact did not compare actual current head: %v", row)
	}
	if row.ProposedResolution.Resources[0].Disposition != policyv1.ResourceResolutionDisposition_RESOURCE_RESOLUTION_DISPOSITION_CONFLICT {
		t.Fatalf("canonical equal-priority conflict disappeared: %v", row.ProposedResolution)
	}
	var head uuid.UUID
	var count int
	if err := f.pool.QueryRow(t.Context(), "SELECT assignment_id FROM resource_assignment_heads WHERE generation_id=$1", f.principal.GenerationID).Scan(&head); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FROM target_assignments").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if head.String() != actual.AssignmentId || count != 1 {
		t.Fatal("preview saved or activated the proposed assignment")
	}
	// The current head is a direct per-device assignment: the review names the
	// revision whose settings the rollout would replace, never a silent removal.
	if !row.ReplacesDirectAssignment || preview.Msg.ReplacingDirectCount != 1 {
		t.Fatalf("review does not say it replaces the direct assignment: %v %d", row.ReplacesDirectAssignment, preview.Msg.ReplacingDirectCount)
	}
	for _, item := range row.CurrentResolution.Resources {
		if len(item.ContributingRevisionIds) != 1 || item.ContributingRevisionIds[0] != actual.RevisionId {
			t.Fatalf("current head provenance missing: %v", item)
		}
	}
	started, err := f.service.StartRollout(f.adminCtx, connect.NewRequest(reviewedRollout(preview.Msg, "Roll out reviewed conflict")))
	if err != nil {
		t.Fatal(err)
	}
	if state := started.Msg.Rollout; state.NeedsReviewCount != 1 || state.PlannedCount != 1 {
		t.Fatalf("a conflicting reviewed change was planned for activation: %v", state)
	}
	if err := f.pool.QueryRow(t.Context(), "SELECT assignment_id FROM resource_assignment_heads WHERE generation_id=$1", f.principal.GenerationID).Scan(&head); err != nil {
		t.Fatal(err)
	}
	if head.String() != actual.AssignmentId {
		t.Fatal("starting a rollout activated inside the request")
	}
}

func TestProposedImpactCanonicalAssignmentReplacement(t *testing.T) {
	f := newDispatchFixture(t)
	if _, err := f.service.ReportHostObservation(f.deviceCtx, connect.NewRequest(hostObservation(f.principal.GenerationID.String(), 1, "finance-replacement"))); err != nil {
		t.Fatal(err)
	}
	assignment := &policyv1.TargetAssignment{AssignmentId: "abcdef01-2345-4678-9abc-def012345678", ProfileRevisionId: f.revision.RevisionId, Target: &policyv1.TargetRef{Target: &policyv1.TargetRef_DeviceId{DeviceId: f.principal.DeviceID.String()}}}
	if _, err := f.service.PutTargetAssignment(f.adminCtx, connect.NewRequest(&adminv1.PutTargetAssignmentRequest{RequestId: uuid.NewString(), Assignment: assignment, Reason: "Original assignment"})); err != nil {
		t.Fatal(err)
	}
	proposal := proto.CloneOf(assignment)
	proposal.AssignmentId = strings.ToUpper(proposal.AssignmentId)
	proposal.Disabled = true
	review, err := f.service.PreviewTargetAssignmentImpact(f.adminCtx, connect.NewRequest(&adminv1.PreviewTargetAssignmentImpactRequest{Assignment: proposal, ExpectedRevision: 1, PageSize: 20}))
	if err != nil {
		t.Fatal(err)
	}
	if len(review.Msg.Devices) != 1 || len(review.Msg.Devices[0].ProposedResolution.Resources) != 0 || review.Msg.ExcludedCount != 1 {
		t.Fatalf("alternate UUID spelling retained old contributor: %v", review.Msg)
	}
	// Disabling removes settings only from devices whose head changes; this
	// device was never activated, so there is nothing to roll out.
	if _, err := f.service.StartRollout(f.adminCtx, connect.NewRequest(reviewedRollout(review.Msg, "Disable reviewed assignment"))); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("a rollout without any device change started: %v", err)
	}
	if _, err := f.service.PutTargetAssignment(f.adminCtx, connect.NewRequest(&adminv1.PutTargetAssignmentRequest{RequestId: uuid.NewString(), Assignment: proposal, ExpectedRevision: 1, Reason: "Disable reviewed assignment"})); err != nil {
		t.Fatal(err)
	}
	actual, err := f.service.PreviewTargetAssignments(f.adminCtx, connect.NewRequest(&adminv1.PreviewTargetAssignmentsRequest{DeviceId: f.principal.DeviceID.String()}))
	if err != nil {
		t.Fatal(err)
	}
	if len(actual.Msg.Preview.Candidates) != 0 || !proto.Equal(actual.Msg.Preview.Resolution, review.Msg.Devices[0].ProposedResolution) {
		t.Fatal("review and UUID-keyed save disagreed")
	}
}

// This is real PostgreSQL + RPC + canonical resource resolution, not a mocked
// fleet or resolver. The 9,999 pending devices deliberately retain unknown host
// and native readiness; only the enrolled fixture has a fresh named observation.
func TestTargetAssignmentImpactTenThousandRealReportPagesAndSave(t *testing.T) {
	f := newDispatchFixture(t)
	if _, err := f.service.ReportHostObservation(f.deviceCtx, connect.NewRequest(hostObservation(f.principal.GenerationID.String(), 1, "finance-canary"))); err != nil {
		t.Fatal(err)
	}
	service := proto.CloneOf(f.revision.GetSpec().GetResources()[1])
	service.DependsOn = nil
	publishDispatchResources(t, f, service)
	group := uuid.New()
	if _, err := f.pool.Exec(t.Context(), "INSERT INTO device_groups(id,name) VALUES ($1,'Finance 10000')", group); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), "WITH inserted AS (INSERT INTO devices(id,state,enrolled_at) SELECT gen_random_uuid(),'pending',now() FROM generate_series(1,9999) RETURNING id) INSERT INTO device_group_memberships(group_id,device_id) SELECT $1,id FROM inserted", group); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), "INSERT INTO device_group_memberships(group_id,device_id) VALUES ($1,$2)", group, f.principal.DeviceID); err != nil {
		t.Fatal(err)
	}
	request := &adminv1.PreviewTargetAssignmentImpactRequest{Assignment: &policyv1.TargetAssignment{AssignmentId: uuid.NewString(), ProfileRevisionId: f.revision.RevisionId, Target: &policyv1.TargetRef{Target: &policyv1.TargetRef_StaticGroupId{StaticGroupId: group.String()}}}, PageSize: 20}
	start := time.Now()
	// The outer transport deadline is 30 seconds; the service applies its tighter bound.
	buildCtx, cancelBuild := context.WithTimeout(f.adminCtx, 30*time.Second)
	first, err := f.service.PreviewTargetAssignmentImpact(buildCtx, connect.NewRequest(request))
	cancelBuild()
	if err != nil {
		t.Fatal(err)
	}
	buildDuration := time.Since(start)
	review := first.Msg
	page := review
	seen := make(map[string]bool, 10000)
	maxProto, maxJSON, pages := 0, 0, 0
	pageStart := time.Now()
	for {
		pages++
		if !page.Complete || page.CandidateCount != 10000 || page.EvaluatedDeviceCount != 10000 || page.TargetCount != 10000 || page.IncludedCount != 10000 || page.UnknownCount != 0 || page.ExcludedCount != 0 {
			t.Fatalf("10k report lost complete totals: %v", page)
		}
		if len(page.Devices) == 0 || len(page.Devices) > 20 {
			t.Fatal("unbounded or empty continuation page")
		}
		b, err := protojson.Marshal(page)
		if err != nil {
			t.Fatal(err)
		}
		maxJSON = max(maxJSON, len(b))
		maxProto = max(maxProto, proto.Size(page))
		for _, device := range page.Devices {
			if seen[device.DeviceId] || len(device.ProposedResolution.Resources) != 1 || !device.Changed {
				t.Fatal("page duplicated a device or lost real proposed settings")
			}
			seen[device.DeviceId] = true
		}
		if page.NextAfterDeviceId == nil {
			break
		}
		request.PreviewId, request.AfterDeviceId = &review.PreviewId, page.NextAfterDeviceId
		pageCtx, cancelPage := context.WithTimeout(f.adminCtx, 30*time.Second)
		next, err := f.service.PreviewTargetAssignmentImpact(pageCtx, connect.NewRequest(request))
		cancelPage()
		if err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(next.Msg.EvaluatedAt, review.EvaluatedAt) || string(next.Msg.ReviewSha256) != string(review.ReviewSha256) {
			t.Fatal("page changed retained review")
		}
		page = next.Msg
	}
	pageDuration := time.Since(pageStart)
	if len(seen) != 10000 || pages != 500 || maxProto > 1<<20 || maxJSON > 1<<20 {
		t.Fatalf("bounded 10k traversal failed: seen=%d pages=%d protobuf=%d JSON=%d", len(seen), pages, maxProto, maxJSON)
	}
	var persistedRows, persistedBytes int64
	if err := f.pool.QueryRow(t.Context(), "SELECT count(*),sum(octet_length(document)) FROM target_assignment_impact_devices WHERE report_id=$1", uuid.MustParse(review.PreviewId)).Scan(&persistedRows, &persistedBytes); err != nil {
		t.Fatal(err)
	}
	if persistedRows != 10000 || persistedBytes > 64<<20 {
		t.Fatalf("unbounded persisted report: rows=%d bytes=%d", persistedRows, persistedBytes)
	}
	t.Logf("10k impact before start: build=%s pages=%s", buildDuration, pageDuration)
	saveStart := time.Now()
	saveCtx, cancelSave := context.WithTimeout(f.adminCtx, 30*time.Second)
	defer cancelSave()
	started, err := f.service.StartRollout(saveCtx, connect.NewRequest(reviewedRollout(review, "Roll out fully reviewed 10000-device baseline")))
	if err != nil {
		t.Fatal(err)
	}
	saveDuration := time.Since(saveStart)
	state := started.Msg.GetRollout()
	if state.GetSelectedCount() != 1 || state.GetPendingCount() != 0 || state.GetExcludedCount() != 9999 {
		t.Fatalf("10k first stage changed cohort eligibility: %v", state)
	}
	var members, included, pendingGenerations int
	if err := f.pool.QueryRow(t.Context(), "SELECT count(*),count(*) FILTER(WHERE membership=1),count(*) FILTER(WHERE generation_id IS NULL AND membership=2) FROM resource_rollout_members WHERE rollout_id=$1 AND ring_index=0", uuid.MustParse(state.GetRollout().GetRolloutId())).Scan(&members, &included, &pendingGenerations); err != nil {
		t.Fatal(err)
	}
	if members != 10000 || included != 1 || pendingGenerations != 9999 {
		t.Fatalf("10k first stage lost durable members: members=%d included=%d pending_generations=%d", members, included, pendingGenerations)
	}
	t.Logf("10k impact build=%s pages=%s save=%s max_protobuf=%d max_json=%d persisted_rows=%d persisted_bytes=%d", buildDuration, pageDuration, saveDuration, maxProto, maxJSON, persistedRows, persistedBytes)
}

// reviewedRollout rolls out exactly the reviewed proposal to everyone at once.
func reviewedRollout(review *adminv1.PreviewTargetAssignmentImpactResponse, reason string) *adminv1.StartRolloutRequest {
	return &adminv1.StartRolloutRequest{
		RequestId: uuid.NewString(), PreviewId: review.PreviewId, ReviewSha256: review.ReviewSha256,
		Assignment: proto.CloneOf(review.Assignment), ExpectedRevision: review.ExpectedRevision, Reason: reason,
		Rollout: &policyv1.RolloutSpec{RolloutId: uuid.NewString(), Salt: make([]byte, 32), Name: reason, Rings: []*policyv1.RolloutRing{{
			Name: "everyone", Cohort: proto.CloneOf(review.Assignment.Target), CumulativeBasisPoints: 10000,
			MinimumCanaries: 1, MinimumObserved: 1, SoakSeconds: 3600, HealthMaxAgeSeconds: 86400,
			FailureBasisPoints: 500, UnknownBasisPoints: 1000, UnavailableBasisPoints: 1000,
		}}},
	}
}
