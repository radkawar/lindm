//go:build integration

package targeting

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/identity"
)

func emptyImpact(context.Context, pgx.Tx, *uuid.UUID, []*policyv1.TargetCandidate) (*policyv1.TargetResolution, *policyv1.TargetResolution, error) {
	return &policyv1.TargetResolution{}, &policyv1.TargetResolution{}, nil
}
func (f *targetingFixture) impactTransaction(t *testing.T, fn func(pgx.Tx) error) error {
	t.Helper()
	tx, err := f.pool.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), "SELECT id FROM principals WHERE id=$1 FOR UPDATE", f.actor.ID); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(t.Context())
}
func (f *targetingFixture) impact(t *testing.T, request *adminv1.PreviewTargetAssignmentImpactRequest) *adminv1.PreviewTargetAssignmentImpactResponse {
	t.Helper()
	var report *adminv1.PreviewTargetAssignmentImpactResponse
	if err := f.impactTransaction(t, func(tx pgx.Tx) error {
		var err error
		report, err = f.store.Impact(t.Context(), tx, f.actor, request, emptyImpact)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return report
}
func (f *targetingFixture) impactRequest(target *policyv1.TargetRef) *adminv1.PreviewTargetAssignmentImpactRequest {
	return &adminv1.PreviewTargetAssignmentImpactRequest{Assignment: &policyv1.TargetAssignment{AssignmentId: uuid.NewString(), ProfileRevisionId: f.profileRevision, Target: target}, PageSize: 20}
}
func reviewedSave(report *adminv1.PreviewTargetAssignmentImpactResponse) *adminv1.SaveTargetAssignmentImpactRequest {
	return &adminv1.SaveTargetAssignmentImpactRequest{RequestId: uuid.NewString(), PreviewId: report.PreviewId, ReviewSha256: report.ReviewSha256, Assignment: proto.CloneOf(report.Assignment), ExpectedRevision: report.ExpectedRevision, Reason: "Save the reviewed cohort baseline"}
}
func impactDevice(id uuid.UUID) *policyv1.TargetRef {
	return &policyv1.TargetRef{Target: &policyv1.TargetRef_DeviceId{DeviceId: id.String()}}
}
func impactGroup(id uuid.UUID) *policyv1.TargetRef {
	return &policyv1.TargetRef{Target: &policyv1.TargetRef_StaticGroupId{StaticGroupId: id.String()}}
}
func (f *targetingFixture) impactGroup(t *testing.T, count int) uuid.UUID {
	t.Helper()
	group := uuid.New()
	if _, err := f.pool.Exec(t.Context(), "INSERT INTO device_groups(id,name) VALUES ($1,'Finance')", group); err != nil {
		t.Fatal(err)
	}
	if count > 0 {
		if _, err := f.pool.Exec(t.Context(), "WITH inserted AS (INSERT INTO devices(id,state,enrolled_at) SELECT gen_random_uuid(),'pending',now() FROM generate_series(1,$2::int) RETURNING id) INSERT INTO device_group_memberships(group_id,device_id) SELECT $1,id FROM inserted", group, count); err != nil {
			t.Fatal(err)
		}
	}
	return group
}

func TestImpactProposedScopeExclusionsAndNoDomainEffects(t *testing.T) {
	f := newTargetingFixture(t)
	group := f.impactGroup(t, 1)
	if _, err := f.pool.Exec(t.Context(), "INSERT INTO device_group_memberships(group_id,device_id) VALUES ($1,$2)", group, f.device); err != nil {
		t.Fatal(err)
	}
	r := f.impactRequest(impactGroup(group))
	r.Assignment.Exclusions = []*policyv1.TargetRef{impactDevice(f.device)}
	report := f.impact(t, r)
	if !report.Complete || report.CandidateCount != 2 || report.TargetCount != 2 || report.IncludedCount != 1 || report.ExcludedCount != 1 || len(report.Devices) != 2 {
		t.Fatalf("wrong proposed scope: %v", report)
	}
	for _, row := range report.Devices {
		if row.DeviceId == f.device.String() && (row.Match != excluded || row.Hostname == "" || row.HostReceivedAt == nil) {
			t.Fatalf("named excluded device lost context: %v", row)
		}
		if !slices.Contains(row.Reasons, "native_capabilities_unknown") {
			t.Fatal("server resolution implied native readiness")
		}
	}
	var assignments, previews, memberships, heads, requests, audits int
	if err := f.pool.QueryRow(t.Context(), "SELECT (SELECT count(*) FROM target_assignments),(SELECT count(*) FROM target_previews),(SELECT count(*) FROM target_membership_snapshots),(SELECT count(*) FROM target_execution_heads),(SELECT count(*) FROM targeting_requests),(SELECT count(*) FROM audit_events WHERE action LIKE 'targeting.%')").Scan(&assignments, &previews, &memberships, &heads, &requests, &audits); err != nil {
		t.Fatal(err)
	}
	if assignments+previews+memberships+heads+requests+audits != 0 {
		t.Fatal("impact changed targeting domain state")
	}
}

func TestImpactUpdateIncludesRemovedScope(t *testing.T) {
	f := newTargetingFixture(t)
	old := f.putAssignment(t, impactDevice(f.device), 0)
	group := f.impactGroup(t, 1)
	r := &adminv1.PreviewTargetAssignmentImpactRequest{Assignment: proto.CloneOf(old.Assignment), ExpectedRevision: 1, PageSize: 20}
	r.Assignment.Target = impactGroup(group)
	report := f.impact(t, r)
	if report.CandidateCount != 2 || report.ExcludedCount != 1 || report.IncludedCount != 1 {
		t.Fatalf("removed old target was not reviewed: %v", report)
	}
}

func TestImpactUnknownMembershipAndFutureWindow(t *testing.T) {
	f := newTargetingFixture(t)
	group := f.dynamicGroup(t, &adminv1.DeviceFilter{OsId: "debian"})
	r := f.impactRequest(&policyv1.TargetRef{Target: &policyv1.TargetRef_DynamicGroupId{DynamicGroupId: group.Group.GroupId}})
	if _, err := f.pool.Exec(t.Context(), "UPDATE host_observations SET received_at=clock_timestamp()-interval '2 days' WHERE generation_id=$1", f.generation); err != nil {
		t.Fatal(err)
	}
	report := f.impact(t, r)
	if report.UnknownCount != 1 || report.Devices[0].Match != unknown || !slices.Contains(report.Devices[0].Reasons, "host_inventory_stale") {
		t.Fatalf("stale input became excluded or ready: %v", report)
	}
	r.Assignment.ActivatesAt = timestamppb.New(time.Now().Add(time.Hour))
	report = f.impact(t, r)
	if report.ExcludedCount != 1 {
		t.Fatal("future assignment bypassed canonical activation window")
	}
}

func TestImpactSaveFencesChangedInputs(t *testing.T) {
	for _, change := range []string{"new member", "removed member", "new device", "host", "metadata", "assignment", "proposal", "digest", "resolution", "scope"} {
		t.Run(change, func(t *testing.T) {
			f := newTargetingFixture(t)
			group := f.impactGroup(t, 0)
			if _, err := f.pool.Exec(t.Context(), "INSERT INTO device_group_memberships(group_id,device_id) VALUES ($1,$2)", group, f.device); err != nil {
				t.Fatal(err)
			}
			r := f.impactRequest(impactGroup(group))
			if change == "new device" {
				dynamic := f.dynamicGroup(t, &adminv1.DeviceFilter{OsId: "debian"})
				r.Assignment.Target = &policyv1.TargetRef{Target: &policyv1.TargetRef_DynamicGroupId{DynamicGroupId: dynamic.Group.GroupId}}
			}
			report := f.impact(t, r)
			save := reviewedSave(report)
			resolve := ImpactResolver(emptyImpact)
			switch change {
			case "new member":
				if _, err := f.pool.Exec(t.Context(), "WITH d AS (INSERT INTO devices(id,state,enrolled_at) VALUES (gen_random_uuid(),'pending',now()) RETURNING id) INSERT INTO device_group_memberships(group_id,device_id) SELECT $1,id FROM d", group); err != nil {
					t.Fatal(err)
				}
			case "removed member":
				if _, err := f.pool.Exec(t.Context(), "DELETE FROM device_group_memberships WHERE group_id=$1", group); err != nil {
					t.Fatal(err)
				}
			case "new device":
				if _, err := f.pool.Exec(t.Context(), "INSERT INTO devices(id,state,enrolled_at) VALUES (gen_random_uuid(),'pending',now())"); err != nil {
					t.Fatal(err)
				}
			case "host":
				if _, err := f.pool.Exec(t.Context(), "UPDATE host_observations SET hostname_value='renamed-finance' WHERE generation_id=$1", f.generation); err != nil {
					t.Fatal(err)
				}
			case "metadata":
				if _, err := f.pool.Exec(t.Context(), "UPDATE devices SET metadata='{}' WHERE id=$1", f.device); err != nil {
					t.Fatal(err)
				}
			case "assignment":
				f.putAssignment(t, impactDevice(f.device), 20)
			case "proposal":
				save.Assignment.Priority++
			case "digest":
				save.ReviewSha256 = make([]byte, 32)
			case "resolution":
				resolve = func(context.Context, pgx.Tx, *uuid.UUID, []*policyv1.TargetCandidate) (*policyv1.TargetResolution, *policyv1.TargetResolution, error) {
					return &policyv1.TargetResolution{}, &policyv1.TargetResolution{Resources: []*policyv1.ResolvedResource{{Reason: "changed_server_capability", Disposition: policyv1.ResourceResolutionDisposition_RESOURCE_RESOLUTION_DISPOSITION_BLOCKED}}}, nil
				}
			case "scope":
				f.actor.Bindings = []*authv1.RoleBinding{{Permissions: []string{string(identity.PermissionAssignResources)}}, {Permissions: []string{string(identity.PermissionReadFleet)}, Scopes: []*authv1.DeviceScope{{DeviceIds: []string{uuid.NewString()}}}}}
			}
			err := f.impactTransaction(t, func(tx pgx.Tx) error {
				_, err := f.store.SaveImpact(t.Context(), tx, f.actor, save, resolve)
				return err
			})
			if !errors.Is(err, ErrImpactStale) {
				t.Fatalf("changed %s did not require fresh review: %v", change, err)
			}
		})
	}
}

func TestImpactEmptyGroupBecomingNonemptyIsStale(t *testing.T) {
	f := newTargetingFixture(t)
	group := f.impactGroup(t, 0)
	report := f.impact(t, f.impactRequest(impactGroup(group)))
	if !report.Complete || report.TargetCount != 0 {
		t.Fatal("empty group was not explicit")
	}
	if _, err := f.pool.Exec(t.Context(), "INSERT INTO device_group_memberships(group_id,device_id) VALUES ($1,$2)", group, f.device); err != nil {
		t.Fatal(err)
	}
	if err := f.impactTransaction(t, func(tx pgx.Tx) error {
		_, err := f.store.SaveImpact(t.Context(), tx, f.actor, reviewedSave(report), emptyImpact)
		return err
	}); !errors.Is(err, ErrImpactStale) {
		t.Fatalf("empty cohort expanded during save: %v", err)
	}
}

func TestImpactAuthorityAndActorBoundPages(t *testing.T) {
	f := newTargetingFixture(t)
	r := f.impactRequest(impactDevice(f.device))
	report := f.impact(t, r)
	r.PreviewId = &report.PreviewId
	owner := f.actor
	f.actor.Bindings = []*authv1.RoleBinding{{Permissions: []string{string(identity.PermissionAssignResources)}, Scopes: []*authv1.DeviceScope{{DeviceIds: []string{f.device.String()}}}}}
	if err := f.impactTransaction(t, func(tx pgx.Tx) error { _, err := f.store.Impact(t.Context(), tx, f.actor, r, emptyImpact); return err }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("scoped assignment authority widened: %v", err)
	}
	f.actor = owner
	f.actor.ID = uuid.New()
	if err := f.impactTransaction(t, func(tx pgx.Tx) error { _, err := f.store.Impact(t.Context(), tx, f.actor, r, emptyImpact); return err }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another actor read report: %v", err)
	}
	f.actor = owner
	f.actor.Bindings = []*authv1.RoleBinding{{Permissions: []string{string(identity.PermissionAssignResources)}}, {Permissions: []string{string(identity.PermissionReadFleet)}, Scopes: []*authv1.DeviceScope{{DeviceIds: []string{uuid.NewString()}}}}}
	r.PreviewId = nil
	hidden := f.impact(t, r)
	if hidden.Complete || len(hidden.Devices) != 0 || hidden.TargetCount != 0 || hidden.CandidateCount != 0 {
		t.Fatalf("hidden devices leaked through aggregate/report: %v", hidden)
	}
}

func TestImpactSaveReplaySurvivesReportEviction(t *testing.T) {
	f := newTargetingFixture(t)
	r := f.impactRequest(impactDevice(f.device))
	report := f.impact(t, r)
	save := reviewedSave(report)
	var first *adminv1.PutTargetAssignmentResponse
	if err := f.impactTransaction(t, func(tx pgx.Tx) error {
		var err error
		first, err = f.store.SaveImpact(t.Context(), tx, f.actor, save, emptyImpact)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), "DELETE FROM target_assignment_impact_reports WHERE id=$1", uuid.MustParse(report.PreviewId)); err != nil {
		t.Fatal(err)
	}
	if err := f.impactTransaction(t, func(tx pgx.Tx) error {
		got, err := f.store.SaveImpact(t.Context(), tx, f.actor, save, nil)
		if err == nil && !proto.Equal(first, got) {
			t.Error("replay replaced original result")
		}
		return err
	}); err != nil {
		t.Fatalf("replay depended on live report or resolver: %v", err)
	}
	save.Reason = "different request content"
	if err := f.impactTransaction(t, func(tx pgx.Tx) error { _, err := f.store.SaveImpact(t.Context(), tx, f.actor, save, nil); return err }); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed replay accepted: %v", err)
	}
	var revisions, heads int
	if err := f.pool.QueryRow(t.Context(), "SELECT (SELECT count(*) FROM target_assignment_revisions),(SELECT count(*) FROM target_execution_heads)").Scan(&revisions, &heads); err != nil {
		t.Fatal(err)
	}
	if revisions != 1 || heads != 0 {
		t.Fatal("reviewed save repeated mutation or activated")
	}
}

func TestImpactPaginationRetentionAndProposalBinding(t *testing.T) {
	f := newTargetingFixture(t)
	group := f.impactGroup(t, 25)
	r := f.impactRequest(impactGroup(group))
	r.PageSize = 7
	first := f.impact(t, r)
	if len(first.Devices) != 7 || first.NextAfterDeviceId == nil || first.CandidateCount != 25 {
		t.Fatalf("bad first page: %v", first)
	}
	r.PreviewId = &first.PreviewId
	seen := make(map[string]bool)
	page := first
	for {
		for _, row := range page.Devices {
			if seen[row.DeviceId] {
				t.Fatal("pagination repeated device")
			}
			seen[row.DeviceId] = true
		}
		if page.NextAfterDeviceId == nil {
			break
		}
		r.AfterDeviceId = page.NextAfterDeviceId
		page = f.impact(t, r)
		if !proto.Equal(page.Assignment, first.Assignment) || page.EvaluatedAt.AsTime() != first.EvaluatedAt.AsTime() || !slices.Equal(page.ReviewSha256, first.ReviewSha256) {
			t.Fatal("page changed report snapshot")
		}
	}
	if len(seen) != 25 {
		t.Fatal("pagination skipped devices")
	}
	r.Assignment.Priority++
	if err := f.impactTransaction(t, func(tx pgx.Tx) error { _, err := f.store.Impact(t.Context(), tx, f.actor, r, emptyImpact); return err }); !errors.Is(err, ErrConflict) {
		t.Fatalf("page changed proposal: %v", err)
	}
	for range 6 {
		f.impact(t, f.impactRequest(impactDevice(f.device)))
	}
	var reports int
	if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FROM target_assignment_impact_reports WHERE actor_id=$1", f.actor.ID).Scan(&reports); err != nil {
		t.Fatal(err)
	}
	if reports != 5 {
		t.Fatalf("unbounded report retention: %d", reports)
	}
}

func TestImpactTenThousandCandidatesAndOverflow(t *testing.T) {
	f := newTargetingFixture(t)
	group := f.impactGroup(t, maxImpactDevices)
	r := f.impactRequest(impactGroup(group))
	report := f.impact(t, r)
	if !report.Complete || report.EvaluatedDeviceCount != maxImpactDevices || report.CandidateCount != maxImpactDevices || len(report.Devices) != 20 {
		t.Fatalf("normal 10k cohort not supported: %v", report)
	}
	if err := f.impactTransaction(t, func(tx pgx.Tx) error {
		_, err := f.store.SaveImpact(t.Context(), tx, f.actor, reviewedSave(report), emptyImpact)
		return err
	}); err != nil {
		t.Fatalf("10k review could not save: %v", err)
	}
	if _, err := f.pool.Exec(t.Context(), "INSERT INTO device_group_memberships(group_id,device_id) VALUES ($1,$2)", group, f.device); err != nil {
		t.Fatal(err)
	}
	r.Assignment.AssignmentId = uuid.NewString()
	overflow := f.impact(t, r)
	if overflow.Complete || overflow.EvaluatedDeviceCount != maxImpactDevices || !slices.Contains(overflow.Reasons, "candidate_limit") {
		t.Fatalf("overflow disguised as full report: %v", overflow)
	}
	if err := f.impactTransaction(t, func(tx pgx.Tx) error {
		_, err := f.store.SaveImpact(t.Context(), tx, f.actor, reviewedSave(overflow), emptyImpact)
		return err
	}); !errors.Is(err, ErrImpactStale) {
		t.Fatalf("overflow saved: %v", err)
	}
}

func TestImpactOversizedRowAndUnsafeIsolationReject(t *testing.T) {
	f := newTargetingFixture(t)
	r := f.impactRequest(impactDevice(f.device))
	if err := f.transaction(t, func(tx pgx.Tx) error { _, err := f.store.Impact(t.Context(), tx, f.actor, r, emptyImpact); return err }); !errors.Is(err, ErrRejected) {
		t.Fatalf("repeatable snapshot allowed unsafe phantom fence: %v", err)
	}
	resolve := func(context.Context, pgx.Tx, *uuid.UUID, []*policyv1.TargetCandidate) (*policyv1.TargetResolution, *policyv1.TargetResolution, error) {
		return &policyv1.TargetResolution{}, &policyv1.TargetResolution{Resources: []*policyv1.ResolvedResource{{Reason: strings.Repeat("x", maxDocumentBytes)}}}, nil
	}
	if err := f.impactTransaction(t, func(tx pgx.Tx) error { _, err := f.store.Impact(t.Context(), tx, f.actor, r, resolve); return err }); !errors.Is(err, ErrCapacity) {
		t.Fatalf("unreviewable row retained: %v", err)
	}
}

func TestImpactByteAwarePagesNeverSkipLargeRows(t *testing.T) {
	f := newTargetingFixture(t)
	group := f.impactGroup(t, 4)
	r := f.impactRequest(impactGroup(group))
	resolve := func(context.Context, pgx.Tx, *uuid.UUID, []*policyv1.TargetCandidate) (*policyv1.TargetResolution, *policyv1.TargetResolution, error) {
		return &policyv1.TargetResolution{}, &policyv1.TargetResolution{Resources: []*policyv1.ResolvedResource{{Reason: strings.Repeat("x", 400000)}}}, nil
	}
	var report *adminv1.PreviewTargetAssignmentImpactResponse
	if err := f.impactTransaction(t, func(tx pgx.Tx) error {
		var err error
		report, err = f.store.Impact(t.Context(), tx, f.actor, r, resolve)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(report.Devices) != 2 || report.NextAfterDeviceId == nil {
		t.Fatalf("page did not shrink to byte ceiling: rows=%d", len(report.Devices))
	}
	firstLast := report.Devices[1].DeviceId
	r.PreviewId, r.AfterDeviceId = &report.PreviewId, report.NextAfterDeviceId
	next := f.impact(t, r)
	if len(next.Devices) != 2 || next.Devices[0].DeviceId <= firstLast || next.NextAfterDeviceId != nil {
		t.Fatal("byte-aware pagination skipped/repeated rows")
	}
}

func TestImpactRetainedExpiredReviewRejectsBeforeResolver(t *testing.T) {
	f := newTargetingFixture(t)
	r := f.impactRequest(impactDevice(f.device))
	// Seed an already-expired immutable report, without sleeps or weakening the
	// production immutability trigger to age a newly created report.
	report := &adminv1.PreviewTargetAssignmentImpactResponse{PreviewId: uuid.NewString(), Assignment: r.Assignment, Complete: true, ReviewSha256: make([]byte, 32), EvaluatedAt: timestamppb.New(time.Unix(1, 0)), ValidUntil: timestamppb.New(time.Unix(2, 0))}
	b, err := proto.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), "INSERT INTO target_assignment_impact_reports(id,actor_id,document,input_digest,expires_at) VALUES ($1,$2,$3,$4,$5)", uuid.MustParse(report.PreviewId), f.actor.ID, b, make([]byte, 32), time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	if err := f.impactTransaction(t, func(tx pgx.Tx) error {
		_, err := f.store.SaveImpact(t.Context(), tx, f.actor, reviewedSave(report), nil)
		return err
	}); !errors.Is(err, ErrImpactStale) {
		t.Fatalf("expired review reached resolution/save: %v", err)
	}
}

func TestImpactLocksCandidatePopulationUntilCommit(t *testing.T) {
	f := newTargetingFixture(t)
	group := f.impactGroup(t, 0)
	tx, err := f.pool.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	report, err := f.store.Impact(t.Context(), tx, f.actor, f.impactRequest(impactGroup(group)), emptyImpact)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	writer, err := f.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	running := false
	finished := make(chan struct{})
	defer func() {
		cancel()
		if running {
			<-finished
		}
		writer.Release()
	}()
	var pid int32
	if err := writer.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	running = true
	go func() {
		defer close(finished)
		_, err := writer.Exec(ctx, "INSERT INTO device_group_memberships(group_id,device_id) VALUES ($1,$2)", group, f.device)
		done <- err
	}()
	// Observe a real queued lock, rather than assuming a goroutine ran during a
	// fixed sleep. A row-only fence would allow this absent membership through.
	queued := false
	for !queued && ctx.Err() == nil {
		if err := f.pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND NOT granted)", pid).Scan(&queued); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			t.Fatalf("membership writer passed the report fence: %v", err)
		default:
		}
	}
	if !queued {
		t.Fatal("membership writer never reached the fence")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := f.impactTransaction(t, func(tx pgx.Tx) error {
		_, err := f.store.SaveImpact(t.Context(), tx, f.actor, reviewedSave(report), emptyImpact)
		return err
	}); !errors.Is(err, ErrImpactStale) {
		t.Fatalf("post-preview membership expansion saved: %v", err)
	}
}

func TestImpactUsesFrozenRolloutAdmissionAndFencesPause(t *testing.T) {
	f := newTargetingFixture(t)
	rollout := &adminv1.PutRolloutRequest{RequestId: uuid.NewString(), Reason: "Finance rollout gate", Rollout: &policyv1.RolloutSpec{RolloutId: uuid.NewString(), Salt: make([]byte, 32), Rings: []*policyv1.RolloutRing{{Name: "Finance", Cohort: impactDevice(f.device), CumulativeBasisPoints: 10000, MinimumCanaries: 1, MinimumObserved: 1, SoakSeconds: 60, HealthMaxAgeSeconds: 60, ManualPromotion: true}}}}
	if err := f.transaction(t, func(tx pgx.Tx) error {
		_, err := f.store.PutRollout(t.Context(), tx, f.actor, identity.PermissionAssignResources, rollout)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	r := f.impactRequest(impactDevice(f.device))
	r.Assignment.RolloutId = &rollout.Rollout.RolloutId
	before := f.impact(t, r)
	if before.IncludedCount != 1 {
		t.Fatal("frozen admitted canary missing from proposal")
	}
	if err := f.transaction(t, func(tx pgx.Tx) error {
		_, err := f.store.ControlRollout(t.Context(), tx, f.actor, identity.PermissionAssignResources, &adminv1.ControlRolloutRequest{RequestId: uuid.NewString(), RolloutId: rollout.Rollout.RolloutId, ExpectedRevision: 1, Operation: adminv1.ControlRolloutRequest_OPERATION_PAUSE, Reason: "Pause before reviewed save"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.impactTransaction(t, func(tx pgx.Tx) error {
		_, err := f.store.SaveImpact(t.Context(), tx, f.actor, reviewedSave(before), emptyImpact)
		return err
	}); !errors.Is(err, ErrImpactStale) {
		t.Fatalf("rollout changed after review but save proceeded: %v", err)
	}
	paused := f.impact(t, r)
	if paused.UnknownCount != 1 || paused.IncludedCount != 0 {
		t.Fatal("paused rollout was reported as admitted/ready")
	}
}

func TestImpactIgnoresLiveRolloutProjectionButFencesDurableChanges(t *testing.T) {
	for _, scenario := range []struct {
		name  string
		empty bool
	}{{name: "admitted_device"}, {name: "empty_cohort", empty: true}} {
		t.Run(scenario.name, func(t *testing.T) {
			f, auth, _, ctx := newPromoterFixture(t)
			id := putAutomaticRollout(t, ctx, f, auth)
			target := impactDevice(f.device)
			if scenario.empty {
				target = impactGroup(f.impactGroup(t, 0))
			}
			request := f.impactRequest(target)
			request.Assignment.RolloutId = proto.String(id.String())
			reviewed := f.impact(t, request)
			if scenario.empty && reviewed.CandidateCount != 0 {
				t.Fatal("empty-cohort dependency fixture included a device")
			}
			// Native receipts and elapsed soak change the live projection only.
			// This also exercises catalog dependencies when there are no rows.
			preparePromoterHealth(t, ctx, f, id, false)
			if err := f.impactTransaction(t, func(tx pgx.Tx) error {
				_, err := f.store.SaveImpact(ctx, tx, f.actor, reviewedSave(reviewed), emptyImpact)
				return err
			}); err != nil {
				t.Fatalf("live projection invalidated unchanged rollout admission: %v", err)
			}
			request.Assignment.AssignmentId = uuid.NewString()
			beforePause := f.impact(t, request)
			if err := f.transaction(t, func(tx pgx.Tx) error {
				_, err := f.store.ControlRollout(ctx, tx, f.actor, identity.PermissionAssignResources, &adminv1.ControlRolloutRequest{
					RequestId: uuid.NewString(), RolloutId: id.String(), ExpectedRevision: 1,
					Operation: adminv1.ControlRolloutRequest_OPERATION_PAUSE, Reason: "Pause after impact review",
				})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := f.impactTransaction(t, func(tx pgx.Tx) error {
				_, err := f.store.SaveImpact(ctx, tx, f.actor, reviewedSave(beforePause), emptyImpact)
				return err
			}); !errors.Is(err, ErrImpactStale) {
				t.Fatalf("durable rollout change did not invalidate reviewed impact: %v", err)
			}
		})
	}
}

func TestImpactFencesDynamicDefinitionRevision(t *testing.T) {
	f := newTargetingFixture(t)
	group := f.dynamicGroup(t, &adminv1.DeviceFilter{OsId: "debian"})
	r := f.impactRequest(&policyv1.TargetRef{Target: &policyv1.TargetRef_DynamicGroupId{DynamicGroupId: group.Group.GroupId}})
	before := f.impact(t, r)
	update := &adminv1.PutDynamicGroupRequest{RequestId: uuid.NewString(), Group: proto.CloneOf(group.Group), ExpectedRevision: 1, Reason: "Change Finance membership expression"}
	update.Group.Expression.Nodes[0].GetPredicate().OsId = "fedora"
	if err := f.transaction(t, func(tx pgx.Tx) error {
		_, err := f.store.PutDynamicGroup(t.Context(), tx, f.actor, identity.PermissionManageInventory, update)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.impactTransaction(t, func(tx pgx.Tx) error {
		_, err := f.store.SaveImpact(t.Context(), tx, f.actor, reviewedSave(before), emptyImpact)
		return err
	}); !errors.Is(err, ErrImpactStale) {
		t.Fatalf("dynamic definition changed after review: %v", err)
	}
}
