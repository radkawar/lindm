// SPDX-License-Identifier: Apache-2.0

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
	resourcev1 "lindm/gen/lindm/resource/v1"
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

// reviewedStart rolls out exactly the reviewed proposal in one stage.
func reviewedStart(report *adminv1.PreviewTargetAssignmentImpactResponse) *adminv1.StartRolloutRequest {
	return &adminv1.StartRolloutRequest{RequestId: uuid.NewString(), PreviewId: report.PreviewId, ReviewSha256: report.ReviewSha256, Assignment: proto.CloneOf(report.Assignment), ExpectedRevision: report.ExpectedRevision, Rollout: singleStage(report.Assignment.Target), Reason: "Roll out the reviewed cohort baseline"}
}
func singleStage(target *policyv1.TargetRef) *policyv1.RolloutSpec {
	return &policyv1.RolloutSpec{RolloutId: uuid.NewString(), Salt: make([]byte, 32), Name: "Cohort baseline", Rings: []*policyv1.RolloutRing{{Name: "all", Cohort: proto.CloneOf(target), CumulativeBasisPoints: 10000, MinimumCanaries: 1, MinimumObserved: 1, SoakSeconds: 3600, FailureBasisPoints: 2000, UnknownBasisPoints: 10000, UnavailableBasisPoints: 10000, HealthMaxAgeSeconds: 86400}}}
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

// Counts cover only devices a rollout plans. A member enrolled but not yet
// active (no host report) keeps its changed row, marked device_not_active, but
// is neither a change nor an adoption: an unchanged declaration must not start
// a rollout (and request an approval) on every apply for it.
func TestImpactCountsOnlyPlannableDevices(t *testing.T) {
	f := newTargetingFixture(t)
	group := f.impactGroup(t, 1)
	if _, err := f.pool.Exec(t.Context(), "INSERT INTO device_group_memberships(group_id,device_id) VALUES ($1,$2)", group, f.device); err != nil {
		t.Fatal(err)
	}
	adopting := &policyv1.TargetResolution{Resources: []*policyv1.ResolvedResource{{
		Ref:         &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL, CanonicalKey: "net.ipv4.conf.all.accept_redirects"},
		Disposition: policyv1.ResourceResolutionDisposition_RESOURCE_RESOLUTION_DISPOSITION_READY,
		Resource: &policyv1.ProfileResource{
			Desired:   &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL, CanonicalKey: "net.ipv4.conf.all.accept_redirects"}},
			Ownership: &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED},
		},
	}}}
	resolve := func(context.Context, pgx.Tx, *uuid.UUID, []*policyv1.TargetCandidate) (*policyv1.TargetResolution, *policyv1.TargetResolution, error) {
		return &policyv1.TargetResolution{}, proto.CloneOf(adopting), nil
	}
	var report *adminv1.PreviewTargetAssignmentImpactResponse
	if err := f.impactTransaction(t, func(tx pgx.Tx) error {
		var err error
		report, err = f.store.Impact(t.Context(), tx, f.actor, f.impactRequest(impactGroup(group)), resolve)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// The fixture's active device runs a direct per-device head, so its change
	// replaces it; the pending member has no head and is not counted at all.
	if report.IncludedCount != 2 || report.ChangedCount != 1 || report.AdoptingCount != 1 || report.RemovingCount != 0 || report.ReplacingDirectCount != 1 || !report.ApprovalRequired {
		t.Fatalf("counts include a device no rollout plans: included=%d changed=%d adopting=%d removing=%d direct=%d approval=%v devices=%d", report.IncludedCount, report.ChangedCount, report.AdoptingCount, report.RemovingCount, report.ReplacingDirectCount, report.ApprovalRequired, len(report.Devices))
	}
	for _, row := range report.Devices {
		pending := row.DeviceId != f.device.String()
		if !row.Changed || pending != slices.Contains(row.Reasons, "device_not_active") {
			t.Fatalf("device row lost its change or activity reason: %v", row)
		}
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
			save := reviewedStart(report)
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
				_, err := f.store.StartRollout(t.Context(), tx, f.actor, save, resolve)
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
		_, err := f.store.StartRollout(t.Context(), tx, f.actor, reviewedStart(report), emptyImpact)
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
	save := reviewedStart(report)
	var first *adminv1.StartRolloutResponse
	if err := f.impactTransaction(t, func(tx pgx.Tx) error {
		var err error
		first, err = f.store.StartRollout(t.Context(), tx, f.actor, save, emptyImpact)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), "DELETE FROM target_assignment_impact_reports WHERE id=$1", uuid.MustParse(report.PreviewId)); err != nil {
		t.Fatal(err)
	}
	if err := f.impactTransaction(t, func(tx pgx.Tx) error {
		got, err := f.store.StartRollout(t.Context(), tx, f.actor, save, nil)
		if err == nil && !proto.Equal(first, got) {
			t.Error("replay replaced original result")
		}
		return err
	}); err != nil {
		t.Fatalf("replay depended on live report or resolver: %v", err)
	}
	save.Reason = "different request content"
	if err := f.impactTransaction(t, func(tx pgx.Tx) error { _, err := f.store.StartRollout(t.Context(), tx, f.actor, save, nil); return err }); !errors.Is(err, ErrConflict) {
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
	// A complete 10k review passes every freshness check; these pending devices
	// have no enrollment to change, so there is nothing to roll out.
	if err := f.impactTransaction(t, func(tx pgx.Tx) error {
		_, err := f.store.StartRollout(t.Context(), tx, f.actor, reviewedStart(report), emptyImpact)
		return err
	}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("10k review was not accepted up to planning: %v", err)
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
		_, err := f.store.StartRollout(t.Context(), tx, f.actor, reviewedStart(overflow), emptyImpact)
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
		_, err := f.store.StartRollout(t.Context(), tx, f.actor, reviewedStart(report), nil)
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
		_, err := f.store.StartRollout(t.Context(), tx, f.actor, reviewedStart(report), emptyImpact)
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
	// A reviewed rollout creates its own rollout; a proposal bound to another is refused.
	if err := f.impactTransaction(t, func(tx pgx.Tx) error {
		_, err := f.store.StartRollout(t.Context(), tx, f.actor, reviewedStart(before), emptyImpact)
		return err
	}); !errors.Is(err, ErrRejected) {
		t.Fatalf("rollout-bound proposal started another rollout: %v", err)
	}
	// A saved assignment bound to the rollout is a dependency of an unbound review.
	bound := f.putAssignment(t, impactDevice(f.device), 0)
	bound.RequestId, bound.ExpectedRevision, bound.Assignment.RolloutId = uuid.NewString(), 1, &rollout.Rollout.RolloutId
	if err := f.transaction(t, func(tx pgx.Tx) error {
		_, err := f.store.PutAssignment(t.Context(), tx, f.actor, identity.PermissionAssignResources, bound)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	unbound := f.impact(t, f.impactRequest(impactDevice(f.device)))
	if err := f.transaction(t, func(tx pgx.Tx) error {
		_, err := f.store.ControlRollout(t.Context(), tx, f.actor, identity.PermissionAssignResources, &adminv1.ControlRolloutRequest{RequestId: uuid.NewString(), RolloutId: rollout.Rollout.RolloutId, ExpectedRevision: 1, Operation: adminv1.ControlRolloutRequest_OPERATION_PAUSE, Reason: "Pause before reviewed save"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.impactTransaction(t, func(tx pgx.Tx) error {
		_, err := f.store.StartRollout(t.Context(), tx, f.actor, reviewedStart(unbound), emptyImpact)
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
			// The saved catalog holds an assignment bound to the rollout; reviews
			// of unbound proposals depend on that rollout's durable state.
			bound := f.putAssignment(t, target, 0)
			bound.RequestId, bound.ExpectedRevision, bound.Assignment.RolloutId = uuid.NewString(), 1, proto.String(id.String())
			if err := f.transaction(t, func(tx pgx.Tx) error {
				_, err := f.store.PutAssignment(ctx, tx, f.actor, identity.PermissionAssignResources, bound)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			request := f.impactRequest(target)
			reviewed := f.impact(t, request)
			if scenario.empty && reviewed.CandidateCount != 0 {
				t.Fatal("empty-cohort dependency fixture included a device")
			}
			// Native receipts and elapsed soak change the live projection only.
			// This also exercises catalog dependencies when there are no rows.
			preparePromoterHealth(t, ctx, f, id, false)
			want := error(nil)
			if scenario.empty {
				want = ErrNotReady
			}
			if err := f.impactTransaction(t, func(tx pgx.Tx) error {
				_, err := f.store.StartRollout(ctx, tx, f.actor, reviewedStart(reviewed), emptyImpact)
				return err
			}); !errors.Is(err, want) {
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
			// With no evaluated device the review never depended on the rollout.
			want = ErrImpactStale
			if scenario.empty {
				want = ErrNotReady
			}
			if err := f.impactTransaction(t, func(tx pgx.Tx) error {
				_, err := f.store.StartRollout(ctx, tx, f.actor, reviewedStart(beforePause), emptyImpact)
				return err
			}); !errors.Is(err, want) {
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
		_, err := f.store.StartRollout(t.Context(), tx, f.actor, reviewedStart(before), emptyImpact)
		return err
	}); !errors.Is(err, ErrImpactStale) {
		t.Fatalf("dynamic definition changed after review: %v", err)
	}
}
