// SPDX-License-Identifier: Apache-2.0

//go:build integration

package targeting

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/identity"
	"lindm/internal/policy"
	"lindm/internal/testdb"
)

type targetingFixture struct {
	pool               *pgxpool.Pool
	store              *Store
	actor              identity.Principal
	device, generation uuid.UUID
	profileRevision    string
}

func newTargetingFixture(t *testing.T) *targetingFixture {
	t.Helper()
	pool, _ := testdb.Open(t)
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	f := &targetingFixture{pool: pool, store: s, actor: identity.Principal{ID: uuid.New(), Role: identity.RoleOwner}, device: uuid.New(), generation: uuid.New()}
	if _, err := pool.Exec(t.Context(), "INSERT INTO principals(id,issuer,subject) VALUES ($1,'https://targeting.example',$2)", f.actor.ID, f.actor.ID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), "INSERT INTO devices(id,state,hostname,os_id,enrolled_at,host_received_at,last_seen_at,metadata) VALUES ($1,'active','canary','debian',clock_timestamp(),clock_timestamp(),clock_timestamp(),'{\"attributes\":{\"rack\":{\"intValue\":\"0\"}}}')", f.device); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), "INSERT INTO enrollment_generations(id,device_id,state,created_at) VALUES ($1,$2,'active',clock_timestamp())", f.generation, f.device); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), "UPDATE devices SET current_generation_id=$2 WHERE id=$1", f.device, f.generation); err != nil {
		t.Fatal(err)
	}
	profiles, err := policy.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	desired := &policyv1.ProfileResource{
		ResourceId:   uuid.NewString(),
		Desired:      &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: "targeting-test.service"}, State: &resourcev1.ResourceDesiredState_SystemdService{SystemdService: &resourcev1.SystemdServiceDesired{Unit: "targeting-test.service", Runtime: resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, Enablement: resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED}}},
		Ownership:    &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED},
		Verification: &resourcev1.VerificationPolicy{MaxAgeSeconds: 300, Checks: []resourcev1.HealthCheck{resourcev1.HealthCheck_HEALTH_CHECK_NATIVE_STATE}},
	}
	if err := f.transaction(t, func(tx pgx.Tx) error {
		revision, err := profiles.Publish(t.Context(), tx, &adminv1.PublishProfileRevisionRequest{RequestId: uuid.NewString(), ProfileId: uuid.NewString(), Reason: "Publish targeting fixture", Spec: &policyv1.ResourceProfile{Name: "Targeting fixture", Resources: []*policyv1.ProfileResource{desired}}}, f.actor.ID)
		if err == nil {
			f.profileRevision = revision.RevisionId
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f.seedInventory(t)
	f.seedResourceHead(t, desired)
	return f
}
func (f *targetingFixture) transaction(t *testing.T, fn func(pgx.Tx) error) error {
	t.Helper()
	tx, err := f.pool.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	// The domain contract is tested with the real principal lock; RPC integration
	// separately exercises identity's external freshness/approval acquisition.
	var id uuid.UUID
	if err := tx.QueryRow(t.Context(), "SELECT id FROM principals WHERE id=$1 FOR UPDATE", f.actor.ID).Scan(&id); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(t.Context())
}
func (f *targetingFixture) putAssignment(t *testing.T, target *policyv1.TargetRef, priority int32) *adminv1.PutTargetAssignmentRequest {
	t.Helper()
	r := &adminv1.PutTargetAssignmentRequest{RequestId: uuid.NewString(), Assignment: &policyv1.TargetAssignment{AssignmentId: uuid.NewString(), ProfileRevisionId: f.profileRevision, Target: target, Priority: priority}, Reason: "Test immutable membership"}
	if err := f.transaction(t, func(tx pgx.Tx) error {
		_, err := f.store.PutAssignment(t.Context(), tx, f.actor, identity.PermissionAssignResources, r)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return r
}

// These tests exercise targeting evidence, not policy resolution or native effects.
// An empty resolution is a legitimate retained document for no resource claims.
func emptyResolution(context.Context, pgx.Tx, []*policyv1.TargetCandidate) (*policyv1.TargetResolution, error) {
	return &policyv1.TargetResolution{}, nil
}
func (f *targetingFixture) preview(t *testing.T) *policyv1.TargetPreview {
	t.Helper()
	var p *policyv1.TargetPreview
	err := f.transaction(t, func(tx pgx.Tx) error {
		var err error
		p, err = f.store.Preview(t.Context(), tx, f.actor, identity.PermissionAssignResources, &adminv1.PreviewTargetAssignmentsRequest{DeviceId: f.device.String()}, emptyResolution)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func activation(p *policyv1.TargetPreview) *adminv1.ActivateTargetPreviewRequest {
	return &adminv1.ActivateTargetPreviewRequest{RequestId: uuid.NewString(), PreviewId: p.PreviewId, DeviceId: p.DeviceId, PreviewSha256: p.PreviewSha256, Reason: "Activate exact reviewed snapshot"}
}
func TestTargetingPinnedInputRejectsChangedMembership(t *testing.T) {
	f := newTargetingFixture(t)
	group := uuid.New()
	if _, err := f.pool.Exec(t.Context(), "INSERT INTO device_groups(id,name) VALUES ($1,'Canaries')", group); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), "INSERT INTO device_group_memberships(group_id,device_id) VALUES ($1,$2)", group, f.device); err != nil {
		t.Fatal(err)
	}
	f.putAssignment(t, &policyv1.TargetRef{Target: &policyv1.TargetRef_StaticGroupId{StaticGroupId: group.String()}}, -7)
	p := f.preview(t)
	if len(p.Candidates) != 1 || p.Candidates[0].Match != included {
		t.Fatal("static membership was not selected")
	}
	if _, err := f.pool.Exec(t.Context(), "DELETE FROM device_group_memberships WHERE group_id=$1", group); err != nil {
		t.Fatal(err)
	}
	called := false
	err := f.transaction(t, func(tx pgx.Tx) error {
		_, err := f.store.Activate(t.Context(), tx, f.actor, identity.PermissionAssignResources, activation(p), func(context.Context, pgx.Tx, *policyv1.TargetPreview) error { called = true; return nil })
		return err
	})
	if !errors.Is(err, ErrConflict) || called {
		t.Fatalf("changed membership activated: called=%v err=%v", called, err)
	}
	var count int
	if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FROM target_membership_snapshots WHERE preview_id=$1 AND membership=1 AND group_kind=1", uuid.MustParse(p.PreviewId)).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("static snapshot not retained")
	}
	if _, err := f.pool.Exec(t.Context(), "UPDATE target_previews SET digest=digest WHERE id=$1", uuid.MustParse(p.PreviewId)); err == nil {
		t.Fatal("immutable preview allowed update")
	}
}
func TestTargetingActivationRetryAndDeviceBinding(t *testing.T) {
	f := newTargetingFixture(t)
	p := f.preview(t)
	r := activation(p)
	wrong := proto.CloneOf(r)
	wrong.DeviceId = uuid.NewString()
	err := f.transaction(t, func(tx pgx.Tx) error {
		_, err := f.store.Activate(t.Context(), tx, f.actor, identity.PermissionAssignResources, wrong, func(context.Context, pgx.Tx, *policyv1.TargetPreview) error { return nil })
		return err
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("device binding accepted: %v", err)
	}
	calls := 0
	activate := func(context.Context, pgx.Tx, *policyv1.TargetPreview) error { calls++; return nil }
	for range 2 {
		if err := f.transaction(t, func(tx pgx.Tx) error {
			got, err := f.store.Activate(t.Context(), tx, f.actor, identity.PermissionAssignResources, r, activate)
			if err == nil && !proto.Equal(got, p) {
				t.Error("retry changed immutable document")
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("activation effect repeated %d times", calls)
	}
}
func TestTargetingDynamicUnknownAndTypedZero(t *testing.T) {
	f := newTargetingFixture(t)
	r := &adminv1.PutDynamicGroupRequest{RequestId: uuid.NewString(), Group: &adminv1.DynamicTargetGroup{GroupId: uuid.NewString(), Name: "Debian rack zero", Expression: &adminv1.TargetExpression{InventoryMaxAgeSeconds: 60, Nodes: []*adminv1.TargetNode{{Depth: 1, Node: &adminv1.TargetNode_Predicate{Predicate: &adminv1.DeviceFilter{OsId: "debian", Attributes: map[string]*adminv1.AttributeValue{"rack": {Value: &adminv1.AttributeValue_IntValue{IntValue: 0}}}}}}}}}, Reason: "Select typed inventory"}
	var published *adminv1.PutDynamicGroupResponse
	if err := f.transaction(t, func(tx pgx.Tx) error {
		var err error
		published, err = f.store.PutDynamicGroup(t.Context(), tx, f.actor, identity.PermissionManageInventory, r)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f.putAssignment(t, &policyv1.TargetRef{Target: &policyv1.TargetRef_DynamicGroupId{DynamicGroupId: r.Group.GroupId}}, 42)
	fresh := f.preview(t)
	if fresh.Candidates[0].Match != included {
		t.Fatal("typed zero was treated as missing")
	}
	if _, err := f.pool.Exec(t.Context(), "UPDATE host_observations SET received_at=clock_timestamp()-interval '2 minutes' WHERE generation_id=$1", f.generation); err != nil {
		t.Fatal(err)
	}
	stale := f.preview(t)
	if stale.Candidates[0].Match != unknown {
		t.Fatal("stale inventory implicitly removed membership")
	}
	err := f.transaction(t, func(tx pgx.Tx) error {
		_, err := f.store.Activate(t.Context(), tx, f.actor, identity.PermissionAssignResources, activation(stale), func(context.Context, pgx.Tx, *policyv1.TargetPreview) error { return nil })
		return err
	})
	if !errors.Is(err, ErrNotReady) {
		t.Fatalf("unknown membership activated: %v", err)
	}
	if err := f.transaction(t, func(tx pgx.Tx) error {
		got, err := f.store.PutDynamicGroup(t.Context(), tx, f.actor, identity.PermissionManageInventory, r)
		if err == nil && !proto.Equal(got, published) {
			t.Error("group retry changed revision")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
func TestTargetingPriorityExclusionAndScope(t *testing.T) {
	f := newTargetingFixture(t)
	target := &policyv1.TargetRef{Target: &policyv1.TargetRef_DeviceId{DeviceId: f.device.String()}}
	lower := f.putAssignment(t, target, -2147483648)
	upper := f.putAssignment(t, target, 2147483647)
	p := f.preview(t)
	if len(p.Candidates) != 2 || p.Candidates[0].Assignment.AssignmentId != upper.Assignment.AssignmentId {
		t.Fatal("signed priority ordering lost")
	}
	upper.RequestId = uuid.NewString()
	upper.ExpectedRevision = 1
	upper.Assignment.Exclusions = []*policyv1.TargetRef{target}
	if err := f.transaction(t, func(tx pgx.Tx) error {
		_, err := f.store.PutAssignment(t.Context(), tx, f.actor, identity.PermissionAssignResources, upper)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	p = f.preview(t)
	if len(p.Candidates) != 1 || p.Candidates[0].Assignment.AssignmentId != lower.Assignment.AssignmentId {
		t.Fatal("explicit exclusion did not win")
	}
	denied := f.actor
	denied.Bindings = []*authv1.RoleBinding{}
	err := f.transaction(t, func(tx pgx.Tx) error {
		_, err := f.store.Preview(t.Context(), tx, denied, identity.PermissionAssignResources, &adminv1.PreviewTargetAssignmentsRequest{DeviceId: f.device.String()}, emptyResolution)
		return err
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("scope denial leaked target: %v", err)
	}
}
func TestRolloutFrozenCanaryPauseAndSoak(t *testing.T) {
	f := newTargetingFixture(t)
	request := &adminv1.PutRolloutRequest{RequestId: uuid.NewString(), Reason: "Frozen canary campaign", Rollout: &policyv1.RolloutSpec{RolloutId: uuid.NewString(), Salt: make([]byte, 32), Rings: []*policyv1.RolloutRing{{Name: "canary", Cohort: &policyv1.TargetRef{Target: &policyv1.TargetRef_DeviceId{DeviceId: f.device.String()}}, CumulativeBasisPoints: 0, MinimumCanaries: 1, MinimumObserved: 1, SoakSeconds: 60, HealthMaxAgeSeconds: 60, FailureBasisPoints: 0, UnknownBasisPoints: 0, UnavailableBasisPoints: 0, ManualPromotion: true}}}}
	var out *adminv1.PutRolloutResponse
	if err := f.transaction(t, func(tx pgx.Tx) error {
		var err error
		out, err = f.store.PutRollout(t.Context(), tx, f.actor, identity.PermissionAssignResources, request)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if out.Rollout.SelectedCount != 1 {
		t.Fatal("minimum canary selected zero")
	}
	id := uuid.MustParse(request.Rollout.RolloutId)
	if err := f.transaction(t, func(tx pgx.Tx) error {
		return f.store.RecordHealth(t.Context(), tx, id, f.device, f.generation, policyv1.RolloutHealth_ROLLOUT_HEALTH_FAILED)
	}); err != nil {
		t.Fatal(err)
	}
	var paused bool
	if err := f.pool.QueryRow(t.Context(), "SELECT paused FROM resource_rollouts WHERE id=$1", id).Scan(&paused); err != nil {
		t.Fatal(err)
	}
	if !paused {
		t.Fatal("failure threshold failed to persist automatic pause")
	}
	var bucket int32
	if err := f.pool.QueryRow(t.Context(), "SELECT bucket FROM resource_rollout_members WHERE rollout_id=$1", id).Scan(&bucket); err != nil {
		t.Fatal(err)
	}
	if uint32(bucket) != Bucket(id, request.Rollout.Salt, f.device) {
		t.Fatal("durable bucket differs from stable selection")
	}
	if err := f.transaction(t, func(tx pgx.Tx) error {
		return f.store.RecordHealth(t.Context(), tx, id, f.device, uuid.New(), policyv1.RolloutHealth_ROLLOUT_HEALTH_HEALTHY)
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong generation refreshed health: %v", err)
	}
}

func TestRolloutSoakPromotionAndExpiredProofPause(t *testing.T) {
	f := newTargetingFixture(t)
	ring := &policyv1.RolloutRing{Name: "canary", Cohort: &policyv1.TargetRef{Target: &policyv1.TargetRef_DeviceId{DeviceId: f.device.String()}}, CumulativeBasisPoints: 10000, MinimumCanaries: 1, MinimumObserved: 1, SoakSeconds: 60, HealthMaxAgeSeconds: 60, ManualPromotion: true}
	next := proto.CloneOf(ring)
	next.Name = "fleet"
	request := &adminv1.PutRolloutRequest{RequestId: uuid.NewString(), Reason: "Exercise health and soak", Rollout: &policyv1.RolloutSpec{RolloutId: uuid.NewString(), Salt: make([]byte, 32), Rings: []*policyv1.RolloutRing{ring, next}}}
	if err := f.transaction(t, func(tx pgx.Tx) error {
		_, err := f.store.PutRollout(t.Context(), tx, f.actor, identity.PermissionAssignResources, request)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	id := uuid.MustParse(request.Rollout.RolloutId)
	if err := f.transaction(t, func(tx pgx.Tx) error {
		return f.store.RecordHealth(t.Context(), tx, id, f.device, f.generation, policyv1.RolloutHealth_ROLLOUT_HEALTH_HEALTHY)
	}); err != nil {
		t.Fatal(err)
	}
	control := &adminv1.ControlRolloutRequest{RequestId: uuid.NewString(), RolloutId: id.String(), ExpectedRevision: 1, Operation: adminv1.ControlRolloutRequest_OPERATION_PROMOTE, Reason: "Promote only after soak"}
	if err := f.transaction(t, func(tx pgx.Tx) error {
		_, err := f.store.ControlRollout(t.Context(), tx, f.actor, identity.PermissionAssignResources, control)
		return err
	}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("promotion ignored soak: %v", err)
	}
	if _, err := f.pool.Exec(t.Context(), "UPDATE resource_rollouts SET stage_started_at=clock_timestamp()-interval '2 minutes' WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	var promoted *adminv1.ControlRolloutResponse
	if err := f.transaction(t, func(tx pgx.Tx) error {
		var err error
		promoted, err = f.store.ControlRollout(t.Context(), tx, f.actor, identity.PermissionAssignResources, control)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if promoted.Rollout.RingIndex != 1 || promoted.Rollout.Revision != 2 {
		t.Fatal("healthy soaked ring did not advance")
	}
	if err := f.transaction(t, func(tx pgx.Tx) error {
		return f.store.RecordHealth(t.Context(), tx, id, f.device, f.generation, policyv1.RolloutHealth_ROLLOUT_HEALTH_HEALTHY)
	}); err != nil {
		t.Fatal(err)
	}
	assertRolloutTargetCount(t, f, id, 1)
	if _, err := f.pool.Exec(t.Context(), "UPDATE resource_rollouts SET stage_started_at=clock_timestamp()-interval '2 minutes' WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	// Native verification can expire before the ring's receipt-age window.
	if _, err := f.pool.Exec(t.Context(), "UPDATE resource_rollout_members SET health_valid_until=clock_timestamp()-interval '1 second' WHERE rollout_id=$1 AND ring_index=1", id); err != nil {
		t.Fatal(err)
	}
	if err := f.transaction(t, func(tx pgx.Tx) error {
		ready, err := f.store.RefreshRollout(t.Context(), tx, id)
		if ready {
			t.Error("expired native proof counted healthy")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var reason string
	if err := f.pool.QueryRow(t.Context(), "SELECT pause_reason FROM resource_rollouts WHERE id=$1", id).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason != "unknown_threshold" {
		t.Fatalf("stale proof pause reason %q", reason)
	}
}

func TestRolloutAutomaticPromotionRetainsCanaryAdmission(t *testing.T) {
	f := newTargetingFixture(t)
	other, otherGeneration := uuid.New(), uuid.New()
	if _, err := f.pool.Exec(t.Context(), "INSERT INTO devices(id,state,enrolled_at) VALUES ($1,'active',clock_timestamp())", other); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), "INSERT INTO enrollment_generations(id,device_id,state,created_at) VALUES ($1,$2,'active',clock_timestamp())", otherGeneration, other); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), "UPDATE devices SET current_generation_id=$2 WHERE id=$1", other, otherGeneration); err != nil {
		t.Fatal(err)
	}
	first := &policyv1.RolloutRing{Name: "canary", Cohort: &policyv1.TargetRef{Target: &policyv1.TargetRef_DeviceId{DeviceId: f.device.String()}}, CumulativeBasisPoints: 10000, MinimumCanaries: 1, MinimumObserved: 1, SoakSeconds: 60, HealthMaxAgeSeconds: 60}
	second := proto.CloneOf(first)
	second.Name = "different-cohort"
	second.Cohort = &policyv1.TargetRef{Target: &policyv1.TargetRef_DeviceId{DeviceId: other.String()}}
	request := &adminv1.PutRolloutRequest{RequestId: uuid.NewString(), Reason: "Automatic promotion with retained canary", Rollout: &policyv1.RolloutSpec{RolloutId: uuid.NewString(), Salt: make([]byte, 32), Rings: []*policyv1.RolloutRing{first, second}}}
	if err := f.transaction(t, func(tx pgx.Tx) error {
		_, err := f.store.PutRollout(t.Context(), tx, f.actor, identity.PermissionAssignResources, request)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	assignment := f.putAssignment(t, first.Cohort, 0)
	assignment.RequestId = uuid.NewString()
	assignment.ExpectedRevision = 1
	assignment.Assignment.RolloutId = proto.String(request.Rollout.RolloutId)
	if err := f.transaction(t, func(tx pgx.Tx) error {
		_, err := f.store.PutAssignment(t.Context(), tx, f.actor, identity.PermissionAssignResources, assignment)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	id := uuid.MustParse(request.Rollout.RolloutId)
	if err := f.transaction(t, func(tx pgx.Tx) error {
		return f.store.RecordHealth(t.Context(), tx, id, f.device, f.generation, policyv1.RolloutHealth_ROLLOUT_HEALTH_HEALTHY)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), "UPDATE resource_rollouts SET stage_started_at=clock_timestamp()-interval '2 minutes' WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	var fenceBefore, fenceAfter int64
	if err := f.pool.QueryRow(t.Context(), "SELECT revision FROM targeting_lock WHERE singleton").Scan(&fenceBefore); err != nil {
		t.Fatal(err)
	}
	if err := f.transaction(t, func(tx pgx.Tx) error {
		out, err := f.store.ListRollouts(t.Context(), tx, f.actor, identity.PermissionAssignResources, &adminv1.ListRolloutsRequest{PageSize: 100})
		if err == nil && (len(out.Rollouts) != 1 || out.Rollouts[0].RingIndex != 0 || out.Rollouts[0].Revision != 1 || out.Rollouts[0].Paused) {
			t.Error("read-only planning changed a promotion-ready rollout")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(t.Context(), "SELECT revision FROM targeting_lock WHERE singleton").Scan(&fenceAfter); err != nil {
		t.Fatal(err)
	}
	if fenceBefore != fenceAfter {
		t.Fatal("read-only rollout projection updated the targeting fence")
	}
	if err := f.transaction(t, func(tx pgx.Tx) error {
		out, err := f.store.PromoteAutomatic(t.Context(), tx, f.actor, identity.PermissionAssignResources, id)
		if err == nil && out.RingIndex != 1 {
			t.Error("automatic promotion did not advance the ring")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var auditReason, auditContext string
	if err := f.pool.QueryRow(t.Context(), "SELECT reason, details->>'context' FROM audit_events WHERE action='targeting.rollout.control' AND resource_id=$1", id.String()).Scan(&auditReason, &auditContext); err != nil {
		t.Fatal(err)
	}
	if auditReason != "" || auditContext != "Automatic promotion after verified health and soak" {
		t.Fatalf("automatic promotion fabricated operator reason: reason=%q context=%q", auditReason, auditContext)
	}
	preview := f.preview(t)
	if len(preview.Candidates) != 1 || preview.Candidates[0].Match != included {
		t.Fatal("promotion stopped management of an already admitted canary")
	}
	if err := f.transaction(t, func(tx pgx.Tx) error {
		return f.store.RecordHealth(t.Context(), tx, id, f.device, f.generation, policyv1.RolloutHealth_ROLLOUT_HEALTH_FAILED)
	}); err != nil {
		t.Fatal(err)
	}
	var pauseReason string
	if err := f.pool.QueryRow(t.Context(), "SELECT pause_reason FROM resource_rollouts WHERE id=$1", id).Scan(&pauseReason); err != nil {
		t.Fatal(err)
	}
	if pauseReason != "failure_threshold" {
		t.Fatalf("prior-ring canary failure did not pause later cohort: %q", pauseReason)
	}
	assertRolloutTargetCount(t, f, id, 2)
}
