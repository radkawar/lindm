//go:build integration

package targeting

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/identity"
	"lindm/internal/targeting/targetingdb"
)

func (f *targetingFixture) seedInventory(t *testing.T) {
	t.Helper()
	definition, err := encoded(&adminv1.AttributeDefinition{Key: "rack", Type: adminv1.AttributeType_ATTRIBUTE_TYPE_INT})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), "INSERT INTO inventory_attribute_definitions(key,definition) VALUES ('rack',$1)", definition); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), `INSERT INTO host_observations(generation_id,sequence,started_at,finished_at,received_at,digest,
 boot_id_status,boot_id_value,hostname_status,hostname_value,os_id_status,os_id_value,os_version_status,os_version_value,
 architecture_status,architecture_value,kernel_release_status,kernel_release_value,hardware_vendor_status,hardware_vendor_value,
 hardware_model_status,hardware_model_value,hardware_serial_status,hardware_serial_value)
 VALUES ($1,1,clock_timestamp(),clock_timestamp(),clock_timestamp(),$2,2,'',1,'canary',1,'debian',2,'',2,'',2,'',2,'',2,'',2,'')`, f.generation, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), "UPDATE enrollment_generations SET host_sequence=1 WHERE id=$1", f.generation); err != nil {
		t.Fatal(err)
	}
}
func (f *targetingFixture) seedResourceHead(t *testing.T, resource *policyv1.ProfileResource) {
	t.Helper()
	document, err := encoded(&policyv1.ResourceProfile{Name: "Targeting fixture", Resources: []*policyv1.ProfileResource{resource}})
	if err != nil {
		t.Fatal(err)
	}
	item, err := encoded(resource)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	if _, err := f.pool.Exec(t.Context(), `INSERT INTO resource_assignments(id,device_id,generation_id,request_id,request_digest,actor_id,authorization_version,revision_id,document,assigned_at)
 VALUES ($1,$2,$3,$4,$5,$6,1,$7,$8,clock_timestamp())`, id, f.device, f.generation, uuid.New(), make([]byte, 32), f.actor.ID, uuid.MustParse(f.profileRevision), document); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), `INSERT INTO resource_assignment_resources(assignment_id,resource_id,resource_kind,canonical_key,position,document,disposition,last_verified_at,verification_max_age_seconds)
 VALUES ($1,$2,1,'targeting-test.service',0,$3,3,clock_timestamp(),300)`, id, uuid.MustParse(resource.ResourceId), item); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), "INSERT INTO resource_assignment_heads(generation_id,assignment_id) VALUES ($1,$2)", f.generation, id); err != nil {
		t.Fatal(err)
	}
}

// RecordHealth exists only in integration tests as a narrow arithmetic fixture.
// Production has no API that supplies a health enum without deriving current-head
// native evidence; it exclusively uses RecordExecutionHealth.
func (s *Store) RecordHealth(ctx context.Context, tx pgx.Tx, campaign, device, generation uuid.UUID, health policyv1.RolloutHealth) error {
	if err := s.Lock(ctx, tx); err != nil {
		return err
	}
	q := targetingdb.New(tx)
	state, err := s.rolloutState(ctx, q, campaign)
	if err != nil {
		return err
	}
	var assignment uuid.UUID
	if err := tx.QueryRow(ctx, "SELECT assignment_id FROM resource_assignment_heads WHERE generation_id=$1", generation).Scan(&assignment); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	now, err := q.TargetingClock(ctx)
	if err != nil {
		return err
	}
	validUntil := pgtype.Timestamptz{Time: now.Time.Add(time.Duration(state.Rollout.Rings[state.RingIndex].HealthMaxAgeSeconds) * time.Second), Valid: true}
	count, err := q.UpdateRolloutExecutionHealth(ctx, targetingdb.UpdateRolloutExecutionHealthParams{RolloutID: campaign, RingIndex: int32(state.RingIndex), DeviceID: device, GenerationID: &generation, Health: int16(health), ReceivedAt: now, HealthValidUntil: validUntil, EvidenceAssignmentID: &assignment})
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrNotFound
	}
	_, err = s.RefreshRollout(ctx, tx, campaign)
	return err
}
func (f *targetingFixture) dynamicGroup(t *testing.T, filter *adminv1.DeviceFilter) *adminv1.PutDynamicGroupRequest {
	t.Helper()
	r := &adminv1.PutDynamicGroupRequest{RequestId: uuid.NewString(), Reason: "Use authoritative predicate inputs", Group: &adminv1.DynamicTargetGroup{GroupId: uuid.NewString(), Name: "Current evidence", Expression: &adminv1.TargetExpression{InventoryMaxAgeSeconds: 60, Nodes: []*adminv1.TargetNode{{Depth: 1, Node: &adminv1.TargetNode_Predicate{Predicate: filter}}}}}}
	if err := f.transaction(t, func(tx pgx.Tx) error {
		_, err := f.store.PutDynamicGroup(t.Context(), tx, f.actor, identity.PermissionManageInventory, r)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return r
}
func TestLatestUnavailableHostFieldCannotUseCachedSuccessfulProjection(t *testing.T) {
	f := newTargetingFixture(t)
	group := f.dynamicGroup(t, &adminv1.DeviceFilter{OsId: "debian"})
	f.putAssignment(t, &policyv1.TargetRef{Target: &policyv1.TargetRef_DynamicGroupId{DynamicGroupId: group.Group.GroupId}}, 0)
	earlier := f.preview(t)
	if len(earlier.Candidates) != 1 || earlier.Candidates[0].Match != included {
		t.Fatal("successful authoritative observation was not included")
	}
	// Model admission of a new unavailable native field: display projection keeps
	// its previous successful value while sequence and receive time advance.
	if _, err := f.pool.Exec(t.Context(), "UPDATE host_observations SET sequence=2,os_id_status=2,os_id_value='',received_at=clock_timestamp() WHERE generation_id=$1", f.generation); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), "UPDATE enrollment_generations SET host_sequence=2 WHERE id=$1", f.generation); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), "UPDATE devices SET host_received_at=clock_timestamp() WHERE id=$1", f.device); err != nil {
		t.Fatal(err)
	}
	current := f.preview(t)
	if len(current.Candidates) != 1 || current.Candidates[0].Match != unknown {
		t.Fatal("failed latest observation became a positive or negative membership")
	}
	for _, p := range []*policyv1.TargetPreview{earlier, current} {
		err := f.transaction(t, func(tx pgx.Tx) error {
			_, err := f.store.Activate(t.Context(), tx, f.actor, identity.PermissionAssignResources, activation(p), func(context.Context, pgx.Tx, *policyv1.TargetPreview) error {
				t.Error("unavailable inventory invoked activation")
				return nil
			})
			return err
		})
		if !errors.Is(err, ErrConflict) && !errors.Is(err, ErrNotReady) {
			t.Fatalf("unavailable observation activated: %v", err)
		}
	}
}
func TestAttributeDefinitionPublicationAndSnapshotBinding(t *testing.T) {
	f := newTargetingFixture(t)
	good := f.dynamicGroup(t, &adminv1.DeviceFilter{Attributes: map[string]*adminv1.AttributeValue{"rack": {Value: &adminv1.AttributeValue_IntValue{IntValue: 0}}}})
	for _, attributes := range []map[string]*adminv1.AttributeValue{
		{"undefined": {Value: &adminv1.AttributeValue_IntValue{IntValue: 0}}},
		{"rack": {Value: &adminv1.AttributeValue_BoolValue{BoolValue: false}}},
	} {
		bad := proto.CloneOf(good)
		bad.RequestId = uuid.NewString()
		bad.Group.GroupId = uuid.NewString()
		bad.Group.Expression.Nodes[0].GetPredicate().Attributes = attributes
		err := f.transaction(t, func(tx pgx.Tx) error {
			_, err := f.store.PutDynamicGroup(t.Context(), tx, f.actor, identity.PermissionManageInventory, bad)
			return err
		})
		if !errors.Is(err, ErrRejected) {
			t.Fatalf("invalid definition reference admitted: %v", err)
		}
	}
	f.putAssignment(t, &policyv1.TargetRef{Target: &policyv1.TargetRef_DynamicGroupId{DynamicGroupId: good.Group.GroupId}}, 0)
	earlier := f.preview(t)
	// Clear the value first, as ordinary inventory definition changes require.
	if _, err := f.pool.Exec(t.Context(), "UPDATE devices SET metadata='{}' WHERE id=$1", f.device); err != nil {
		t.Fatal(err)
	}
	changed, err := encoded(&adminv1.AttributeDefinition{Key: "rack", Type: adminv1.AttributeType_ATTRIBUTE_TYPE_BOOL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), "UPDATE inventory_attribute_definitions SET definition=$1 WHERE key='rack'", changed); err != nil {
		t.Fatal(err)
	}
	current := f.preview(t)
	if len(current.Candidates) != 1 || current.Candidates[0].Match != unknown {
		t.Fatal("changed definition silently removed target membership")
	}
	err = f.transaction(t, func(tx pgx.Tx) error {
		_, err := f.store.Activate(t.Context(), tx, f.actor, identity.PermissionAssignResources, activation(earlier), func(context.Context, pgx.Tx, *policyv1.TargetPreview) error { return nil })
		return err
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("definition change retained old preview authority: %v", err)
	}
}
func TestSupersededResourceHeadCannotPromoteHealthyCampaign(t *testing.T) {
	f := newTargetingFixture(t)
	ring := &policyv1.RolloutRing{Name: "canary", Cohort: &policyv1.TargetRef{Target: &policyv1.TargetRef_DeviceId{DeviceId: f.device.String()}}, CumulativeBasisPoints: 10000, MinimumCanaries: 1, MinimumObserved: 1, SoakSeconds: 60, HealthMaxAgeSeconds: 60}
	next := proto.CloneOf(ring)
	next.Name = "fleet"
	request := &adminv1.PutRolloutRequest{RequestId: uuid.NewString(), Reason: "Bind rollout health to current resource head", Rollout: &policyv1.RolloutSpec{RolloutId: uuid.NewString(), Salt: make([]byte, 32), Rings: []*policyv1.RolloutRing{ring, next}}}
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
	newer := uuid.New()
	if _, err := f.pool.Exec(t.Context(), `INSERT INTO resource_assignments(id,device_id,generation_id,request_id,request_digest,actor_id,authorization_version,revision_id,document,assigned_at)
 SELECT $1,a.device_id,a.generation_id,$2,a.request_digest,a.actor_id,a.authorization_version,a.revision_id,a.document,clock_timestamp()
 FROM resource_assignments a JOIN resource_assignment_heads h ON h.assignment_id=a.id WHERE h.generation_id=$3`, newer, uuid.New(), f.generation); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), "UPDATE resource_assignment_heads SET assignment_id=$1 WHERE generation_id=$2", newer, f.generation); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), "UPDATE resource_rollouts SET stage_started_at=clock_timestamp()-interval '2 minutes' WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	if err := f.transaction(t, func(tx pgx.Tx) error {
		ready, err := f.store.RefreshRollout(t.Context(), tx, id)
		if ready {
			t.Error("superseded healthy evidence was ready for promotion")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.transaction(t, func(tx pgx.Tx) error {
		out, err := f.store.ListRollouts(t.Context(), tx, f.actor, identity.PermissionAssignResources, &adminv1.ListRolloutsRequest{PageSize: 100})
		if err == nil && (len(out.Rollouts) != 1 || !out.Rollouts[0].Paused || out.Rollouts[0].RingIndex != 0 || out.Rollouts[0].PauseReason != "unknown_threshold") {
			t.Error("superseded healthy evidence advanced rollout")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func assertRolloutTargetCount(t *testing.T, f *targetingFixture, id uuid.UUID, want int64) {
	t.Helper()
	if err := f.transaction(t, func(tx pgx.Tx) error {
		q := targetingdb.New(tx)
		state, err := f.store.rolloutState(t.Context(), q, id)
		if err != nil {
			return err
		}
		now, err := q.TargetingClock(t.Context())
		if err != nil {
			return err
		}
		counts, err := q.RolloutHealthCounts(t.Context(), targetingdb.RolloutHealthCountsParams{RolloutID: id, RingIndex: int32(state.RingIndex), FreshAfter: now, AvailabilityAfter: now, AssessedAt: now})
		if err == nil && counts.Targeted != want {
			t.Errorf("cumulative denominator %d, want %d", counts.Targeted, want)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
