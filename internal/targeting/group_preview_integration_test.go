// SPDX-License-Identifier: Apache-2.0

//go:build integration

package targeting

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/identity"
)

// previewDevice adds an active device whose latest inventory and last contact
// are the given ages; a negative contact age means the device was never seen.
func (f *targetingFixture) previewDevice(t *testing.T, hostname string, seenAgo time.Duration) {
	t.Helper()
	device, generation := uuid.New(), uuid.New()
	if _, err := f.pool.Exec(t.Context(), "INSERT INTO devices(id,state,enrolled_at,last_seen_at,metadata) VALUES ($1,'active',clock_timestamp(),CASE WHEN $2::float8 < 0 THEN NULL ELSE clock_timestamp() - make_interval(secs => $2::float8) END,'{}')", device, seenAgo.Seconds()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), "INSERT INTO enrollment_generations(id,device_id,state,created_at) VALUES ($1,$2,'active',clock_timestamp())", generation, device); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), "UPDATE devices SET current_generation_id=$2 WHERE id=$1", device, generation); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), `INSERT INTO host_observations(generation_id,sequence,started_at,finished_at,received_at,digest,
 boot_id_status,boot_id_value,hostname_status,hostname_value,os_id_status,os_id_value,os_version_status,os_version_value,
 architecture_status,architecture_value,kernel_release_status,kernel_release_value,hardware_vendor_status,hardware_vendor_value,
 hardware_model_status,hardware_model_value,hardware_serial_status,hardware_serial_value)
 VALUES ($1,1,clock_timestamp(),clock_timestamp(),clock_timestamp(),$2,2,'',1,$3,1,'ubuntu',2,'',2,'',2,'',2,'',2,'',2,'')`, generation, make([]byte, 32), hostname); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), "UPDATE enrollment_generations SET host_sequence=1 WHERE id=$1", generation); err != nil {
		t.Fatal(err)
	}
}

func (f *targetingFixture) previewGroup(t *testing.T, nodes ...*adminv1.TargetNode) (*adminv1.PreviewDynamicGroupResponse, error) {
	t.Helper()
	return f.previewGroupSample(t, 0, nodes...)
}

func (f *targetingFixture) previewGroupSample(t *testing.T, size uint32, nodes ...*adminv1.TargetNode) (*adminv1.PreviewDynamicGroupResponse, error) {
	t.Helper()
	var out *adminv1.PreviewDynamicGroupResponse
	err := f.transaction(t, func(tx pgx.Tx) error {
		var err error
		out, err = f.store.PreviewDynamicGroup(t.Context(), tx, f.actor, identity.PermissionManageInventory, &adminv1.PreviewDynamicGroupRequest{SampleSize: size, Expression: &adminv1.TargetExpression{InventoryMaxAgeSeconds: 3600, Nodes: nodes}})
		return err
	})
	return out, err
}

func previewPredicate(depth uint32, filter *adminv1.DeviceFilter) *adminv1.TargetNode {
	return &adminv1.TargetNode{Depth: depth, Node: &adminv1.TargetNode_Predicate{Predicate: filter}}
}

func TestPreviewDynamicGroupCountsUnsavedExpressionWithoutSaving(t *testing.T) {
	f := newTargetingFixture(t) // "canary": debian, seen now
	f.previewDevice(t, "ubuntu-ws-02", 10*24*time.Hour)
	f.previewDevice(t, "ubuntu-ws-01", time.Hour)
	f.previewDevice(t, "ubuntu-ws-03", -1)
	week := uint32(7 * 24 * 60 * 60)

	recent, err := f.previewGroup(t, previewPredicate(1, &adminv1.DeviceFilter{LastSeenWithinSeconds: week}))
	if err != nil {
		t.Fatal(err)
	}
	if !recent.Complete || recent.EvaluatedDeviceCount != 4 || recent.MatchedCount != 2 || recent.UnknownCount != 1 || recent.EvaluatedAt == nil {
		t.Fatalf("last seen within 7 days: %v", recent)
	}
	if len(recent.MatchedDevices) != 2 || recent.MatchedDevices[0].Hostname != "canary" || recent.MatchedDevices[1].Hostname != "ubuntu-ws-01" || recent.MatchedDevices[1].OsId != "ubuntu" {
		t.Fatalf("members not named in hostname order: %v", recent.MatchedDevices)
	}
	one, err := f.previewGroupSample(t, 1, previewPredicate(1, &adminv1.DeviceFilter{LastSeenWithinSeconds: week}))
	if err != nil || one.MatchedCount != 2 || len(one.MatchedDevices) != 1 || one.MatchedDevices[0].Hostname != "canary" {
		t.Fatalf("sample size one: %v %v", err, one)
	}
	if _, err := f.previewGroupSample(t, 101, previewPredicate(1, &adminv1.DeviceFilter{})); !errors.Is(err, ErrRejected) {
		t.Fatalf("unbounded sample accepted: %v", err)
	}

	// Nested condition group: OS is Ubuntu AND (seen within 7 days OR NOT seen within 30 days).
	nested, err := f.previewGroup(t,
		previewPredicate(1, &adminv1.DeviceFilter{OsId: "ubuntu"}),
		previewPredicate(1, &adminv1.DeviceFilter{LastSeenWithinSeconds: week}),
		previewPredicate(1, &adminv1.DeviceFilter{LastSeenWithinSeconds: 30 * 24 * 60 * 60}),
		&adminv1.TargetNode{Depth: 2, Node: &adminv1.TargetNode_NotIndex{NotIndex: 2}},
		&adminv1.TargetNode{Depth: 3, Node: &adminv1.TargetNode_Any{Any: &adminv1.TargetChildren{Indices: []uint32{1, 3}}}},
		&adminv1.TargetNode{Depth: 4, Node: &adminv1.TargetNode_All{All: &adminv1.TargetChildren{Indices: []uint32{0, 4}}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	// canary is debian; ubuntu-ws-02 is neither recent nor 30 days absent;
	// ubuntu-ws-03 was never seen, so its membership is undecided.
	if nested.MatchedCount != 1 || nested.UnknownCount != 1 || len(nested.MatchedDevices) != 1 || nested.MatchedDevices[0].Hostname != "ubuntu-ws-01" {
		t.Fatalf("nested any/all: %v", nested)
	}

	if _, err := f.previewGroup(t, &adminv1.TargetNode{Depth: 1, Node: &adminv1.TargetNode_NotIndex{NotIndex: 0}}); !errors.Is(err, ErrRejected) {
		t.Fatalf("cyclic expression previewed: %v", err)
	}
	if _, err := f.previewGroup(t, previewPredicate(1, &adminv1.DeviceFilter{Attributes: map[string]*adminv1.AttributeValue{"undefined": {Value: &adminv1.AttributeValue_IntValue{IntValue: 1}}}})); !errors.Is(err, ErrRejected) {
		t.Fatalf("undefined custom attribute previewed: %v", err)
	}

	var groups, requests, audits int
	if err := f.pool.QueryRow(t.Context(), "SELECT (SELECT count(*) FROM dynamic_target_groups),(SELECT count(*) FROM targeting_requests),(SELECT count(*) FROM audit_events WHERE action LIKE 'targeting.%')").Scan(&groups, &requests, &audits); err != nil {
		t.Fatal(err)
	}
	if groups != 0 || requests != 0 || audits != 0 {
		t.Fatalf("preview saved state: groups=%d requests=%d audits=%d", groups, requests, audits)
	}
}
