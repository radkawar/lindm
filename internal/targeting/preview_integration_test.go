// SPDX-License-Identifier: Apache-2.0

//go:build integration

package targeting

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/identity"
)

func TestPreviewHeartbeatAllowsUnchangedActivation(t *testing.T) {
	for _, kind := range []string{"device", "static", "dynamic", "excluded dynamic"} {
		t.Run(kind, func(t *testing.T) {
			f := newTargetingFixture(t)
			target := &policyv1.TargetRef{Target: &policyv1.TargetRef_DeviceId{DeviceId: f.device.String()}}
			switch kind {
			case "static":
				group := uuid.New()
				if _, err := f.pool.Exec(t.Context(), "INSERT INTO device_groups(id,name) VALUES ($1,'Heartbeat canaries')", group); err != nil {
					t.Fatal(err)
				}
				if _, err := f.pool.Exec(t.Context(), "INSERT INTO device_group_memberships(group_id,device_id) VALUES ($1,$2)", group, f.device); err != nil {
					t.Fatal(err)
				}
				target = &policyv1.TargetRef{Target: &policyv1.TargetRef_StaticGroupId{StaticGroupId: group.String()}}
			case "dynamic", "excluded dynamic":
				os := "debian"
				if kind == "excluded dynamic" {
					os = "fedora"
				}
				group := f.dynamicGroup(t, &adminv1.DeviceFilter{OsId: os, Attributes: map[string]*adminv1.AttributeValue{"rack": {Value: &adminv1.AttributeValue_IntValue{IntValue: 0}}}})
				target = &policyv1.TargetRef{Target: &policyv1.TargetRef_DynamicGroupId{DynamicGroupId: group.Group.GroupId}}
			}
			f.putAssignment(t, target, 0)
			// Separate committed transactions model a heartbeat after the operator
			// reviewed the preview, not an update hidden in the preview snapshot.
			before := time.Unix(1000, 0).UTC()
			if _, err := f.pool.Exec(t.Context(), "UPDATE devices SET last_seen_at=$2 WHERE id=$1", f.device, before); err != nil {
				t.Fatal(err)
			}
			preview := f.preview(t)
			wantCandidates := 1
			if kind == "excluded dynamic" {
				wantCandidates = 0
			}
			if len(preview.Candidates) != wantCandidates || (wantCandidates == 1 && preview.Candidates[0].Match != included) {
				t.Fatal("unexpected initial membership")
			}
			if _, err := f.pool.Exec(t.Context(), "UPDATE devices SET last_seen_at=$2 WHERE id=$1", f.device, before.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			current := f.preview(t)
			if !bytes.Equal(preview.InputSha256, current.InputSha256) {
				t.Fatal("heartbeat changed an unrelated membership digest")
			}
			called := false
			err := f.transaction(t, func(tx pgx.Tx) error {
				got, err := f.store.Activate(t.Context(), tx, f.actor, identity.PermissionAssignResources, activation(preview), func(_ context.Context, _ pgx.Tx, pinned *policyv1.TargetPreview) error {
					called = true
					if !proto.Equal(pinned, preview) {
						t.Error("activation replaced the reviewed snapshot")
					}
					return nil
				})
				if err == nil && !proto.Equal(got, preview) {
					t.Error("activation returned a different preview")
				}
				return err
			})
			if err != nil || !called {
				t.Fatalf("unchanged preview did not activate after heartbeat: called=%v err=%v", called, err)
			}
		})
	}
}

func TestPreviewHeartbeatRejectsLastSeenMembershipChanges(t *testing.T) {
	boundary := timestamppb.New(time.Unix(1001, 0).UTC())
	for _, test := range []struct {
		name           string
		filter         *adminv1.DeviceFilter
		exclusion      bool
		beforeIncluded bool
	}{
		{name: "target leaves upper bound", filter: &adminv1.DeviceFilter{LastSeenUntil: boundary}, beforeIncluded: true},
		{name: "excluded catalog target enters lower bound", filter: &adminv1.DeviceFilter{LastSeenFrom: boundary}},
		{name: "exclusion starts matching", filter: &adminv1.DeviceFilter{LastSeenFrom: boundary}, exclusion: true, beforeIncluded: true},
		{name: "exclusion stops matching", filter: &adminv1.DeviceFilter{LastSeenUntil: boundary}, exclusion: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newTargetingFixture(t)
			group := f.dynamicGroup(t, test.filter)
			target := &policyv1.TargetRef{Target: &policyv1.TargetRef_DynamicGroupId{DynamicGroupId: group.Group.GroupId}}
			if test.exclusion {
				request := f.putAssignment(t, &policyv1.TargetRef{Target: &policyv1.TargetRef_DeviceId{DeviceId: f.device.String()}}, 0)
				request.RequestId = uuid.NewString()
				request.ExpectedRevision = 1
				request.Assignment.Exclusions = []*policyv1.TargetRef{target}
				if err := f.transaction(t, func(tx pgx.Tx) error {
					_, err := f.store.PutAssignment(t.Context(), tx, f.actor, identity.PermissionAssignResources, request)
					return err
				}); err != nil {
					t.Fatal(err)
				}
			} else {
				f.putAssignment(t, target, 0)
			}
			if _, err := f.pool.Exec(t.Context(), "UPDATE devices SET last_seen_at=$2 WHERE id=$1", f.device, time.Unix(1000, 0).UTC()); err != nil {
				t.Fatal(err)
			}
			preview := f.preview(t)
			if selected := len(preview.Candidates) == 1 && preview.Candidates[0].Match == included; selected != test.beforeIncluded {
				t.Fatal("unexpected initial last-seen membership")
			}
			if _, err := f.pool.Exec(t.Context(), "UPDATE devices SET last_seen_at=$2 WHERE id=$1", f.device, time.Unix(1002, 0).UTC()); err != nil {
				t.Fatal(err)
			}
			current := f.preview(t)
			if selected := len(current.Candidates) == 1 && current.Candidates[0].Match == included; selected == test.beforeIncluded {
				t.Fatal("last-seen boundary did not change membership")
			}
			if bytes.Equal(preview.InputSha256, current.InputSha256) {
				t.Fatal("changed last-seen membership retained input digest")
			}
			called := false
			err := f.transaction(t, func(tx pgx.Tx) error {
				_, err := f.store.Activate(t.Context(), tx, f.actor, identity.PermissionAssignResources, activation(preview), func(context.Context, pgx.Tx, *policyv1.TargetPreview) error {
					called = true
					return nil
				})
				return err
			})
			if !errors.Is(err, ErrConflict) || called {
				t.Fatalf("changed last-seen membership activated: called=%v err=%v", called, err)
			}
		})
	}
}
