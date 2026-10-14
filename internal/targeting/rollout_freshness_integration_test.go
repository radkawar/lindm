// SPDX-License-Identifier: Apache-2.0

//go:build integration

package targeting

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/targeting/targetingdb"
)

func TestRolloutAuthenticatedContactAndNativeFreshnessAreIndependent(t *testing.T) {
	for _, scenario := range []struct {
		name       string
		contactAge time.Duration
		change     string
		wantReady  bool
		wantReason string
	}{
		{name: "connected_between_jittered_heartbeats", contactAge: 70 * time.Second, wantReady: true},
		{name: "fresh_authenticated_contact", wantReady: true},
		{name: "stale_native_receipt", change: "UPDATE resource_rollout_members SET received_at=clock_timestamp()-interval '70 seconds' WHERE rollout_id=$1", wantReason: "unknown_threshold"},
		{name: "expired_native_validity", change: "UPDATE resource_rollout_members SET health_valid_until=clock_timestamp()-interval '1 second' WHERE rollout_id=$1", wantReason: "unknown_threshold"},
		{name: "superseded_head", change: "DELETE FROM resource_assignment_heads WHERE assignment_id=(SELECT evidence_assignment_id FROM resource_rollout_members WHERE rollout_id=$1)", wantReason: "unknown_threshold"},
		{name: "generation_changed", change: "UPDATE devices SET current_generation_id=NULL WHERE id=(SELECT device_id FROM resource_rollout_members WHERE rollout_id=$1)", wantReason: "unavailable_threshold"},
		{name: "heartbeat_expired", contactAge: 4 * time.Minute, wantReason: "unavailable_threshold"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			f := newTargetingFixture(t)
			id := uuid.New()
			request := &adminv1.PutRolloutRequest{
				RequestId: uuid.NewString(), Reason: "Separate authenticated availability from native health",
				Rollout: &policyv1.RolloutSpec{RolloutId: id.String(), Salt: make([]byte, 32), Rings: []*policyv1.RolloutRing{{
					Name: "canary", Cohort: &policyv1.TargetRef{Target: &policyv1.TargetRef_DeviceId{DeviceId: f.device.String()}},
					CumulativeBasisPoints: 10000, MinimumCanaries: 1, MinimumObserved: 1,
					SoakSeconds: 60, HealthMaxAgeSeconds: 60, ManualPromotion: true,
				}}},
			}
			if err := f.transaction(t, func(tx pgx.Tx) error {
				_, err := f.store.PutRollout(t.Context(), tx, f.actor, identity.PermissionAssignResources, request)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			// Derive the receipt from the real current-head native resource rows,
			// rather than the arithmetic-only RecordHealth integration helper.
			if err := f.transaction(t, func(tx pgx.Tx) error {
				q := targetingdb.New(tx)
				now, err := q.TargetingClock(t.Context())
				if err != nil {
					return err
				}
				var assignment uuid.UUID
				if err := tx.QueryRow(t.Context(), "SELECT assignment_id FROM resource_assignment_heads WHERE generation_id=$1", f.generation).Scan(&assignment); err != nil {
					return err
				}
				health, err := q.CurrentExecutionHealth(t.Context(), targetingdb.CurrentExecutionHealthParams{
					AssignmentID: assignment, DeviceID: f.device, GenerationID: f.generation,
					FreshAfter: pgtype.Timestamptz{Time: now.Time.Add(-time.Minute), Valid: true},
				})
				if err != nil {
					return err
				}
				if health.Health != int16(policyv1.RolloutHealth_ROLLOUT_HEALTH_HEALTHY) {
					t.Fatalf("fixture has no current native proof: %v", health)
				}
				count, err := q.UpdateRolloutExecutionHealth(t.Context(), targetingdb.UpdateRolloutExecutionHealthParams{
					RolloutID: id, RingIndex: 0, DeviceID: f.device, GenerationID: &f.generation,
					Health: health.Health, ReceivedAt: health.OldestVerifiedAt,
					HealthValidUntil: health.NativeValidUntil, EvidenceAssignmentID: &assignment,
				})
				if err == nil && count != 1 {
					t.Fatalf("native evidence did not bind the frozen member: %d", count)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.pool.Exec(t.Context(), "UPDATE resource_rollouts SET stage_started_at=clock_timestamp()-interval '2 minutes' WHERE id=$1", id); err != nil {
				t.Fatal(err)
			}
			if scenario.change != "" {
				if _, err := f.pool.Exec(t.Context(), scenario.change, id); err != nil {
					t.Fatal(err)
				}
			}
			var received, validUntil time.Time
			if err := f.pool.QueryRow(t.Context(), "SELECT received_at,health_valid_until FROM resource_rollout_members WHERE rollout_id=$1", id).Scan(&received, &validUntil); err != nil {
				t.Fatal(err)
			}
			if err := f.transaction(t, func(tx pgx.Tx) error {
				q := targetingdb.New(tx)
				now, err := q.TargetingClock(t.Context())
				if err != nil {
					return err
				}
				// Exercise the durable contact query used after authenticated sync
				// and accepted dispatch, including a normal heartbeat interval.
				// RPC authentication fences are covered by device integration tests.
				if err := devicedb.New(tx).TouchDeviceLastSeen(t.Context(), devicedb.TouchDeviceLastSeenParams{
					ID: f.device, LastSeenAt: pgtype.Timestamptz{Time: now.Time.Add(-scenario.contactAge), Valid: true},
				}); err != nil {
					return err
				}
				ready, reason, err := f.store.assess(t.Context(), q, id)
				if err == nil && (ready != scenario.wantReady || reason != scenario.wantReason) {
					t.Errorf("assessment ready=%v reason=%q; want ready=%v reason=%q", ready, reason, scenario.wantReady, scenario.wantReason)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			var afterReceived, afterValidUntil time.Time
			if err := f.pool.QueryRow(t.Context(), "SELECT received_at,health_valid_until FROM resource_rollout_members WHERE rollout_id=$1", id).Scan(&afterReceived, &afterValidUntil); err != nil {
				t.Fatal(err)
			}
			if !received.Equal(afterReceived) || !validUntil.Equal(afterValidUntil) {
				t.Fatal("authenticated contact rejuvenated native verification")
			}
		})
	}
}
