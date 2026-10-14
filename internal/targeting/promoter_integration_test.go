// SPDX-License-Identifier: Apache-2.0

//go:build integration

package targeting

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/devlab/webauthnlab"
	"lindm/internal/identity"
	"lindm/internal/targeting/targetingdb"
)

// This fixture exercises real protected LOCAL setup with a software lab
// authenticator, account authorization and PostgreSQL, not browser qualification.
func newPromoterFixture(t *testing.T) (*targetingFixture, *identity.Service, *Promoter, context.Context) {
	t.Helper()
	f := newTargetingFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	t.Cleanup(cancel)
	auth, err := identity.New(ctx, f.pool, identity.Config{Local: true, PublicURL: "https://rollouts.example.test", HTTPClient: &http.Client{Timeout: time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := auth.Close(); err != nil {
			t.Error(err)
		}
	})
	code, err := identity.IssueSetupCode(ctx, f.pool)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := webauthnlab.RegisterSetupOwner(ctx, auth.Handler(), "https://rollouts.example.test", code, "rollout-owner", "private rollout fixture password")
	if err != nil {
		t.Fatal(err)
	}
	ownerID, err := uuid.Parse(owner.GetId())
	if err != nil {
		t.Fatal(err)
	}
	grant, err := auth.AuthorizeFresh(ctx, ownerID, identity.PermissionAssignResources)
	if err != nil {
		t.Fatal(err)
	}
	f.actor = grant.Principal()
	if unrestricted, _ := identity.DeviceScopes(f.actor, identity.PermissionAssignResources); !unrestricted {
		t.Fatal("creator did not begin with unrestricted resources.assign authority")
	}
	promoter, err := NewPromoter(f.pool, auth, f.store, testRolloutHooks(f))
	if err != nil {
		t.Fatal(err)
	}
	return f, auth, promoter, ctx
}

func putAutomaticRollout(t *testing.T, ctx context.Context, f *targetingFixture, auth *identity.Service) uuid.UUID {
	t.Helper()
	first := &policyv1.RolloutRing{
		Name: "canary", Cohort: &policyv1.TargetRef{Target: &policyv1.TargetRef_DeviceId{DeviceId: f.device.String()}},
		CumulativeBasisPoints: 10000, MinimumCanaries: 1, MinimumObserved: 1,
		SoakSeconds: 60, HealthMaxAgeSeconds: 300,
	}
	second, third := proto.CloneOf(first), proto.CloneOf(first)
	second.Name, third.Name = "expansion", "fleet"
	id := uuid.New()
	request := &adminv1.PutRolloutRequest{
		RequestId: uuid.NewString(), Reason: "Exercise autonomous promotion under current creator authority",
		Rollout: &policyv1.RolloutSpec{RolloutId: id.String(), Salt: make([]byte, 32), Rings: []*policyv1.RolloutRing{first, second, third}},
	}
	grant, err := auth.AuthorizeFresh(ctx, f.actor.ID, identity.PermissionAssignResources)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.transaction(t, func(tx pgx.Tx) error {
		if err := auth.LockAuthorization(ctx, tx, grant, identity.PermissionAssignResources); err != nil {
			return err
		}
		_, err := f.store.PutRollout(ctx, tx, grant.Principal(), identity.PermissionAssignResources, request)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

// Store the real native evidence without invoking RefreshRollout: the worker,
// rather than a result recorder or list request, must make the durable decision.
func preparePromoterHealth(t *testing.T, ctx context.Context, f *targetingFixture, id uuid.UUID, failed bool) {
	t.Helper()
	if failed {
		if _, err := f.pool.Exec(ctx, `UPDATE resource_assignment_resources SET disposition=4,reason='native_verification_failed'
WHERE assignment_id=(SELECT assignment_id FROM resource_assignment_heads WHERE generation_id=$1)`, f.generation); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.transaction(t, func(tx pgx.Tx) error {
		q := targetingdb.New(tx)
		now, err := q.TargetingClock(ctx)
		if err != nil {
			return err
		}
		var assignment uuid.UUID
		if err := tx.QueryRow(ctx, "SELECT assignment_id FROM resource_assignment_heads WHERE generation_id=$1", f.generation).Scan(&assignment); err != nil {
			return err
		}
		health, err := q.CurrentExecutionHealth(ctx, targetingdb.CurrentExecutionHealthParams{
			AssignmentID: assignment, DeviceID: f.device, GenerationID: f.generation,
			FreshAfter: pgtype.Timestamptz{Time: now.Time.Add(-5 * time.Minute), Valid: true},
		})
		if err != nil {
			return err
		}
		wantHealth := policyv1.RolloutHealth_ROLLOUT_HEALTH_HEALTHY
		if failed {
			wantHealth = policyv1.RolloutHealth_ROLLOUT_HEALTH_FAILED
		}
		if health.Health != int16(wantHealth) {
			t.Fatalf("current native health=%d, want %v", health.Health, wantHealth)
		}
		received, validUntil := health.OldestVerifiedAt, health.NativeValidUntil
		if failed {
			received, validUntil = now, now
		}
		count, err := q.UpdateRolloutExecutionHealth(ctx, targetingdb.UpdateRolloutExecutionHealthParams{
			RolloutID: id, RingIndex: 0, DeviceID: f.device, GenerationID: &f.generation,
			Health: health.Health, ReceivedAt: received, HealthValidUntil: validUntil, EvidenceAssignmentID: &assignment,
		})
		if err == nil && count != 1 {
			t.Fatalf("native evidence did not bind one frozen member: %d", count)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, "UPDATE resource_rollouts SET stage_started_at=clock_timestamp()-interval '2 minutes' WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	ready, reason, err := f.store.assess(ctx, targetingdb.New(f.pool), id)
	wantReason := ""
	if failed {
		wantReason = "failure_threshold"
	}
	if err != nil || ready == failed || reason != wantReason {
		t.Fatalf("prepared rollout ready=%v reason=%q err=%v; failed=%v", ready, reason, err, failed)
	}
}

func assertPromoterState(t *testing.T, ctx context.Context, f *targetingFixture, id uuid.UUID, ring int32, revision int64, reason string) {
	t.Helper()
	var creator uuid.UUID
	var gotRing int32
	var gotRevision int64
	var paused bool
	var gotReason string
	if err := f.pool.QueryRow(ctx, "SELECT creator_id,ring_index,revision,paused,pause_reason FROM resource_rollouts WHERE id=$1", id).Scan(&creator, &gotRing, &gotRevision, &paused, &gotReason); err != nil {
		t.Fatal(err)
	}
	if creator != f.actor.ID || gotRing != ring || gotRevision != revision || paused != (reason != "") || gotReason != reason {
		t.Fatalf("durable rollout creator=%s ring=%d revision=%d paused=%v reason=%q; want creator=%s ring=%d revision=%d reason=%q", creator, gotRing, gotRevision, paused, gotReason, f.actor.ID, ring, revision, reason)
	}
}

func assertPromoterAudit(t *testing.T, ctx context.Context, f *targetingFixture, id uuid.UUID, action, auditContext string, actor *uuid.UUID) {
	t.Helper()
	var count int
	if err := f.pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action=$2", id.String(), action).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("rollout %s audit count=%d, want 1", action, count)
	}
	var gotActor *uuid.UUID
	var reason, gotContext string
	if err := f.pool.QueryRow(ctx, "SELECT actor_id,reason,details->>'context' FROM audit_events WHERE resource_id=$1 AND action=$2", id.String(), action).Scan(&gotActor, &reason, &gotContext); err != nil {
		t.Fatal(err)
	}
	if reason != "" || gotContext != auditContext || (gotActor == nil) != (actor == nil) || (actor != nil && gotActor != nil && *gotActor != *actor) {
		t.Fatalf("automatic audit actor=%v reason=%q context=%q; want actor=%v empty reason context=%q", gotActor, reason, gotContext, actor, auditContext)
	}
}

func TestPromoterPromotesWithoutListAndDoesNotRepeatPromotion(t *testing.T) {
	f, auth, promoter, ctx := newPromoterFixture(t)
	id := putAutomaticRollout(t, ctx, f, auth)
	preparePromoterHealth(t, ctx, f, id, false)
	assertPromoterState(t, ctx, f, id, 0, 1, "")
	if err := promoter.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	assertPromoterState(t, ctx, f, id, 1, 2, "")
	// A new worker instance must observe the durable CAS result, not rely on
	// process-local deduplication. The next ring has neither soak nor proof yet.
	restarted, err := NewPromoter(f.pool, auth, f.store, testRolloutHooks(f))
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	assertPromoterState(t, ctx, f, id, 1, 2, "")
	assertPromoterAudit(t, ctx, f, id, "targeting.rollout.control", "Automatic promotion after verified health and soak", &f.actor.ID)
	var events, receipts, stages int
	if err := f.pool.QueryRow(ctx, `SELECT
(SELECT count(*) FROM resource_rollout_events WHERE rollout_id=$1),
(SELECT count(*) FROM targeting_requests WHERE actor_id=$2 AND method='targeting.rollout.control'),
(SELECT count(*) FROM resource_rollout_stages WHERE rollout_id=$1)`, id, f.actor.ID).Scan(&events, &receipts, &stages); err != nil {
		t.Fatal(err)
	}
	if events != 1 || receipts != 1 || stages != 2 {
		t.Fatalf("promotion was not exactly once: events=%d receipts=%d stages=%d", events, receipts, stages)
	}
}

func TestPromoterPausesWhenCreatorLosesCurrentAuthority(t *testing.T) {
	for _, change := range []string{"disabled", "scoped_resources_assign"} {
		t.Run(change, func(t *testing.T) {
			f, auth, promoter, ctx := newPromoterFixture(t)
			id := putAutomaticRollout(t, ctx, f, auth)
			preparePromoterHealth(t, ctx, f, id, false)
			switch change {
			case "disabled":
				if _, err := f.pool.Exec(ctx, "UPDATE local_accounts SET enabled=false WHERE id=$1", f.actor.ID); err != nil {
					t.Fatal(err)
				}
			case "scoped_resources_assign":
				scopes, err := protojson.Marshal(&authv1.RoleBinding{Scopes: []*authv1.DeviceScope{{Labels: []string{"other-fleet"}}}})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.pool.Exec(ctx, "UPDATE local_accounts SET role=$2,scope_binding=$3 WHERE id=$1", f.actor.ID, identity.RoleAdmin, scopes); err != nil {
					t.Fatal(err)
				}
				grant, err := auth.AuthorizeFresh(ctx, f.actor.ID, identity.PermissionAssignResources)
				if err != nil {
					t.Fatal(err)
				}
				if unrestricted, got := identity.DeviceScopes(grant.Principal(), identity.PermissionAssignResources); unrestricted || len(got) != 1 || len(got[0].Labels) != 1 || got[0].Labels[0] != "other-fleet" {
					t.Fatal("creator's current resources.assign authority was not narrowed")
				}
			}
			if err := promoter.RunOnce(ctx); err != nil {
				t.Fatal(err)
			}
			assertPromoterPaused(t, ctx, f, id, "rollout_authorization_denied")
			if err := promoter.RunOnce(ctx); err != nil {
				t.Fatal(err)
			}
			assertPromoterPaused(t, ctx, f, id, "rollout_authorization_denied")
		})
	}
}

func TestPromoterCommitsFailureBudgetPause(t *testing.T) {
	f, auth, promoter, ctx := newPromoterFixture(t)
	id := putAutomaticRollout(t, ctx, f, auth)
	preparePromoterHealth(t, ctx, f, id, true)
	assertPromoterState(t, ctx, f, id, 0, 1, "")
	if err := promoter.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	assertPromoterPaused(t, ctx, f, id, "failure_threshold")
	if err := promoter.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	assertPromoterPaused(t, ctx, f, id, "failure_threshold")
}

func assertPromoterPaused(t *testing.T, ctx context.Context, f *targetingFixture, id uuid.UUID, reason string) {
	t.Helper()
	assertPromoterState(t, ctx, f, id, 0, 2, reason)
	assertPromoterAudit(t, ctx, f, id, "targeting.rollout.pause", reason, nil)
	var events, pauses, promotions int
	if err := f.pool.QueryRow(ctx, `SELECT
(SELECT count(*) FROM resource_rollout_events WHERE rollout_id=$1),
(SELECT count(*) FROM resource_rollout_events WHERE rollout_id=$1 AND revision=2 AND reason=$2 AND actor_id IS NULL),
(SELECT count(*) FROM targeting_requests WHERE actor_id=$3 AND method='targeting.rollout.control')`, id, reason, f.actor.ID).Scan(&events, &pauses, &promotions); err != nil {
		t.Fatal(err)
	}
	if events != 1 || pauses != 1 || promotions != 0 {
		t.Fatalf("pause was not durable and exactly once: events=%d matching pauses=%d promotion receipts=%d", events, pauses, promotions)
	}
}

func rolloutReadSnapshot(t *testing.T, ctx context.Context, f *targetingFixture, id uuid.UUID) string {
	t.Helper()
	var snapshot string
	if err := f.pool.QueryRow(ctx, `SELECT jsonb_build_object(
'rollout',(SELECT to_jsonb(r) FROM resource_rollouts r WHERE id=$1),
'stages',(SELECT jsonb_agg(to_jsonb(s) ORDER BY ring_index) FROM resource_rollout_stages s WHERE rollout_id=$1),
'members',(SELECT jsonb_agg(to_jsonb(m) ORDER BY ring_index,device_id) FROM resource_rollout_members m WHERE rollout_id=$1),
'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM resource_rollout_events e WHERE rollout_id=$1),
'audits',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM audit_events a WHERE resource_id=$1::text),
'receipts',(SELECT jsonb_agg(to_jsonb(q) ORDER BY request_id) FROM targeting_requests q WHERE actor_id=$2),
'fence',(SELECT revision FROM targeting_lock WHERE singleton))::text`, id, f.actor.ID).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestListRolloutsNeverRefreshesReadyOrFailingRollouts(t *testing.T) {
	for _, failed := range []bool{false, true} {
		name := "ready"
		if failed {
			name = "failure_budget_exceeded"
		}
		t.Run(name, func(t *testing.T) {
			f, auth, _, ctx := newPromoterFixture(t)
			id := putAutomaticRollout(t, ctx, f, auth)
			preparePromoterHealth(t, ctx, f, id, failed)
			before := rolloutReadSnapshot(t, ctx, f, id)
			for _, mode := range []pgx.TxAccessMode{pgx.ReadWrite, pgx.ReadOnly} {
				tx, err := f.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: mode})
				if err != nil {
					t.Fatal(err)
				}
				out, err := f.store.ListRollouts(ctx, tx, f.actor, identity.PermissionAssignResources, &adminv1.ListRolloutsRequest{PageSize: 100})
				if err != nil {
					if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
						t.Error(rollbackErr)
					}
					t.Fatalf("list in %s transaction: %v", mode, err)
				}
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if len(out.Rollouts) != 1 || out.Rollouts[0].Rollout.RolloutId != id.String() || out.Rollouts[0].RingIndex != 0 || out.Rollouts[0].Revision != 1 || out.Rollouts[0].Paused || out.Rollouts[0].PauseReason != "" {
					t.Fatalf("list refreshed rollout state: %v", out)
				}
				if after := rolloutReadSnapshot(t, ctx, f, id); after != before {
					t.Fatalf("list mutated durable rollout, proof, audit, receipt or targeting fence in %s transaction", mode)
				}
			}
		})
	}
}

func TestPreviewActivationIgnoresLiveRolloutHealthProjection(t *testing.T) {
	f, auth, _, ctx := newPromoterFixture(t)
	id := putAutomaticRollout(t, ctx, f, auth)
	request := f.putAssignment(t, &policyv1.TargetRef{Target: &policyv1.TargetRef_DeviceId{DeviceId: f.device.String()}}, 0)
	request.RequestId = uuid.NewString()
	request.ExpectedRevision = 1
	request.Assignment.RolloutId = proto.String(id.String())
	if err := f.transaction(t, func(tx pgx.Tx) error {
		_, err := f.store.PutAssignment(ctx, tx, f.actor, identity.PermissionAssignResources, request)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	preview := f.preview(t)
	// Ordinary evidence and elapsed soak alter the live read projection, not
	// membership, the admitted ring or the retained rollout revision.
	preparePromoterHealth(t, ctx, f, id, false)
	state, err := f.store.rolloutState(ctx, targetingdb.New(f.pool), id)
	if err != nil {
		t.Fatal(err)
	}
	if !state.PromotionReady || state.HealthyCount != 1 || state.Revision != 1 {
		t.Fatalf("health fixture did not change only the live projection: %v", state)
	}
	activated := false
	if err := f.transaction(t, func(tx pgx.Tx) error {
		_, err := f.store.Activate(ctx, tx, f.actor, identity.PermissionAssignResources, activation(preview), func(context.Context, pgx.Tx, *policyv1.TargetPreview) error {
			activated = true
			return nil
		})
		return err
	}); err != nil {
		t.Fatalf("live health invalidated unchanged rollout admission: %v", err)
	}
	if !activated {
		t.Fatal("unchanged rollout admission was not activated")
	}
}
