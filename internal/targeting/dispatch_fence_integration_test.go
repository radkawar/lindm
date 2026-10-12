//go:build integration

package targeting

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/protobuf/proto"

	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/identity"
)

// Dispatches without rollout state share the targeting fence with each other
// but never with a targeting writer; rollout-bound dispatch stays exclusive, and
// a shared fence refuses rollout state instead of upgrading.
func TestDispatchFenceSharesOnlyWithoutRolloutState(t *testing.T) {
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
	rolloutBound := uuid.MustParse(f.preview(t).PreviewId)
	begin := func() pgx.Tx {
		t.Helper()
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tx.Rollback(ctx) })
		if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout = '300ms'"); err != nil {
			t.Fatal(err)
		}
		return tx
	}
	blocked := func(err error) bool {
		var database *pgconn.PgError
		return errors.As(err, &database) && database.Code == "55P03"
	}
	first, second := begin(), begin()
	shared, err := f.store.LockDispatch(ctx, first, uuid.Nil)
	if err != nil || shared.exclusive {
		t.Fatalf("plain dispatch fence: %+v %v", shared, err)
	}
	if other, err := f.store.LockDispatch(ctx, second, uuid.Nil); err != nil || other.exclusive {
		t.Fatalf("concurrent plain dispatch waited: %+v %v", other, err)
	}
	if err := f.store.Lock(ctx, begin()); !blocked(err) {
		t.Fatalf("targeting writer passed shared dispatch fences: %v", err)
	}
	if _, err := f.store.LockDispatch(ctx, begin(), rolloutBound); !blocked(err) {
		t.Fatalf("rollout-bound dispatch shared the fence: %v", err)
	}
	if _, err := f.store.CheckExecution(ctx, first, shared, f.device, f.generation, rolloutBound); !errors.Is(err, ErrDispatchFence) {
		t.Fatalf("shared fence reached rollout state: %v", err)
	}
	if err := f.store.RecordExecutionHealth(ctx, first, shared, f.device, f.generation, rolloutBound); !errors.Is(err, ErrDispatchFence) {
		t.Fatalf("shared fence recorded rollout health: %v", err)
	}
	if _, err := f.store.CheckExecution(ctx, second, shared, f.device, f.generation, rolloutBound); !errors.Is(err, ErrRejected) {
		t.Fatalf("fence accepted for another transaction: %v", err)
	}
	if err := first.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := second.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	exclusive, err := f.store.LockDispatch(ctx, begin(), rolloutBound)
	if err != nil || !exclusive.exclusive {
		t.Fatalf("rollout-bound dispatch fence: %+v %v", exclusive, err)
	}
	if _, err := f.store.LockDispatch(ctx, begin(), uuid.Nil); !blocked(err) {
		t.Fatalf("plain dispatch passed an exclusive rollout fence: %v", err)
	}
}
