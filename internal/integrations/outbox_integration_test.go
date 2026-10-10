//go:build integration

package integrations

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	integrationsv1 "lindm/gen/lindm/integrations/v1"
	"lindm/internal/integrations/integrationdb"
)

func TestAuditOutboxAtomicImmutableRedacted(t *testing.T) {
	f := newIntegrationFixture(t)
	f.target(t, 1, "https://example.test/events", "", bytes.Repeat([]byte{1}, 32))
	tx, err := f.pool.Begin(f.ctx)
	requireNoError(t, err)
	id := uuid.New()
	_, err = tx.Exec(f.ctx, "INSERT INTO audit_events(id,action,resource_id,reason) VALUES($1,'device.enrolled','device-a','password-secret')", id)
	requireNoError(t, err)
	var count int
	requireNoError(t, tx.QueryRow(f.ctx, "SELECT count(*) FROM integration_deliveries WHERE event_id=$1", id).Scan(&count))
	if count != 1 {
		t.Fatalf("fanout within domain transaction: %d", count)
	}
	requireNoError(t, tx.Rollback(f.ctx))
	requireNoError(t, f.conn.QueryRow(f.ctx, "SELECT count(*) FROM integration_events WHERE id=$1", id).Scan(&count))
	if count != 0 {
		t.Fatal("rollback retained outbox event")
	}
	id = f.event(t, "device-a")
	event, err := integrationdb.New(f.pool).LoadEvent(f.ctx, id)
	requireNoError(t, err)
	if bytes.Contains(event.Payload, []byte("super-secret")) || bytes.Contains(event.Payload, []byte("reason")) {
		t.Fatal("free-form reason leaked")
	}
	for _, statement := range []string{"UPDATE integration_events SET resource_id='tampered' WHERE id=$1", "DELETE FROM integration_events WHERE id=$1"} {
		if _, err = f.conn.Exec(f.ctx, statement, id); err == nil {
			t.Fatal("event mutation accepted")
		}
	}
	if _, err = f.conn.Exec(f.ctx, "TRUNCATE integration_events CASCADE"); err == nil {
		t.Fatal("event truncation accepted")
	}
}

func TestTwoWorkersFenceExpiredLeasesAndKeepResourceOrder(t *testing.T) {
	f := newIntegrationFixture(t)
	secret := bytes.Repeat([]byte{2}, 32)
	firstTarget := f.target(t, 1, "https://first.example/events", "", secret)
	secondTarget := f.target(t, 1, "https://second.example/events", "", secret)
	firstEvent := f.event(t, "same-device")
	f.event(t, "same-device")
	type claimed struct {
		row integrationdb.IntegrationDelivery
		err error
	}
	results := make(chan claimed, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Go(func() {
			token := uuid.New()
			row, err := integrationdb.New(f.pool).ClaimDelivery(f.ctx, &token)
			results <- claimed{row, err}
		})
	}
	workers.Wait()
	close(results)
	var leases []integrationdb.IntegrationDelivery
	for result := range results {
		requireNoError(t, result.err)
		leases = append(leases, result.row)
		if result.row.EventID != firstEvent {
			t.Fatal("later event overtook first")
		}
	}
	if leases[0].DestinationID == leases[1].DestinationID {
		t.Fatal("two workers acquired same destination/resource")
	}
	destinations := map[uuid.UUID]bool{firstTarget.ID: true, secondTarget.ID: true}
	if !destinations[leases[0].DestinationID] || !destinations[leases[1].DestinationID] {
		t.Fatal("unknown destination")
	}
	token := uuid.New()
	_, err := integrationdb.New(f.pool).ClaimDelivery(f.ctx, &token)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("active lease did not block later event: %v", err)
	}
	stale := leases[0]
	_, err = f.conn.Exec(f.ctx, "UPDATE integration_deliveries SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", stale.ID)
	requireNoError(t, err)
	current, err := integrationdb.New(f.pool).ClaimDelivery(f.ctx, &token)
	requireNoError(t, err)
	if current.ID != stale.ID || current.LeaseGeneration <= stale.LeaseGeneration {
		t.Fatal("expired lease not fenced and reclaimed")
	}
	q := integrationdb.New(f.pool)
	n, err := q.CompleteDelivery(f.ctx, integrationdb.CompleteDeliveryParams{ID: stale.ID, LeaseToken: stale.LeaseToken, LeaseGeneration: stale.LeaseGeneration})
	requireNoError(t, err)
	if n != 0 {
		t.Fatal("stale worker committed")
	}
	n, err = q.FailDelivery(f.ctx, integrationdb.FailDeliveryParams{ID: stale.ID, LeaseToken: stale.LeaseToken, LeaseGeneration: stale.LeaseGeneration, LastError: "stale", DelaySeconds: 5})
	requireNoError(t, err)
	if n != 0 {
		t.Fatal("stale worker rescheduled")
	}
	n, err = q.CompleteDelivery(f.ctx, integrationdb.CompleteDeliveryParams{ID: current.ID, LeaseToken: current.LeaseToken, LeaseGeneration: current.LeaseGeneration})
	requireNoError(t, err)
	if n != 1 {
		t.Fatal("current worker could not commit")
	}
	next, err := q.ClaimDelivery(f.ctx, &token)
	requireNoError(t, err)
	if next.EventID == firstEvent || next.DestinationID != current.DestinationID {
		t.Fatal("completed stream did not advance independently")
	}
}

func TestBackoffDeadLetterOrderingAndAuthorizedReplay(t *testing.T) {
	f := newIntegrationFixture(t)
	f.target(t, 1, "https://example.test/events", "", bytes.Repeat([]byte{3}, 32))
	first := f.event(t, "ordered")
	f.event(t, "ordered")
	q := integrationdb.New(f.pool)
	token := uuid.New()
	lease, err := q.ClaimDelivery(f.ctx, &token)
	requireNoError(t, err)
	before := time.Now()
	delay := retryDelay(lease.Attempts)
	n, err := q.FailDelivery(f.ctx, integrationdb.FailDeliveryParams{ID: lease.ID, LeaseToken: lease.LeaseToken, LeaseGeneration: lease.LeaseGeneration, DelaySeconds: delay.Seconds(), LastError: "webhook_http_503"})
	requireNoError(t, err)
	if n != 1 {
		t.Fatal("retry not saved")
	}
	row, err := q.LockDelivery(f.ctx, lease.ID)
	requireNoError(t, err)
	if !row.NextAttemptAt.Time.After(before.Add(2 * time.Second)) {
		t.Fatal("retry lost minimum backoff")
	}
	_, err = q.ClaimDelivery(f.ctx, &token)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("backoff or ordering bypassed: %v", err)
	}
	_, err = f.conn.Exec(f.ctx, "UPDATE integration_deliveries SET status=2,attempts=10,lease_token=$2,lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", lease.ID, token)
	requireNoError(t, err)
	requireNoError(t, q.ExpireExhaustedDeliveries(f.ctx))
	_, err = q.ClaimDelivery(f.ctx, &token)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("dead letter did not block stream: %v", err)
	}
	page, err := f.service.ListDeliveries(f.ctx, connect.NewRequest(&integrationsv1.ListDeliveriesRequest{Status: integrationsv1.DeliveryStatus_DELIVERY_STATUS_DEAD_LETTER}))
	requireNoError(t, err)
	if len(page.Msg.Deliveries) != 1 || page.Msg.Deliveries[0].EventId != first.String() {
		t.Fatal("dead letter listing missing")
	}
	request := &integrationsv1.ReplayDeliveryRequest{RequestId: uuid.NewString(), DeliveryId: lease.ID.String(), Reason: "receiver repaired"}
	replay, err := f.service.ReplayDelivery(f.ctx, connect.NewRequest(request))
	requireNoError(t, err)
	again, err := f.service.ReplayDelivery(f.ctx, connect.NewRequest(request))
	requireNoError(t, err)
	if !proto.Equal(replay.Msg, again.Msg) || replay.Msg.Delivery.ReplayCount != 1 {
		t.Fatal("replay was not idempotent")
	}
	changed := proto.CloneOf(request)
	changed.Reason = "changed input"
	_, err = f.service.ReplayDelivery(f.ctx, connect.NewRequest(changed))
	if connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("changed request replay accepted: %v", err)
	}
	row, err = q.LockDelivery(f.ctx, lease.ID)
	requireNoError(t, err)
	if row.Attempts != 0 || row.ReplayCount != 1 || row.Status != 1 {
		t.Fatal("replay transition invalid")
	}
	// Revoking the authoritative local account immediately blocks a new mutation,
	// even though the request still carries its previously valid principal.
	_, err = f.conn.Exec(f.ctx, "UPDATE local_accounts SET enabled=false WHERE id=$1", f.actor.ID)
	requireNoError(t, err)
	request.RequestId = uuid.NewString()
	_, err = f.service.ReplayDelivery(f.ctx, connect.NewRequest(request))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("disabled actor authorized: %v", err)
	}
}
