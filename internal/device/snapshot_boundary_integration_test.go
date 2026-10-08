//go:build integration

package device

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	adminv1 "lindm/gen/lindm/admin/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/identity"
)

func TestPackageCursorBindsActorDeviceAndLiteralFilter(t *testing.T) {
	f := newEnrolled(t, 0)
	prefix := `a%_\`
	f.publishPackages(t, 1, "axy-decoy", prefix+"one", prefix+"two", "other")
	client := inventoryAdminClient(t, f, f.ownerCtx, false)
	first, err := client.ListDevicePackages(f.ctx, connect.NewRequest(&adminv1.ListDevicePackagesRequest{DeviceId: f.deviceID, PageSize: 1, NamePrefix: prefix}))
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Msg.Packages) != 1 || first.Msg.Packages[0].Name != prefix+"one" || first.Msg.NextPageToken == "" {
		t.Fatal("literal wildcard prefix selected the wrong first page")
	}
	otherActor := identity.WithPrincipal(f.ctx, insertPrincipal(t, f.ctx, f.conn, identity.RoleAdmin))
	otherClient := inventoryAdminClient(t, f, otherActor, true)
	request := &adminv1.ListDevicePackagesRequest{DeviceId: f.deviceID, PageSize: 1, PageToken: first.Msg.NextPageToken}
	if _, err := otherClient.ListDevicePackages(f.ctx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeInvalidArgument || rpcReason(err) != "page_token" {
		t.Fatalf("another actor reused package cursor: %v", err)
	}
	otherDevice := uuid.New()
	if _, err := f.conn.Exec(f.ctx, `INSERT INTO devices (id, state, enrolled_at) VALUES ($1, 'pending', $2)`, otherDevice, f.now); err != nil {
		t.Fatal(err)
	}
	request.DeviceId = otherDevice.String()
	if _, err := client.ListDevicePackages(f.ctx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeInvalidArgument || rpcReason(err) != "page_token" {
		t.Fatalf("cursor rebound to another device: %v", err)
	}
	request.DeviceId = f.deviceID
	request.NamePrefix = "other"
	request.Manager = "rpm"
	second, err := client.ListDevicePackages(f.ctx, connect.NewRequest(request))
	if err != nil || len(second.Msg.Packages) != 1 || second.Msg.Packages[0].Name != prefix+"two" || second.Msg.NextPageToken != "" {
		t.Fatalf("cursor lost its original literal filter after rejected reuse: %v", err)
	}
}

func TestPackageCursorExpiryWhileWaitingForCursorLock(t *testing.T) {
	f := newEnrolled(t, 0)
	f.publishPackages(t, 1, "one", "two")
	client := inventoryAdminClient(t, f, f.ownerCtx, false)
	first, err := client.ListDevicePackages(f.ctx, connect.NewRequest(&adminv1.ListDevicePackagesRequest{DeviceId: f.deviceID, PageSize: 1}))
	if err != nil {
		t.Fatal(err)
	}
	cursorID, _, err := decodePackagePage(first.Msg.NextPageToken)
	if err != nil {
		t.Fatal(err)
	}
	var clock atomic.Int64
	clock.Store(first.Msg.CursorExpiresAt.AsTime().Add(-time.Microsecond).UnixMicro())
	f.svc.clock = func() time.Time { return time.UnixMicro(clock.Load()).UTC() }
	lock, err := f.conn.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := lock.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error(err)
		}
	})
	var lockedID uuid.UUID
	if err := lock.QueryRow(f.ctx, `SELECT id FROM package_page_cursors WHERE id = $1 FOR UPDATE`, cursorID).Scan(&lockedID); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := client.ListDevicePackages(f.ctx, connect.NewRequest(&adminv1.ListDevicePackagesRequest{DeviceId: f.deviceID, PageSize: 1, PageToken: first.Msg.NextPageToken}))
		result <- err
	}()
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := f.svc.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1::integer = ANY(pg_blocking_pids(pid)))`, int32(f.conn.PgConn().PID())).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-result:
			t.Fatalf("page completed before cursor lock release: %v", err)
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	clock.Store(first.Msg.CursorExpiresAt.AsTime().UnixMicro())
	if err := lock.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if connect.CodeOf(err) != connect.CodeFailedPrecondition || rpcReason(err) != "page_expired" {
			t.Fatalf("cursor admitted after expiry while blocked: %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestConcurrentSnapshotAdmissionPreservesBudgetAndLoserSequence(t *testing.T) {
	f := newEnrolled(t, minInventoryBudget)
	otherKey := ed25519Key(t)
	_, _, _, enrolled := enrollDevice(t, f.ctx, f.svc, f.ownerCtx, otherKey)
	principal, err := f.svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), parseCertPEM(t, enrolled.Msg.CertificatePem))
	if err != nil {
		t.Fatal(err)
	}
	acquireTestSession(t, f.ctx, f.svc, principal, otherKey, 0)
	contexts := []context.Context{f.deviceCtx(), withDevicePrincipal(f.ctx, principal)}
	generations := []string{f.generation, enrolled.Msg.EnrollmentGeneration}
	manifests := make([]*devicev1.PackageSnapshotManifest, len(contexts))
	for i := range manifests {
		manifests[i] = declaredManifest(t, generations[i], 1, f.now, 64, maxBatchBytes)
	}
	type admission struct {
		index int
		err   error
	}
	start := make(chan struct{})
	results := make(chan admission, len(contexts))
	for i := range contexts {
		go func() {
			<-start
			_, err := f.svc.BeginPackageSnapshot(contexts[i], connect.NewRequest(&devicev1.BeginPackageSnapshotRequest{EnrollmentGeneration: generations[i], SessionEpoch: 1, Manifest: manifests[i]}))
			results <- admission{index: i, err: err}
		}()
	}
	close(start)
	winner, loser := -1, -1
	for range contexts {
		got := <-results
		if got.err == nil {
			if winner != -1 {
				t.Fatal("concurrent admissions exceeded the deployment reservation budget")
			}
			winner = got.index
		} else if connect.CodeOf(got.err) == connect.CodeResourceExhausted && rpcReason(got.err) == "inventory_budget" {
			loser = got.index
		} else {
			t.Fatalf("unexpected concurrent admission failure: %v", got.err)
		}
	}
	if winner == -1 || loser == -1 {
		t.Fatalf("expected exactly one winner and loser, got %d and %d", winner, loser)
	}
	var sequence, reserved int64
	var open bool
	if err := f.conn.QueryRow(f.ctx, `SELECT g.package_sequence, d.reserved_inventory_bytes, d.open_snapshot_id IS NOT NULL
		FROM enrollment_generations g JOIN devices d ON d.id = g.device_id WHERE g.id = $1`, generations[loser]).Scan(&sequence, &reserved, &open); err != nil {
		t.Fatal(err)
	}
	if sequence != 0 || reserved != 0 || open {
		t.Fatalf("failed admission mutated loser: sequence=%d reserved=%d open=%t", sequence, reserved, open)
	}
	var global, snapshots, devices int64
	if err := f.conn.QueryRow(f.ctx, `SELECT reserved_bytes, (SELECT sum(reserved_bytes) FROM package_snapshots), (SELECT sum(reserved_inventory_bytes) FROM devices) FROM inventory_reservation`).Scan(&global, &snapshots, &devices); err != nil {
		t.Fatal(err)
	}
	if global <= 0 || global > minInventoryBudget || global != snapshots || global != devices {
		t.Fatalf("reservation accounting diverged: global=%d snapshots=%d devices=%d", global, snapshots, devices)
	}
	if _, err := f.svc.BeginPackageSnapshot(contexts[winner], connect.NewRequest(&devicev1.BeginPackageSnapshotRequest{EnrollmentGeneration: generations[winner], SessionEpoch: 1, Manifest: manifests[winner]})); err != nil {
		t.Fatal(err)
	}
	var replayReserved int64
	if err := f.conn.QueryRow(f.ctx, `SELECT reserved_bytes FROM inventory_reservation`).Scan(&replayReserved); err != nil || replayReserved != global {
		t.Fatalf("admission replay double-reserved: got=%d want=%d error=%v", replayReserved, global, err)
	}
}
