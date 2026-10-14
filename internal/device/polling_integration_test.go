// SPDX-License-Identifier: Apache-2.0

//go:build integration

package device

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	adminv1 "lindm/gen/lindm/admin/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/trust"
)

func TestPollingReadOnlyTransactionsAndHeartbeat(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDispatchFixture(t)
	state, err := f.service.Execution.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	rootDigest, err := trust.ExecutionRootDigest(state.Root)
	if err != nil {
		t.Fatal(err)
	}
	delegationDigest := sha256.Sum256(state.DelegationEnvelope)

	// A real PostgreSQL read-only connection rejects both UPDATE and FOR UPDATE,
	// including a FOR UPDATE that would otherwise only lock an unchanged tuple.
	cfg := f.pool.Config()
	cfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	for _, statement := range []string{
		"SELECT id FROM devices WHERE id=$1 FOR UPDATE",
		"UPDATE devices SET last_seen_at=clock_timestamp() WHERE id=$1",
	} {
		_, err := pool.Exec(t.Context(), statement, f.principal.DeviceID)
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "25006" {
			t.Fatalf("read-only database did not reject a write/row lock: %v", err)
		}
	}
	// The service holds admission counters and must not be copied; poll
	// through it with the read-only pool, then restore the writable pool.
	reader := f.service
	writable := reader.Pool
	reader.Pool = pool
	var before time.Time
	if err := f.pool.QueryRow(t.Context(), "UPDATE devices SET last_seen_at=clock_timestamp()-interval '2 minutes' WHERE id=$1 RETURNING last_seen_at", f.principal.DeviceID).Scan(&before); err != nil {
		t.Fatal(err)
	}

	lock, err := f.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Rollback(t.Context()) }()
	if _, err := devicedb.New(lock).GetDeviceForUpdate(t.Context(), f.principal.DeviceID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(f.deviceCtx, 5*time.Second)
	defer cancel()
	for _, current := range []bool{false, true} {
		request := &devicev1.GetExecutionTrustRequest{SessionEpoch: 1, RootVersion: state.Root.GetVersion(), RootSha256: rootDigest[:]}
		if current {
			request.DelegationVersion = state.Delegation.GetVersion()
			request.MinimumRecoveryEpoch = state.Delegation.GetMinimumRecoveryEpoch()
			request.DelegationSha256 = delegationDigest[:]
		}
		response, err := reader.GetExecutionTrust(ctx, connect.NewRequest(request))
		if err != nil {
			t.Fatalf("public trust poll needed a write or waited for the device lock: %v", err)
		}
		if response.Msg.GetRootVersion() != state.Root.GetVersion() || response.Msg.GetDelegationVersion() != state.Delegation.GetVersion() {
			t.Fatal("trust poll lost the authoritative versions")
		}
		if current && response.Msg.GetUpdate() != nil {
			t.Fatal("unchanged trust invented an update")
		}
		if !current && !bytes.Equal(response.Msg.GetUpdate().GetDelegationEnvelope(), state.DelegationEnvelope) {
			t.Fatal("read-only trust delivery lost the signed update")
		}
	}
	response, err := reader.GetResourceWork(ctx, connect.NewRequest(&devicev1.GetResourceWorkRequest{SessionEpoch: 1}))
	if err != nil || response.Msg.GetWork() != nil {
		t.Fatalf("empty work poll needed a write or waited for the device lock: %v", err)
	}
	if err := lock.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	reader.Pool = writable
	var after time.Time
	if err := f.pool.QueryRow(t.Context(), "SELECT last_seen_at FROM devices WHERE id=$1", f.principal.DeviceID).Scan(&after); err != nil || !after.Equal(before) {
		t.Fatalf("read-only polling changed durable last seen: %v %v", after, err)
	}
	if _, err := f.service.GetSyncState(f.deviceCtx, connect.NewRequest(&devicev1.GetSyncStateRequest{SessionEpoch: 1})); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(t.Context(), "SELECT last_seen_at FROM devices WHERE id=$1", f.principal.DeviceID).Scan(&after); err != nil || !after.After(before) {
		t.Fatalf("sync heartbeat no longer records durable contact: %v %v", after, err)
	}
}

func TestPollingAuthorityFences(t *testing.T) {
	parallelDeviceIntegration(t)
	for _, change := range []struct {
		name, statement, reason string
		code                    connect.Code
	}{
		{"session", "UPDATE enrollment_generations SET session_epoch=2 WHERE id=$2", "session_fenced", connect.CodeFailedPrecondition},
		{"device_hold", "UPDATE devices SET state='recovery_hold' WHERE id=$1", "recovery_hold", connect.CodePermissionDenied},
		{"generation_hold", "UPDATE enrollment_generations SET state='recovery_hold' WHERE id=$2", "certificate_rejected", connect.CodePermissionDenied},
		{"generation_changed", "UPDATE devices SET current_generation_id=NULL WHERE id=$1", "device_revoked", connect.CodePermissionDenied},
		{"certificate_revoked", "UPDATE device_certificates SET status='revoked', revoked_at=clock_timestamp() WHERE id=$3", "certificate_rejected", connect.CodePermissionDenied},
		{"certificate_expired", "UPDATE device_certificates SET not_before=clock_timestamp()-interval '2 days', not_after=clock_timestamp()-interval '1 day' WHERE id=$3", "certificate_rejected", connect.CodePermissionDenied},
		{"certificate_not_yet_valid", "UPDATE device_certificates SET not_before=clock_timestamp()+interval '1 hour' WHERE id=$3", "certificate_rejected", connect.CodePermissionDenied},
		{"overlap_expired", "UPDATE device_certificates SET status='overlapping', overlap_until=clock_timestamp()-interval '1 day' WHERE id=$3", "certificate_rejected", connect.CodePermissionDenied},
	} {
		t.Run(change.name, func(t *testing.T) {
			f := newEnrolled(t, 0)
			// Cast all bindings in the same statement so pgx can encode unused
			// numbered parameters consistently across these mutation fixtures.
			statement := "WITH binding AS (SELECT $1::uuid, $2::uuid, $3::uuid) " + change.statement
			if _, err := f.svc.Pool.Exec(f.ctx, statement, f.principal.DeviceID, f.principal.GenerationID, f.principal.CertificateID); err != nil {
				t.Fatal(err)
			}
			for _, method := range []string{"trust", "work"} {
				dispatchError(t, pollingCall(f.svc, f.deviceCtx(), method), change.code, change.reason)
			}
		})
	}
	t.Run("fingerprint", func(t *testing.T) {
		f := newEnrolled(t, 0)
		f.principal.Fingerprint = make([]byte, sha256.Size)
		for _, method := range []string{"trust", "work"} {
			dispatchError(t, pollingCall(f.svc, f.deviceCtx(), method), connect.CodePermissionDenied, "certificate_rejected")
		}
	})
	t.Run("device_revoked", func(t *testing.T) {
		f := newEnrolled(t, 0)
		if _, err := f.svc.RevokeDevice(f.ownerCtx, approvedRevocation(t, f.svc, f.ownerCtx, &adminv1.RevokeDeviceRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Reason: "retire polling authority"})); err != nil {
			t.Fatal(err)
		}
		for _, method := range []string{"trust", "work"} {
			dispatchError(t, pollingCall(f.svc, f.deviceCtx(), method), connect.CodePermissionDenied, "device_revoked")
		}
	})
}

func TestPollingCoherentAuthoritySnapshotWithoutWriteXID(t *testing.T) {
	parallelDeviceIntegration(t)
	for _, method := range []string{"trust", "work"} {
		t.Run(method, func(t *testing.T) {
			f := newEnrolled(t, 0)
			lock, err := f.conn.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = lock.Rollback(f.ctx) }()
			// The first authority read fixes the snapshot; pause the second
			// query using PostgreSQL itself, not a production hook or sleep.
			if _, err := lock.Exec(f.ctx, "LOCK TABLE enrollment_generations IN ACCESS EXCLUSIVE MODE"); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(f.deviceCtx(), 10*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- pollingCall(f.svc, ctx, method) }()
			waitPollingQuery(t, ctx, f.svc.Pool, f.conn.PgConn().PID(), "GetGenerationAuthority", true, result)
			if _, err := lock.Exec(ctx, "UPDATE devices SET state='recovery_hold' WHERE id=$1", f.principal.DeviceID); err != nil {
				t.Fatal(err)
			}
			if _, err := lock.Exec(ctx, "UPDATE enrollment_generations SET state='recovery_hold', session_epoch=2 WHERE id=$1", f.principal.GenerationID); err != nil {
				t.Fatal(err)
			}
			if _, err := lock.Exec(ctx, "UPDATE device_certificates SET status='revoked', revoked_at=clock_timestamp() WHERE id=$1", f.principal.CertificateID); err != nil {
				t.Fatal(err)
			}
			if err := lock.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if err != nil {
					t.Fatalf("poll mixed pre-transition device with post-transition authority: %v", err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			// The old snapshot may complete, but it is never cached as authority
			// for another request after the revocation/clone fence commits.
			dispatchError(t, pollingCall(f.svc, f.deviceCtx(), method), connect.CodePermissionDenied, "recovery_hold")
		})
	}
}

func TestPollingConcurrentAssignmentAndWriteRecheck(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDispatchFixture(t)
	lock, err := f.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Rollback(t.Context()) }()
	if _, err := lock.Exec(t.Context(), "LOCK TABLE device_action_restrictions IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(f.deviceCtx, 15*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- pollingCall(f.service, ctx, "work") }()
	waitPollingQuery(t, ctx, f.pool, lock.Conn().PgConn().PID(), "GetDeviceActionRestriction", true, result)
	f.assign(t, nil)
	if err := lock.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("concurrent assignment invalidated an already-empty snapshot: %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	work := f.work(t)
	if work == nil {
		t.Fatal("next poll lost the concurrent assignment")
	}
	_, grant := f.start(t, work)
	// An open granted action still needs nonce/grant replay even if no head is
	// visible; the probe must check actions device-wide, not only head presence.
	if _, err := f.pool.Exec(t.Context(), "DELETE FROM resource_assignment_heads WHERE generation_id=$1", f.principal.GenerationID); err != nil {
		t.Fatal(err)
	}
	replay := f.work(t)
	if replay.GetActionId() != work.GetActionId() || !bytes.Equal(replay.GetStartGrantEnvelope(), grant) || bytes.Equal(replay.GetResultNonce(), work.GetResultNonce()) {
		t.Fatal("headless open action was treated as an empty read-only poll")
	}

	// A positive probe is not authorization to write. Fence the device while
	// the slow path waits for the mutation lock, then require a fresh rejection.
	ctx, cancel = context.WithTimeout(f.deviceCtx, 10*time.Second)
	defer cancel()
	lock, err = f.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Rollback(t.Context()) }()
	if _, err := devicedb.New(lock).GetDeviceForUpdate(t.Context(), f.principal.DeviceID); err != nil {
		t.Fatal(err)
	}
	go func() {
		_, err := f.service.GetResourceWork(ctx, connect.NewRequest(&devicev1.GetResourceWorkRequest{SessionEpoch: 1}))
		result <- err
	}()
	waitPollingQuery(t, ctx, f.pool, lock.Conn().PgConn().PID(), "GetDeviceForUpdate", false, result)
	if _, err := lock.Exec(ctx, "UPDATE enrollment_generations SET session_epoch=2 WHERE id=$1", f.principal.GenerationID); err != nil {
		t.Fatal(err)
	}
	if err := lock.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		dispatchError(t, err, connect.CodeFailedPrecondition, "session_fenced")
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var nonce []byte
	if err := f.pool.QueryRow(t.Context(), "SELECT result_nonce FROM resource_actions WHERE id=$1", replay.GetActionId()).Scan(&nonce); err != nil || !bytes.Equal(nonce, replay.GetResultNonce()) {
		t.Fatalf("fenced poll mutated the open action: %v", err)
	}
}

func pollingCall(s *Service, ctx context.Context, method string) error {
	if method == "trust" {
		_, err := s.GetExecutionTrust(ctx, connect.NewRequest(&devicev1.GetExecutionTrustRequest{SessionEpoch: 1, RootVersion: 1, RootSha256: make([]byte, sha256.Size)}))
		return err
	}
	response, err := s.GetResourceWork(ctx, connect.NewRequest(&devicev1.GetResourceWorkRequest{SessionEpoch: 1}))
	if err == nil && response.Msg.GetWork() != nil {
		return errors.New("expected an empty poll")
	}
	return err
}

func waitPollingQuery(t *testing.T, ctx context.Context, pool *pgxpool.Pool, blocker uint32, query string, readOnly bool, result <-chan error) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting, noWriteXID bool
		err := pool.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_stat_activity WHERE $1::integer = ANY(pg_blocking_pids(pid)) AND query LIKE $2
		), NOT EXISTS (
			SELECT 1 FROM pg_stat_activity WHERE $1::integer = ANY(pg_blocking_pids(pid)) AND query LIKE $2 AND backend_xid IS NOT NULL
		)`, int32(blocker), "-- name: "+query+" %").Scan(&waiting, &noWriteXID)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			if readOnly && !noWriteXID {
				t.Fatal("read-only poll assigned a write XID before returning work")
			}
			return
		}
		select {
		case err := <-result:
			t.Fatalf("poll returned before the blocked query: %v", err)
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}
