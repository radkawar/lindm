//go:build integration

package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"lindm/internal/identity/identitydb"
)

func TestStaleDisableDoesNotRevokeNewerSession(t *testing.T) {
	svc, ctx, conn := integrationService(t)
	subject := uuid.New()
	row := insertObservedPrincipal(t, ctx, svc, subject)
	at := time.Now().UTC()
	oldCookie, denied, err := svc.completeLogin(ctx, subject.String(), directoryObs(subject, at, true))
	if err != nil || denied || oldCookie == "" {
		t.Fatalf("login err=%v denied=%v", err, denied)
	}
	if err := svc.withTx(ctx, func(q *identitydb.Queries) error {
		_, err := svc.writeObservation(ctx, q, row.ID, directoryObs(subject, at.Add(time.Second), false))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !sessionRevoked(t, ctx, conn, oldCookie) {
		t.Fatal("disable observation left the old session active")
	}
	freshCookie, denied, err := svc.completeLogin(ctx, subject.String(), directoryObs(subject, at.Add(2*time.Second), true))
	if err != nil || denied || freshCookie == "" {
		t.Fatalf("re-enable login err=%v denied=%v", err, denied)
	}
	var enabled, deactivated bool
	if err := conn.QueryRow(ctx, `SELECT directory_enabled, deactivated_at IS NOT NULL FROM principals WHERE id = $1`, row.ID).Scan(&enabled, &deactivated); err != nil {
		t.Fatal(err)
	}
	if !enabled || deactivated {
		t.Fatalf("re-enable did not commit enabled=%v deactivated=%v", enabled, deactivated)
	}
	if live := liveSessions(t, ctx, conn, row.ID); live != 1 {
		t.Fatalf("live sessions after re-enable = %d", live)
	}
	disables := auditCount(t, ctx, conn, row.ID, reasonDisabled)

	// resolve still holds the pre-re-enable snapshot and calls revokePrincipal.
	if err := svc.revokePrincipal(ctx, row.ID); err != nil {
		t.Fatal(err)
	}
	if live := liveSessions(t, ctx, conn, row.ID); live != 1 {
		t.Fatalf("stale disable revocation left %d live sessions", live)
	}
	if sessionRevoked(t, ctx, conn, freshCookie) {
		t.Fatal("stale disable revocation revoked the newer session")
	}
	if got := auditCount(t, ctx, conn, row.ID, reasonDisabled); got != disables {
		t.Fatalf("false disable audits=%d want %d", got, disables)
	}
	if !sessionRevoked(t, ctx, conn, oldCookie) {
		t.Fatal("old session was resurrected")
	}

	principal, dec, err := svc.resolve(ctx, freshCookie)
	if err != nil || dec.Kind != accessOK || principal.ID != row.ID {
		t.Fatalf("newer session rejected: principal=%v kind=%v err=%v", principal.ID, dec.Kind, err)
	}
	if _, dec, err := svc.resolve(ctx, oldCookie); err != nil || dec.Kind != accessUnauthenticated {
		t.Fatalf("revoked session kind=%v err=%v", dec.Kind, err)
	}
}

func TestResolveRevokesSessionWhilePrincipalStaysDisabled(t *testing.T) {
	svc, ctx, conn := integrationService(t)
	subject := uuid.New()
	row := insertObservedPrincipal(t, ctx, svc, subject)
	if err := svc.withTx(ctx, func(q *identitydb.Queries) error {
		_, err := svc.writeObservation(ctx, q, row.ID, directoryObs(subject, time.Now().UTC(), false))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	cookie := insertLiveSession(t, ctx, svc, row.ID)
	before := auditCount(t, ctx, conn, row.ID, reasonDisabled)
	_, dec, err := svc.resolve(ctx, cookie)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Kind != accessUnauthenticated {
		t.Fatalf("disabled session kind=%v", dec.Kind)
	}
	if !sessionRevoked(t, ctx, conn, cookie) {
		t.Fatal("resolve left a live session for a disabled principal")
	}
	if got := auditCount(t, ctx, conn, row.ID, reasonDisabled); got != before+1 {
		t.Fatalf("disable audits=%d want %d", got, before+1)
	}
}

func TestLogoutAndDirectoryDisableDoNotDeadlock(t *testing.T) {
	svc, parent, conn := integrationService(t)
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	subject := uuid.New()
	row := insertObservedPrincipal(t, ctx, svc, subject)
	at := time.Now().UTC()
	cookie, denied, err := svc.completeLogin(ctx, subject.String(), directoryObs(subject, at, true))
	if err != nil || denied || cookie == "" {
		t.Fatalf("login err=%v denied=%v", err, denied)
	}
	observation, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := observation.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error(err)
		}
	})
	q := identitydb.New(observation)
	if _, err := q.GetPrincipalForUpdate(ctx, row.ID); err != nil {
		t.Fatal(err)
	}
	logoutResult := make(chan error, 1)
	go func() { logoutResult <- svc.logout(ctx, cookie, row.ID) }()

	// Synchronize on PostgreSQL's actual wait graph, not a sleep or an assertion
	// about a particular lock implementation. The old logout held the session
	// while waiting here, causing the following disable to deadlock.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		err := svc.pool.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_stat_activity
			WHERE $1::integer = ANY(pg_blocking_pids(pid))
		)`, int32(conn.PgConn().PID())).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-logoutResult:
			t.Fatalf("logout completed before the directory transaction released its principal: %v", err)
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if _, err := svc.writeObservation(ctx, q, row.ID, directoryObs(subject, at.Add(time.Second), false)); err != nil {
		t.Fatalf("concurrent directory disable: %v", err)
	}
	if err := observation.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-logoutResult:
		// The directory transaction may already have revoked this exact session.
		if err != nil && !errors.Is(err, errNotFound) {
			t.Fatalf("concurrent logout: %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if !sessionRevoked(t, ctx, conn, cookie) {
		t.Fatal("concurrent disable and logout left the session active")
	}
	if got := auditCount(t, ctx, conn, row.ID, reasonDisabled); got != 1 {
		t.Fatalf("committed disable audits=%d", got)
	}
}

func directoryObs(subject uuid.UUID, at time.Time, enabled bool) directoryObservation {
	return directoryObservation{
		Found: true, UserID: subject.String(), Enabled: enabled, Direct: true,
		Groups: []string{"/admins"}, DisplayName: "ada", AcquiredAt: at,
	}
}

func insertLiveSession(t *testing.T, ctx context.Context, svc *Service, principal uuid.UUID) string {
	t.Helper()
	cookie, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := identitydb.New(svc.pool).InsertSession(ctx, identitydb.InsertSessionParams{
		TokenHash:   sessionHash(cookie),
		PrincipalID: principal,
	}); err != nil {
		t.Fatal(err)
	}
	return cookie
}

func sessionRevoked(t *testing.T, ctx context.Context, conn *pgx.Conn, cookie string) bool {
	t.Helper()
	var revoked bool
	if err := conn.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM sessions WHERE token_hash = $1`, sessionHash(cookie)).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	return revoked
}

func liveSessions(t *testing.T, ctx context.Context, conn *pgx.Conn, principal uuid.UUID) int {
	t.Helper()
	var n int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE principal_id = $1 AND revoked_at IS NULL`, principal).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
