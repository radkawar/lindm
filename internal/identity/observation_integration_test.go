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
	"lindm/internal/testdb"
)

func TestDelayedLoginDoesNotAuthorizeAfterDisable(t *testing.T) {
	svc, ctx, conn := integrationService(t)
	subject := uuid.New()
	row := insertObservedPrincipal(t, ctx, svc, subject)
	base := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	if err := svc.withTx(ctx, func(q *identitydb.Queries) error {
		_, err := svc.writeObservation(ctx, q, row.ID, directoryObservation{
			Found: true, UserID: subject.String(), Enabled: false, Direct: true, AcquiredAt: base.Add(time.Second),
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	_, denied, err := svc.completeLogin(ctx, subject.String(), directoryObservation{
		Found: true, UserID: subject.String(), Enabled: true, Direct: true, Groups: []string{"/admins"}, DisplayName: "stale", AcquiredAt: base,
	})
	if !errors.Is(err, errStaleObservation) || denied {
		t.Fatalf("stale login err=%v denied=%v", err, denied)
	}
	var enabled, deactivated bool
	if err := conn.QueryRow(ctx, `SELECT directory_enabled, deactivated_at IS NOT NULL FROM principals WHERE id = $1`, row.ID).Scan(&enabled, &deactivated); err != nil {
		t.Fatal(err)
	}
	if enabled || !deactivated {
		t.Fatalf("disabled state resurrected enabled=%v deactivated=%v", enabled, deactivated)
	}
	var sessions int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE principal_id = $1 AND revoked_at IS NULL`, row.ID).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 {
		t.Fatalf("stale login created %d authorized sessions", sessions)
	}
}

func TestAuthorizationChangesAreAuditedAndRolledBack(t *testing.T) {
	svc, ctx, conn := integrationService(t)
	subject := uuid.New()
	row := insertObservedPrincipal(t, ctx, svc, subject)
	base := time.Date(2026, 10, 8, 13, 0, 0, 0, time.UTC)
	apply := func(at time.Time, groups []string) error {
		return svc.withTx(ctx, func(q *identitydb.Queries) error {
			_, err := svc.writeObservation(ctx, q, row.ID, directoryObservation{
				Found: true, UserID: subject.String(), Enabled: true, Direct: true, Groups: groups, AcquiredAt: at,
			})
			return err
		})
	}
	if err := apply(base, []string{"/admins"}); err != nil {
		t.Fatal(err)
	}
	if err := apply(base.Add(time.Second), nil); err != nil {
		t.Fatal(err)
	}
	if err := apply(base.Add(2*time.Second), nil); err != nil {
		t.Fatal(err)
	}
	assertAuditCount(t, ctx, conn, row.ID, reasonAdminGranted, 1)
	assertAuditCount(t, ctx, conn, row.ID, reasonAdminRemoved, 1)
	snap, err := svc.loadSnapshot(ctx, row.ID)
	if err != nil {
		t.Fatal(err)
	}
	if role := effectiveRole(snap.PinnedRole, snap.Groups, svc.policy); role != "" || Authorize(Principal{Role: role}, PermissionManageEnrollment) {
		t.Fatalf("removed admin still authorized as %q", role)
	}
	if _, err := conn.Exec(ctx, `
		CREATE OR REPLACE FUNCTION lindm_test_fail_authz_audit() RETURNS trigger AS $$
		BEGIN
			IF NEW.action = 'identity.authorization_changed' THEN
				RAISE EXCEPTION 'forced authorization audit failure';
			END IF;
			RETURN NEW;
		END $$ LANGUAGE plpgsql`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `CREATE TRIGGER lindm_test_fail_authz_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE PROCEDURE lindm_test_fail_authz_audit()`); err != nil {
		t.Fatal(err)
	}
	before := auditCount(t, ctx, conn, row.ID, reasonAdminGranted)
	if err := apply(base.Add(3*time.Second), []string{"/admins"}); err == nil {
		t.Fatal("authorization audit failure was committed")
	}
	if got := auditCount(t, ctx, conn, row.ID, reasonAdminGranted); got != before {
		t.Fatalf("failed audit insert committed, count %d want %d", got, before)
	}
	var groups int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM principal_groups WHERE principal_id = $1`, row.ID).Scan(&groups); err != nil {
		t.Fatal(err)
	}
	if groups != 0 {
		t.Fatalf("rolled-back grant left %d groups", groups)
	}
}

func TestBootstrapSameOwnerIsIdempotent(t *testing.T) {
	svc, ctx, conn := integrationService(t)
	subject := uuid.New()
	row := insertObservedPrincipal(t, ctx, svc, subject)
	if _, err := conn.Exec(ctx, `UPDATE principals SET pinned_role = 'owner' WHERE id = $1`, row.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `UPDATE deployment_identity SET owner_principal_id = $1, initialized_at = now() WHERE id`, row.ID); err != nil {
		t.Fatal(err)
	}
	issuer, gotSubject, ok, err := svc.InitializedOwner(ctx)
	if err != nil || !ok || issuer != svc.issuer || gotSubject != subject.String() {
		t.Fatalf("initialized owner issuer=%s subject=%s ok=%v err=%v", issuer, gotSubject, ok, err)
	}
	if err := svc.BootstrapOwner(ctx, svc.issuer, subject.String()); err != nil {
		t.Fatalf("same owner bootstrap: %v", err)
	}
	if err := svc.BootstrapOwner(ctx, svc.issuer, uuid.NewString()); !errors.Is(err, ErrOwnerInitialized) {
		t.Fatalf("different owner err=%v", err)
	}
	_, gotSubject, ok, err = svc.InitializedOwner(ctx)
	if err != nil || !ok || gotSubject != subject.String() {
		t.Fatalf("owner changed to %s ok=%v err=%v", gotSubject, ok, err)
	}
}

func integrationService(t *testing.T) (*Service, context.Context, *pgx.Conn) {
	t.Helper()
	ctx := t.Context()
	pool, conn := testdb.Open(t)
	svc := &Service{
		pool:   pool,
		issuer: "https://idp.example/realms/lindm",
		policy: mappedPolicy(t, "/admins"),
		now:    time.Now,
	}
	if err := svc.activatePolicy(ctx); err != nil {
		t.Fatal(err)
	}
	return svc, ctx, conn
}

func insertObservedPrincipal(t *testing.T, ctx context.Context, svc *Service, subject uuid.UUID) identitydb.Principal {
	t.Helper()
	row, err := identitydb.New(svc.pool).UpsertPrincipal(ctx, identitydb.UpsertPrincipalParams{
		ID:      uuid.New(),
		Issuer:  svc.issuer,
		Subject: subject.String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func assertAuditCount(t *testing.T, ctx context.Context, conn *pgx.Conn, principal uuid.UUID, reason string, want int) {
	t.Helper()
	if got := auditCount(t, ctx, conn, principal, reason); got != want {
		t.Fatalf("audit %q count=%d want=%d", reason, got, want)
	}
}

func auditCount(t *testing.T, ctx context.Context, conn *pgx.Conn, principal uuid.UUID, reason string) int {
	t.Helper()
	var n int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE resource_id = $1 AND reason = '' AND details->>'context' = $2`, principalResource(principal), reason).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
