//go:build integration

package identity

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"lindm/internal/identity/identitydb"
)

func TestAuthorizationVersionTracksEffectiveRole(t *testing.T) {
	svc, ctx, conn := integrationService(t)
	subject := uuid.New()
	row := insertObservedPrincipal(t, ctx, svc, subject)
	base := authorizationDatabaseTime(t, ctx, svc).Add(-time.Minute)
	before := readAuthorizationState(t, ctx, conn, row.ID)
	if before.Version <= 0 || before.Role != "" {
		t.Fatalf("unobserved principal authorization = %+v", before)
	}
	steps := []struct {
		name    string
		enabled bool
		direct  bool
		found   bool
		groups  []string
		role    string
	}{
		{"grant", true, true, true, []string{"/admins"}, RoleAdmin},
		{"display and irrelevant membership", true, true, true, []string{"/unrelated", "/admins"}, RoleAdmin},
		{"remove irrelevant membership", true, true, true, []string{"/admins"}, RoleAdmin},
		{"remove administrator", true, true, true, []string{"/unrelated"}, ""},
		{"refresh without privilege", true, true, true, nil, ""},
		{"restore administrator", true, true, true, []string{"/admins"}, RoleAdmin},
		{"disable", false, true, true, []string{"/admins"}, ""},
		{"repeat disable", false, true, true, []string{"/admins"}, ""},
		{"re-enable", true, true, true, []string{"/admins"}, RoleAdmin},
		{"unqualified lineage", true, false, true, []string{"/admins"}, ""},
		{"restore direct lineage", true, true, true, []string{"/admins"}, RoleAdmin},
		{"directory absence", false, false, false, nil, ""},
		{"return from absence", true, true, true, []string{"/admins"}, RoleAdmin},
	}
	for i, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			obs := directoryObservation{
				Found: step.found, UserID: subject, Enabled: step.enabled, Direct: step.direct,
				Groups: step.groups, DisplayName: step.name, AcquiredAt: base.Add(time.Duration(i) * time.Second),
			}
			if err := applyAuthorizationObservation(ctx, svc, row.ID, obs); err != nil {
				t.Fatal(err)
			}
			want := before
			want.Role = step.role
			if before.Role != step.role {
				want.Version++
				want.Changes++
			}
			after := readAuthorizationState(t, ctx, conn, row.ID)
			if after != want {
				t.Fatalf("authorization transition %+v -> %+v, want %+v", before, after, want)
			}
			snap, err := svc.loadSnapshot(ctx, row.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !snap.ObservedAt.Equal(obs.AcquiredAt) || snap.AuthorizationVersion != after.Version || snap.AuthorizationRole != after.Role {
				t.Fatalf("observation and authorization disagree: snapshot=%+v state=%+v", snap, after)
			}
			if step.found && snap.DisplayName != step.name {
				t.Fatalf("display-only update lost: got %q want %q", snap.DisplayName, step.name)
			}
			if step.enabled && step.direct && step.found {
				if len(snap.Groups) != len(step.groups) {
					t.Fatalf("membership update lost: got %v want %v", snap.Groups, step.groups)
				}
				for _, group := range step.groups {
					found := false
					for _, got := range snap.Groups {
						found = found || got == group
					}
					if !found {
						t.Fatalf("membership update omitted %q: %v", group, snap.Groups)
					}
				}
			}
			before = after
		})
	}
}

func TestAuthorizationStaleObservationAndRestoredRole(t *testing.T) {
	svc, ctx, conn := integrationService(t)
	createAuthorizationEffects(t, ctx, conn)
	subject, grant := observedAuthorization(t, ctx, svc)
	before := readAuthorizationState(t, ctx, conn, grant.actorID)
	assertAuthorizationEffect(t, ctx, conn, svc, grant, nil)
	refreshed := directoryObs(subject, authorizationDatabaseTime(t, ctx, svc), true)
	refreshed.DisplayName = "updated display"
	refreshed.Groups = []string{"/admins", "/irrelevant"}
	if err := applyAuthorizationObservation(ctx, svc, grant.actorID, refreshed); err != nil {
		t.Fatal(err)
	}
	if got := readAuthorizationState(t, ctx, conn, grant.actorID); got != before {
		t.Fatalf("nonprivileged observation changed authorization: before=%+v after=%+v", before, got)
	}
	assertAuthorizationEffect(t, ctx, conn, svc, grant, nil)

	disabled := directoryObs(subject, authorizationDatabaseTime(t, ctx, svc), false)
	if err := applyAuthorizationObservation(ctx, svc, grant.actorID, disabled); err != nil {
		t.Fatal(err)
	}
	revoked := readAuthorizationState(t, ctx, conn, grant.actorID)
	if revoked.Version != before.Version+1 || revoked.Role != "" || revoked.Changes != before.Changes+1 {
		t.Fatalf("disable did not revoke durable authorization: before=%+v after=%+v", before, revoked)
	}
	for _, at := range []time.Time{grant.observedAt, disabled.AcquiredAt} {
		err := applyAuthorizationObservation(ctx, svc, grant.actorID, directoryObs(subject, at, true))
		if !errors.Is(err, errStaleObservation) {
			t.Fatalf("older/equal observation error = %v", err)
		}
		if got := readAuthorizationState(t, ctx, conn, grant.actorID); got != revoked {
			t.Fatalf("stale grant changed authorization: got=%+v want=%+v", got, revoked)
		}
	}
	disabledSnapshot, err := svc.loadSnapshot(ctx, grant.actorID)
	if err != nil {
		t.Fatal(err)
	}
	if disabledSnapshot.Enabled || !disabledSnapshot.Deactivated || !disabledSnapshot.ObservedAt.Equal(disabled.AcquiredAt) {
		t.Fatalf("stale grant partially changed disabled directory state: %+v", disabledSnapshot)
	}
	assertAuthorizationEffect(t, ctx, conn, svc, grant, ErrAuthorizationChanged)

	restoredAt := authorizationDatabaseTime(t, ctx, svc)
	if err := applyAuthorizationObservation(ctx, svc, grant.actorID, directoryObs(subject, restoredAt, true)); err != nil {
		t.Fatal(err)
	}
	restored := readAuthorizationState(t, ctx, conn, grant.actorID)
	if restored.Version != before.Version+2 || restored.Role != before.Role || restored.Changes != before.Changes+2 {
		t.Fatalf("role restoration reused revoked authorization: before=%+v after=%+v", before, restored)
	}
	if err := applyAuthorizationObservation(ctx, svc, grant.actorID, disabled); !errors.Is(err, errStaleObservation) {
		t.Fatalf("stale disable error = %v", err)
	}
	if got := readAuthorizationState(t, ctx, conn, grant.actorID); got != restored {
		t.Fatalf("stale disable changed restored authorization: %+v", got)
	}
	assertAuthorizationEffect(t, ctx, conn, svc, grant, ErrAuthorizationChanged)
	fresh := authorizationFromSnapshot(t, ctx, svc, grant.actorID)
	assertAuthorizationEffect(t, ctx, conn, svc, fresh, nil)
}

func TestAuthorizationAuditFailureRollsBackAllState(t *testing.T) {
	for _, action := range []string{auditAuthorizationChanged, auditDisabled} {
		t.Run(action, func(t *testing.T) {
			svc, ctx, conn := integrationService(t)
			createAuthorizationEffects(t, ctx, conn)
			subject, grant := observedAuthorization(t, ctx, svc)
			cookie := insertLiveSession(t, ctx, svc, grant.actorID)
			before := readAuthorizationState(t, ctx, conn, grant.actorID)
			beforeSnapshot, err := svc.loadSnapshot(ctx, grant.actorID)
			if err != nil {
				t.Fatal(err)
			}
			beforeAudits := authorizationPrincipalAuditCount(t, ctx, conn, grant.actorID)
			if _, err := conn.Exec(ctx, `
				CREATE FUNCTION lindm_test_fail_fresh_authorization_audit() RETURNS trigger AS $$
				BEGIN
					IF NEW.action = TG_ARGV[0] THEN
						RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'forced audit rollback';
					END IF;
					RETURN NEW;
				END $$ LANGUAGE plpgsql`); err != nil {
				t.Fatal(err)
			}
			// Both action values are constants above, not directory or user input.
			if _, err := conn.Exec(ctx, `CREATE TRIGGER lindm_test_fail_fresh_authorization_audit
				BEFORE INSERT ON audit_events FOR EACH ROW
				EXECUTE FUNCTION lindm_test_fail_fresh_authorization_audit('`+action+`')`); err != nil {
				t.Fatal(err)
			}
			obs := directoryObs(subject, authorizationDatabaseTime(t, ctx, svc), false)
			obs.DisplayName = "must roll back with revocation"
			if err := applyAuthorizationObservation(ctx, svc, grant.actorID, obs); !errors.Is(err, errStore) {
				t.Fatalf("audit failure error = %v, want store sentinel", err)
			}
			afterSnapshot, err := svc.loadSnapshot(ctx, grant.actorID)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(afterSnapshot, beforeSnapshot) {
				t.Fatalf("audit failure partially committed directory state: before=%+v after=%+v", beforeSnapshot, afterSnapshot)
			}
			if got := readAuthorizationState(t, ctx, conn, grant.actorID); got != before {
				t.Fatalf("audit failure partially committed authorization: before=%+v after=%+v", before, got)
			}
			if got := authorizationPrincipalAuditCount(t, ctx, conn, grant.actorID); got != beforeAudits {
				t.Fatalf("audit failure committed %d audit events, want %d", got, beforeAudits)
			}
			if sessionRevoked(t, ctx, conn, cookie) {
				t.Fatal("audit failure committed session revocation")
			}
			assertAuthorizationEffect(t, ctx, conn, svc, grant, nil)
			if _, err := conn.Exec(ctx, `DROP TRIGGER lindm_test_fail_fresh_authorization_audit ON audit_events`); err != nil {
				t.Fatal(err)
			}
			// The identical observation must remain admissible after the rollback.
			if err := applyAuthorizationObservation(ctx, svc, grant.actorID, obs); err != nil {
				t.Fatal(err)
			}
			after := readAuthorizationState(t, ctx, conn, grant.actorID)
			if after.Version != before.Version+1 || after.Role != "" || after.Changes != before.Changes+1 {
				t.Fatalf("successful revocation did not commit atomically: before=%+v after=%+v", before, after)
			}
			if !sessionRevoked(t, ctx, conn, cookie) {
				t.Fatal("committed disable left its session active")
			}
			assertAuthorizationEffect(t, ctx, conn, svc, grant, ErrAuthorizationChanged)
		})
	}
}

func TestAuthorizationOwnerPinInvalidatesAdminGrant(t *testing.T) {
	svc, ctx, conn := integrationService(t)
	createAuthorizationEffects(t, ctx, conn)
	subject, admin := observedAuthorization(t, ctx, svc)
	before := readAuthorizationState(t, ctx, conn, admin.actorID)
	pin := func(q *identitydb.Queries) error {
		if _, err := q.GetPrincipalForUpdate(ctx, admin.actorID); err != nil {
			return err
		}
		n, err := q.PinOwnerRole(ctx, admin.actorID)
		if err != nil {
			return err
		}
		if n != 1 {
			t.Fatalf("owner pin affected %d principals", n)
		}
		return svc.insertAudit(ctx, q, &admin.actorID, auditOwnerBootstrapped, principalResource(admin.actorID), reasonInitialOwner)
	}
	// Exercise the production pin query without a synthetic HTTP bootstrap.
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cleanupAuthorizationTx(t, tx)
	if err := pin(identitydb.New(tx)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if got := readAuthorizationState(t, ctx, conn, admin.actorID); got != before {
		t.Fatalf("rolled-back owner pin changed authorization: %+v", got)
	}
	assertAuthorizationEffect(t, ctx, conn, svc, admin, nil)
	if err := svc.withTx(ctx, pin); err != nil {
		t.Fatal(err)
	}
	pinned := readAuthorizationState(t, ctx, conn, admin.actorID)
	if pinned.Version != before.Version+1 || pinned.Role != RoleOwner {
		t.Fatalf("owner pin did not advance effective authorization: before=%+v after=%+v", before, pinned)
	}
	assertAuditCount(t, ctx, conn, admin.actorID, reasonInitialOwner, 1)
	assertAuthorizationEffect(t, ctx, conn, svc, admin, ErrAuthorizationChanged)
	owner := authorizationFromSnapshot(t, ctx, svc, admin.actorID)
	assertAuthorizationEffect(t, ctx, conn, svc, owner, nil)
	obs := directoryObs(subject, authorizationDatabaseTime(t, ctx, svc), true)
	obs.Groups = nil
	if err := applyAuthorizationObservation(ctx, svc, admin.actorID, obs); err != nil {
		t.Fatal(err)
	}
	if got := readAuthorizationState(t, ctx, conn, admin.actorID); got != pinned {
		t.Fatalf("owner group removal consumed authorization version: before=%+v after=%+v", pinned, got)
	}
	assertAuthorizationEffect(t, ctx, conn, svc, owner, nil)
	obs.AcquiredAt = authorizationDatabaseTime(t, ctx, svc)
	obs.Enabled = false
	if err := applyAuthorizationObservation(ctx, svc, admin.actorID, obs); err != nil {
		t.Fatal(err)
	}
	disabled := readAuthorizationState(t, ctx, conn, admin.actorID)
	if disabled.Version != pinned.Version+1 || disabled.Role != "" {
		t.Fatalf("owner pin bypassed disable: before=%+v after=%+v", pinned, disabled)
	}
	assertAuthorizationEffect(t, ctx, conn, svc, owner, ErrAuthorizationChanged)
	obs.AcquiredAt = authorizationDatabaseTime(t, ctx, svc)
	obs.Enabled = true
	if err := applyAuthorizationObservation(ctx, svc, admin.actorID, obs); err != nil {
		t.Fatal(err)
	}
	if got := readAuthorizationState(t, ctx, conn, admin.actorID); got.Version != pinned.Version+2 || got.Role != RoleOwner {
		t.Fatalf("owner re-enable reused authorization: %+v", got)
	}
	assertAuthorizationEffect(t, ctx, conn, svc, owner, ErrAuthorizationChanged)
	assertAuthorizationEffect(t, ctx, conn, svc, authorizationFromSnapshot(t, ctx, svc, admin.actorID), nil)
}

func TestLockAuthorizationFencesDurableMutation(t *testing.T) {
	svc, ctx, conn := integrationService(t)
	createAuthorizationEffects(t, ctx, conn)
	cases := []struct {
		name   string
		change func(*Authorization)
		sql    string
		want   error
	}{
		{name: "valid"},
		{name: "foreign issuing service", change: func(a *Authorization) {
			a.service = &Service{pool: svc.pool, issuer: svc.issuer, adminGroups: svc.adminGroups, now: time.Now}
		}, want: ErrAuthorizationDenied},
		{name: "unknown permission", change: func(a *Authorization) { a.permission = Permission("unknown.permission") }, want: ErrAuthorizationDenied},
		{name: "read approval cannot revoke a device", change: func(a *Authorization) { a.permission = PermissionReadFleet }, want: ErrAuthorizationDenied},
		{name: "expired", change: func(a *Authorization) {
			a.observedAt = a.observedAt.Add(-time.Minute)
			a.expiresAt = a.observedAt.Add(30 * time.Second)
		}, want: ErrAuthorizationExpired},
		{name: "expired monotonic deadline", change: func(a *Authorization) { a.monotonicDeadline = time.Now().Add(-time.Second) }, want: ErrAuthorizationExpired},
		{name: "future observation", change: func(a *Authorization) {
			a.observedAt = a.observedAt.Add(time.Minute)
			a.expiresAt = a.observedAt.Add(30 * time.Second)
		}, want: ErrAuthorizationExpired},
		{name: "deadline exceeds observation window", change: func(a *Authorization) { a.expiresAt = a.observedAt.Add(31 * time.Second) }, want: ErrAuthorizationExpired},
		{name: "current issuer", sql: `UPDATE principals SET issuer = 'https://other.example/realm' WHERE id = $1`, want: ErrAuthorizationDenied},
		{name: "current subject", sql: `UPDATE principals SET subject = 'different-subject' WHERE id = $1`, want: ErrAuthorizationDenied},
		{name: "current enabled flag", sql: `UPDATE principals SET directory_enabled = false WHERE id = $1`, want: ErrAuthorizationDenied},
		{name: "current tombstone", sql: `UPDATE principals SET deactivated_at = clock_timestamp(), deactivation_source = 'scim' WHERE id = $1`, want: ErrAuthorizationDenied},
		{name: "current lineage connector", sql: `UPDATE principal_lineage SET directory_connector = 'unqualified' WHERE principal_id = $1`, want: ErrAuthorizationDenied},
		{name: "current lineage subject", sql: `UPDATE principal_lineage SET upstream_subject = 'different-subject' WHERE principal_id = $1`, want: ErrAuthorizationDenied},
		{name: "current broker linkage", sql: `UPDATE principal_lineage SET broker_issuer = 'https://broker.example', broker_subject = 'broker-user' WHERE principal_id = $1`, want: ErrAuthorizationDenied},
		{name: "missing lineage", sql: `DELETE FROM principal_lineage WHERE principal_id = $1`, want: ErrAuthorizationDenied},
		{name: "unobserved lineage", sql: `UPDATE principal_lineage SET upstream_observed_at = NULL WHERE principal_id = $1`, want: ErrAuthorizationDenied},
		{name: "current observation ahead of database clock", sql: `UPDATE principal_lineage SET upstream_observed_at = clock_timestamp() + interval '30 seconds' WHERE principal_id = $1`, want: ErrAuthorizationExpired},
		{name: "observation older than approval", sql: `UPDATE principal_lineage SET upstream_observed_at = upstream_observed_at - interval '1 second' WHERE principal_id = $1`, want: ErrAuthorizationChanged},
		{name: "current authorization role", sql: `UPDATE principals SET authorization_role = 'owner' WHERE id = $1`, want: ErrAuthorizationChanged},
		{name: "current membership", sql: `DELETE FROM principal_groups WHERE principal_id = $1`, want: ErrAuthorizationDenied},
		{name: "version without role change", sql: `UPDATE principals SET authorization_version = authorization_version + 1 WHERE id = $1`, want: ErrAuthorizationChanged},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, grant := observedAuthorization(t, ctx, svc)
			expiry := grant.ExpiresAt()
			if grant.ActorID() != grant.actorID || grant.Version() != uint64(grant.version) || expiry.After(grant.expiresAt) || !expiry.After(grant.observedAt) {
				t.Fatal("authorization accessors lost the issued fence")
			}
			if tc.change != nil {
				tc.change(grant)
			}
			if tc.sql != "" {
				// Intentionally bypass version advancement to prove the final fence
				// checks current state independently of the durable counter.
				if _, err := conn.Exec(ctx, tc.sql, grant.actorID); err != nil {
					t.Fatal(err)
				}
			}
			assertAuthorizationEffect(t, ctx, conn, svc, grant, tc.want)
		})
	}
	t.Run("nil authorization", func(t *testing.T) {
		assertAuthorizationEffect(t, ctx, conn, svc, nil, ErrAuthorizationDenied)
	})
	t.Run("zero authorization", func(t *testing.T) {
		assertAuthorizationEffect(t, ctx, conn, svc, &Authorization{}, ErrAuthorizationDenied)
	})
	t.Run("unknown operation even with matching approval", func(t *testing.T) {
		_, grant := observedAuthorization(t, ctx, svc)
		grant.permission = Permission("unknown.permission")
		effect := uuid.New()
		err := commitAuthorizedEffect(ctx, svc, grant, effect, grant.permission)
		if !errors.Is(err, ErrAuthorizationDenied) {
			t.Fatalf("unknown operation error = %v, want denied authorization", err)
		}
		assertAuthorizationEffectCount(t, ctx, conn, effect, 0)
	})
	t.Run("database clock not process clock", func(t *testing.T) {
		_, grant := observedAuthorization(t, ctx, svc)
		svc.now = func() time.Time { return grant.expiresAt.Add(24 * time.Hour) }
		defer func() { svc.now = time.Now }()
		assertAuthorizationEffect(t, ctx, conn, svc, grant, nil)
	})
}

func TestAuthorizationExpiryClipsWallClockRollback(t *testing.T) {
	svc, ctx, _ := integrationService(t)
	_, grant := observedAuthorization(t, ctx, svc)
	// Shorten only the local monotonic budget; the durable observation and its
	// database deadline remain unchanged and valid.
	grant.monotonicDeadline = time.Now().Add(15 * time.Second)
	wall := grant.observedAt.Add(-time.Hour)
	svc.now = func() time.Time { return wall }
	expiry := grant.ExpiresAt()
	if !expiry.After(wall) || expiry.After(wall.Add(15*time.Second)) || expiry.After(grant.expiresAt) {
		t.Fatalf("wall rollback widened or discarded residual authority: wall=%v expiry=%v database deadline=%v", wall, expiry, grant.expiresAt)
	}
	// A further rollback must use the remaining budget again, not reuse the
	// prior absolute result as a fresh start-grant deadline.
	wall = wall.Add(-time.Hour)
	next := grant.ExpiresAt()
	if !next.After(wall) || next.After(wall.Add(15*time.Second)) || !next.Before(expiry) {
		t.Fatalf("repeated wall rollback widened residual authority: wall=%v first=%v next=%v", wall, expiry, next)
	}
	grant.monotonicDeadline = time.Now().Add(-time.Second)
	if expired := grant.ExpiresAt(); expired.After(wall) {
		t.Fatalf("expired monotonic authority advertised future expiry: wall=%v expiry=%v", wall, expired)
	}
}

func TestLockAuthorizationUsesClockAfterTransactionStart(t *testing.T) {
	svc, ctx, conn := integrationService(t)
	createAuthorizationEffects(t, ctx, conn)
	_, grant := observedAuthorization(t, ctx, svc)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cleanupAuthorizationTx(t, tx)
	// Set a deadline after this transaction began but before its final fence.
	// transaction_timestamp()/now() would incorrectly leave this grant valid.
	var began time.Time
	if err := tx.QueryRow(ctx, `SELECT transaction_timestamp(), clock_timestamp()`).Scan(&began, &grant.expiresAt); err != nil {
		t.Fatal(err)
	}
	if !grant.expiresAt.After(began) {
		t.Fatal("database clock did not advance after transaction start")
	}
	effect := uuid.New()
	lockErr := svc.LockAuthorization(ctx, tx, grant, PermissionRevokeDevice)
	if lockErr == nil {
		if _, err := tx.Exec(ctx, `INSERT INTO lindm_test_authorized_effects (id) VALUES ($1)`, effect); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	} else if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(lockErr, ErrAuthorizationExpired) {
		t.Fatalf("post-start deadline error = %v, want expired authorization", lockErr)
	}
	assertAuthorizationEffectCount(t, ctx, conn, effect, 0)
}

func TestLockAuthorizationHoldsPrincipalUntilCommit(t *testing.T) {
	svc, parent, conn := integrationService(t)
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	createAuthorizationEffects(t, ctx, conn)
	subject, grant := observedAuthorization(t, ctx, svc)
	before := readAuthorizationState(t, ctx, conn, grant.actorID)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cleanupAuthorizationTx(t, tx)
	if err := svc.LockAuthorization(ctx, tx, grant, PermissionRevokeDevice); err != nil {
		t.Fatal(err)
	}
	obs := directoryObs(subject, authorizationDatabaseTime(t, ctx, svc), false)
	revocation := make(chan error, 1)
	go func() { revocation <- applyAuthorizationObservation(ctx, svc, grant.actorID, obs) }()
	waitForAuthorizationBlock(t, ctx, svc, int32(conn.PgConn().PID()), revocation)
	var version int64
	var role string
	if err := svc.pool.QueryRow(ctx, `SELECT authorization_version, authorization_role FROM principals WHERE id = $1`, grant.actorID).Scan(&version, &role); err != nil {
		t.Fatal(err)
	}
	if version != before.Version || role != before.Role {
		t.Fatalf("revocation escaped held principal fence: version=%d role=%q", version, role)
	}
	effect := uuid.New()
	if _, err := tx.Exec(ctx, `INSERT INTO lindm_test_authorized_effects (id) VALUES ($1)`, effect); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-revocation:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	assertAuthorizationEffectCount(t, ctx, conn, effect, 1)
	after := readAuthorizationState(t, ctx, conn, grant.actorID)
	if after.Version != before.Version+1 || after.Role != "" || after.Changes != before.Changes+1 {
		t.Fatalf("waiting revocation did not commit after fence released: before=%+v after=%+v", before, after)
	}
	assertAuthorizationEffect(t, ctx, conn, svc, grant, ErrAuthorizationChanged)
}

func TestLockAuthorizationLocksPrincipalBeforeLineage(t *testing.T) {
	svc, parent, conn := integrationService(t)
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	createAuthorizationEffects(t, ctx, conn)
	subject, grant := observedAuthorization(t, ctx, svc)
	before := readAuthorizationState(t, ctx, conn, grant.actorID)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cleanupAuthorizationTx(t, tx)
	q := identitydb.New(tx)
	if _, err := q.GetPrincipalForUpdate(ctx, grant.actorID); err != nil {
		t.Fatal(err)
	}
	effect := uuid.New()
	approval := make(chan error, 1)
	go func() { approval <- commitAuthorizedEffect(ctx, svc, grant, effect, PermissionRevokeDevice) }()
	waitForAuthorizationBlock(t, ctx, svc, int32(conn.PgConn().PID()), approval)
	// If LockAuthorization took lineage/groups before waiting on the principal,
	// this real writer now deadlocks. Principal-first ordering lets it revoke.
	obs := directoryObs(subject, authorizationDatabaseTime(t, ctx, svc), false)
	if _, err := svc.writeObservation(ctx, q, grant.actorID, obs); err != nil {
		t.Fatalf("principal holder could not revoke while approval waited: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-approval:
		if !errors.Is(err, ErrAuthorizationChanged) {
			t.Fatalf("waiting approval error = %v, want changed authorization", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	assertAuthorizationEffectCount(t, ctx, conn, effect, 0)
	after := readAuthorizationState(t, ctx, conn, grant.actorID)
	if after.Version != before.Version+1 || after.Role != "" || after.Changes != before.Changes+1 {
		t.Fatalf("revocation did not persist ahead of waiting approval: before=%+v after=%+v", before, after)
	}
}

func TestAuthorizationVersionOverflowRollsBack(t *testing.T) {
	svc, ctx, conn := integrationService(t)
	subject, grant := observedAuthorization(t, ctx, svc)
	cookie := insertLiveSession(t, ctx, svc, grant.actorID)
	if _, err := conn.Exec(ctx, `UPDATE principals SET authorization_version = 9223372036854775807 WHERE id = $1`, grant.actorID); err != nil {
		t.Fatal(err)
	}
	before := readAuthorizationState(t, ctx, conn, grant.actorID)
	beforeSnapshot, err := svc.loadSnapshot(ctx, grant.actorID)
	if err != nil {
		t.Fatal(err)
	}
	obs := directoryObs(subject, authorizationDatabaseTime(t, ctx, svc), false)
	if err := applyAuthorizationObservation(ctx, svc, grant.actorID, obs); !errors.Is(err, errStore) {
		t.Fatalf("version overflow error = %v, want store sentinel", err)
	}
	if got := readAuthorizationState(t, ctx, conn, grant.actorID); got != before {
		t.Fatalf("overflow reset or partially advanced authorization: before=%+v after=%+v", before, got)
	}
	afterSnapshot, err := svc.loadSnapshot(ctx, grant.actorID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(afterSnapshot, beforeSnapshot) || sessionRevoked(t, ctx, conn, cookie) {
		t.Fatal("overflow partially committed directory or session state")
	}
}

type authorizationState struct {
	Version int64
	Role    string
	Changes int
}

func readAuthorizationState(t *testing.T, ctx context.Context, conn *pgx.Conn, actor uuid.UUID) authorizationState {
	t.Helper()
	var state authorizationState
	if err := conn.QueryRow(ctx, `SELECT authorization_version, authorization_role,
		(SELECT count(*) FROM audit_events WHERE resource_id = $2 AND action = $3)
		FROM principals WHERE id = $1`, actor, principalResource(actor), auditAuthorizationChanged).Scan(&state.Version, &state.Role, &state.Changes); err != nil {
		t.Fatal(err)
	}
	return state
}

func authorizationPrincipalAuditCount(t *testing.T, ctx context.Context, conn *pgx.Conn, actor uuid.UUID) int {
	t.Helper()
	var count int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE resource_id = $1`, principalResource(actor)).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func authorizationDatabaseTime(t *testing.T, ctx context.Context, svc *Service) time.Time {
	t.Helper()
	at, err := svc.databaseTime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

func applyAuthorizationObservation(ctx context.Context, svc *Service, actor uuid.UUID, obs directoryObservation) error {
	return svc.withTx(ctx, func(q *identitydb.Queries) error {
		_, err := svc.writeObservation(ctx, q, actor, obs)
		return err
	})
}

func observedAuthorization(t *testing.T, ctx context.Context, svc *Service) (uuid.UUID, *Authorization) {
	t.Helper()
	subject := uuid.New()
	row := insertObservedPrincipal(t, ctx, svc, subject)
	obs := directoryObs(subject, authorizationDatabaseTime(t, ctx, svc), true)
	if err := applyAuthorizationObservation(ctx, svc, row.ID, obs); err != nil {
		t.Fatal(err)
	}
	return subject, authorizationFromSnapshot(t, ctx, svc, row.ID)
}

// These package-private fixtures exercise the PostgreSQL fence, not issuance.
// The maintained real-Keycloak smoke separately exercises AuthorizeFresh.
func authorizationFromSnapshot(t *testing.T, ctx context.Context, svc *Service, actor uuid.UUID) *Authorization {
	t.Helper()
	snap, err := svc.loadSnapshot(ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Enabled || !snap.Qualified || snap.Deactivated || snap.AuthorizationRole == "" {
		t.Fatalf("authorization fixture is not qualified: %+v", snap)
	}
	return &Authorization{
		service: svc, actorID: actor, role: snap.AuthorizationRole,
		permission: PermissionRevokeDevice, version: snap.AuthorizationVersion,
		observedAt: snap.ObservedAt, expiresAt: snap.ObservedAt.Add(30 * time.Second),
		monotonicDeadline: time.Now().Add(30 * time.Second),
	}
}

func createAuthorizationEffects(t *testing.T, ctx context.Context, conn *pgx.Conn) {
	t.Helper()
	if _, err := conn.Exec(ctx, `CREATE TABLE lindm_test_authorized_effects (id uuid PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
}

func commitAuthorizedEffect(ctx context.Context, svc *Service, grant *Authorization, effect uuid.UUID, permission Permission) error {
	tx, err := svc.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if err := svc.LockAuthorization(ctx, tx, grant, permission); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO lindm_test_authorized_effects (id) VALUES ($1)`, effect); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func assertAuthorizationEffect(t *testing.T, ctx context.Context, conn *pgx.Conn, svc *Service, grant *Authorization, want error) {
	t.Helper()
	effect := uuid.New()
	err := commitAuthorizedEffect(ctx, svc, grant, effect, PermissionRevokeDevice)
	if !errors.Is(err, want) {
		t.Fatalf("gated effect error = %v, want %v", err, want)
	}
	count := 0
	if want == nil {
		count = 1
	}
	assertAuthorizationEffectCount(t, ctx, conn, effect, count)
}

func assertAuthorizationEffectCount(t *testing.T, ctx context.Context, conn *pgx.Conn, effect uuid.UUID, want int) {
	t.Helper()
	var count int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM lindm_test_authorized_effects WHERE id = $1`, effect).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("durable gated effect count = %d, want %d", count, want)
	}
}

func cleanupAuthorizationTx(t *testing.T, tx pgx.Tx) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error(err)
		}
	})
}

func waitForAuthorizationBlock(t *testing.T, ctx context.Context, svc *Service, blocker int32, result <-chan error) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := svc.pool.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_stat_activity WHERE $1::integer = ANY(pg_blocking_pids(pid))
		)`, blocker).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case err := <-result:
			t.Fatalf("competing operation completed before the principal fence released: %v", err)
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}
