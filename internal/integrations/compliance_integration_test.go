//go:build integration

package integrations

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"lindm/internal/testdb"
)

func TestComplianceEventsAtomicDependenciesAndStaleness(t *testing.T) {
	pool, _ := testdb.Open(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	actor, device, generation, assignment := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	root, child, grandchild := uuid.New(), uuid.New(), uuid.New()
	complianceExec(t, ctx, pool, "INSERT INTO principals(id,issuer,subject) VALUES($1,'local',$2)", actor, actor.String())
	complianceExec(t, ctx, pool, "INSERT INTO devices(id,state,enrolled_at) VALUES($1,'active',clock_timestamp())", device)
	complianceExec(t, ctx, pool, "INSERT INTO enrollment_generations(id,device_id,state,created_at) VALUES($1,$2,'active',clock_timestamp())", generation, device)
	complianceExec(t, ctx, pool, "UPDATE devices SET current_generation_id=$2 WHERE id=$1", device, generation)
	complianceExec(t, ctx, pool, "INSERT INTO resource_assignments(id,device_id,generation_id,request_id,request_digest,actor_id,authorization_version,document,assigned_at) VALUES($1,$2,$3,$4,$5,$6,1,$7,clock_timestamp())", assignment, device, generation, uuid.New(), make([]byte, 32), actor, []byte{1})
	for index, resource := range []uuid.UUID{root, child, grandchild} {
		dependencies := []uuid.UUID{}
		if index == 1 {
			dependencies = []uuid.UUID{root}
		}
		if index == 2 {
			dependencies = []uuid.UUID{child}
		}
		complianceExec(t, ctx, pool, "INSERT INTO resource_assignment_resources(assignment_id,resource_id,resource_kind,canonical_key,position,document,depends_on) VALUES($1,$2,1,$3,$4,$5,$6)", assignment, resource, resource.String()+".service", index, []byte{1}, dependencies)
	}
	complianceExec(t, ctx, pool, "INSERT INTO resource_assignment_heads(generation_id,assignment_id) VALUES($1,$2)", generation, assignment)
	complianceExec(t, ctx, pool, "INSERT INTO audit_events(actor_id,action,resource_id,reason) VALUES($1,'resource_assignment.assign',$2,'assign')", actor, assignment.String())
	assertComplianceStates(t, ctx, pool, assignment, "unknown", 3)
	var before int64
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM integration_events").Scan(&before); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "UPDATE resource_assignment_resources SET disposition=4 WHERE assignment_id=$1 AND resource_id=$2", assignment, root); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "INSERT INTO audit_events(actor_id,action,resource_id,reason) VALUES($1,'resource_assignment.update',$2,'rollback')", actor, assignment.String()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	assertComplianceStates(t, ctx, pool, assignment, "unknown", 3)
	var after int64
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM integration_events").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("rolled-back state emitted outbox events: %d -> %d", before, after)
	}

	complianceExec(t, ctx, pool, "UPDATE resource_assignment_resources SET disposition=4 WHERE assignment_id=$1 AND resource_id=$2", assignment, root)
	complianceExec(t, ctx, pool, "INSERT INTO audit_events(actor_id,action,resource_id,reason) VALUES($1,'resource_assignment.update',$2,'dependency failed')", actor, assignment.String())
	assertComplianceStates(t, ctx, pool, assignment, "attention", 3)
	// A running dependency does not inherit attention: propagation traverses
	// only pending nodes, matching the public Kahn-ordered state projection.
	complianceExec(t, ctx, pool, "UPDATE resource_assignment_resources SET disposition=2 WHERE assignment_id=$1 AND resource_id=$2", assignment, child)
	complianceExec(t, ctx, pool, "SELECT integration_refresh_compliance($1,clock_timestamp(),NULL)", assignment)
	assertComplianceStates(t, ctx, pool, assignment, "attention", 1)
	assertComplianceStates(t, ctx, pool, assignment, "unknown", 2)

	complianceExec(t, ctx, pool, "UPDATE resource_assignment_resources SET disposition=3,last_verified_at=clock_timestamp() WHERE assignment_id=$1", assignment)
	complianceExec(t, ctx, pool, "SELECT integration_refresh_compliance($1,clock_timestamp(),NULL)", assignment)
	assertComplianceStates(t, ctx, pool, assignment, "compliant", 3)
	complianceExec(t, ctx, pool, "UPDATE resource_assignment_resources SET last_verified_at=clock_timestamp()-interval '1 hour' WHERE assignment_id=$1", assignment)
	complianceExec(t, ctx, pool, "UPDATE integration_compliance_states SET stale_at=clock_timestamp()-interval '1 second' WHERE assignment_id=$1", assignment)
	complianceExec(t, ctx, pool, "SELECT integration_refresh_due_compliance()")
	assertComplianceStates(t, ctx, pool, assignment, "stale", 3)
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action='compliance.state.changed'").Scan(&before); err != nil {
		t.Fatal(err)
	}
	complianceExec(t, ctx, pool, "SELECT integration_refresh_due_compliance()")
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action='compliance.state.changed'").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("unchanged stale resources emitted duplicate transitions")
	}
}

func complianceExec(t *testing.T, ctx context.Context, pool *pgxpool.Pool, query string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(ctx, query, args...); err != nil {
		t.Fatal(err)
	}
}

func assertComplianceStates(t *testing.T, ctx context.Context, pool *pgxpool.Pool, assignment uuid.UUID, state string, want int64) {
	t.Helper()
	var count int64
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM integration_compliance_states WHERE assignment_id=$1 AND state=$2", assignment, state).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("%s resources = %d, want %d", state, count, want)
	}
}
