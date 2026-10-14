// SPDX-License-Identifier: Apache-2.0

//go:build integration

package testdb

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// A cached migration snapshot must not share rows, sequences, identity defaults,
// foreign-key targets or immutable-audit triggers between disposable schemas.
func TestMigrationFixturesRemainIndependent(t *testing.T) {
	first, firstConn := Open(t)
	second, secondConn := Open(t)
	ctx := t.Context()
	var firstDeployment, secondDeployment, firstChain, secondChain uuid.UUID
	if err := first.QueryRow(ctx, "SELECT deployment_id FROM deployment_identity").Scan(&firstDeployment); err != nil {
		t.Fatal(err)
	}
	if err := second.QueryRow(ctx, "SELECT deployment_id FROM deployment_identity").Scan(&secondDeployment); err != nil {
		t.Fatal(err)
	}
	if err := first.QueryRow(ctx, "SELECT chain_id FROM report_audit_head").Scan(&firstChain); err != nil {
		t.Fatal(err)
	}
	if err := second.QueryRow(ctx, "SELECT chain_id FROM report_audit_head").Scan(&secondChain); err != nil {
		t.Fatal(err)
	}
	if firstDeployment == secondDeployment || firstChain == secondChain {
		t.Fatal("migration snapshot reused volatile identity defaults")
	}
	principal := uuid.New()
	if _, err := firstConn.Exec(ctx, "INSERT INTO principals(id,issuer,subject,pinned_role) VALUES($1,'fixture','fixture','owner')", principal); err != nil {
		t.Fatal(err)
	}
	if _, err := secondConn.Exec(ctx, "INSERT INTO local_accounts(id,username,role) VALUES($1,'foreign','owner')", principal); err == nil {
		t.Fatal("restored foreign key refers to another fixture's principals")
	} else {
		var postgres *pgconn.PgError
		if !errors.As(err, &postgres) || postgres.Code != "23503" {
			t.Fatalf("foreign-key rejection: %v", err)
		}
	}
	appendAudit := func(connectionName string, insert func() (int64, error)) {
		t.Helper()
		sequence, err := insert()
		if err != nil || sequence != 1 {
			t.Fatalf("%s audit sequence = %d: %v", connectionName, sequence, err)
		}
	}
	appendAudit("first", func() (int64, error) {
		var sequence int64
		_, err := firstConn.Exec(ctx, "INSERT INTO audit_events(action,resource_id) VALUES('fixture.first','first')")
		if err == nil {
			err = first.QueryRow(ctx, "SELECT sequence FROM integration_events").Scan(&sequence)
		}
		return sequence, err
	})
	var secondCount int
	if err := second.QueryRow(ctx, "SELECT count(*) FROM integration_events").Scan(&secondCount); err != nil || secondCount != 0 {
		t.Fatalf("first audit leaked to second fixture: %d %v", secondCount, err)
	}
	appendAudit("second", func() (int64, error) {
		var sequence int64
		_, err := secondConn.Exec(ctx, "INSERT INTO audit_events(action,resource_id) VALUES('fixture.second','second')")
		if err == nil {
			err = second.QueryRow(ctx, "SELECT sequence FROM integration_events").Scan(&sequence)
		}
		return sequence, err
	})
	if _, err := secondConn.Exec(ctx, "UPDATE integration_events SET resource_id='modified'"); err == nil {
		t.Fatal("restored immutable-audit trigger did not reject mutation")
	}
}
