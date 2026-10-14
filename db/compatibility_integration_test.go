// SPDX-License-Identifier: Apache-2.0

//go:build integration

package db_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"lindm/db"
	"lindm/internal/testdb"
)

func TestPreflightReadsMigratedDatabaseWithoutDDL(t *testing.T) {
	pool, _ := testdb.Open(t)
	cfg := pool.Config()
	cfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	readOnly, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	var transactionReadOnly bool
	if err := readOnly.QueryRow(t.Context(), "SELECT current_setting('transaction_read_only')::boolean").Scan(&transactionReadOnly); err != nil {
		t.Fatal(err)
	}
	if !transactionReadOnly {
		t.Fatal("preflight test connection is not read-only")
	}
	status, err := db.Preflight(t.Context(), readOnly)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Compatible || !status.Online || status.Current != status.Target || len(status.Pending) != 0 || status.Floor <= 0 {
		t.Fatalf("fully migrated preflight = %+v", status)
	}
	if err := db.Check(t.Context(), readOnly); err != nil {
		t.Fatal(err)
	}
}

func TestSchemaRejectsHistoryNotDeclaredByMigrator(t *testing.T) {
	pool, _ := testdb.Open(t)
	status, err := db.Preflight(t.Context(), pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), "INSERT INTO goose_db_version(version_id,is_applied) VALUES($1,true)", status.Target+1); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Preflight(t.Context(), pool); err == nil {
		t.Fatal("undeclared newer history passed preflight")
	}
	if err := db.Check(t.Context(), pool); err == nil {
		t.Fatal("undeclared newer history passed startup")
	}
}

func TestSchemaAdmitsDeclaredExpandButRefusesContractRollback(t *testing.T) {
	pool, _ := testdb.Open(t)
	initial, err := db.Preflight(t.Context(), pool)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Rollback(t.Context()); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error(err)
		}
	}()
	if _, err := tx.Exec(t.Context(), "INSERT INTO goose_db_version(version_id,is_applied) VALUES($1,true)", initial.Target+1); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), "UPDATE lindm_schema_compatibility SET migration_versions=array_append(migration_versions,$1)", initial.Target+1); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := db.Check(t.Context(), pool); err != nil {
		t.Fatalf("declared compatible expansion refused: %v", err)
	}
	if _, err := pool.Exec(t.Context(), "UPDATE lindm_schema_compatibility SET minimum_runtime_version=$1", initial.Target+1); err != nil {
		t.Fatal(err)
	}
	status, err := db.Preflight(t.Context(), pool)
	if err != nil {
		t.Fatal(err)
	}
	if status.Compatible {
		t.Fatal("contract beyond this binary admitted rollback")
	}
	if err := db.Check(t.Context(), pool); err == nil {
		t.Fatal("contract beyond this binary admitted startup")
	}
}

func TestSchemaRejectsRevertedEmbeddedMigration(t *testing.T) {
	pool, _ := testdb.Open(t)
	status, err := db.Preflight(t.Context(), pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), "INSERT INTO goose_db_version(version_id,is_applied) VALUES($1,false)", status.Target); err != nil {
		t.Fatal(err)
	}
	if err := db.Check(t.Context(), pool); err == nil {
		t.Fatal("reverted embedded migration admitted startup")
	}
}

func TestCompatibilityMigrationRevokesInheritedNonOwnerDML(t *testing.T) {
	pool, _ := testdb.Open(t)
	schema := "lindm_policy_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := pool.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := pool.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	// pg_monitor is an existing non-owner role, not a deployment role-name
	// assumption. It has no inherent DML authority on application tables.
	if _, err := pool.Exec(t.Context(), "ALTER DEFAULT PRIVILEGES IN SCHEMA "+pgx.Identifier{schema}.Sanitize()+" GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO pg_monitor"); err != nil {
		t.Fatal(err)
	}
	cfg := pool.Config()
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	migrator, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer migrator.Close()
	if err := db.Migrate(t.Context(), migrator); err != nil {
		t.Fatal(err)
	}
	var readable, writable bool
	if err := migrator.QueryRow(t.Context(), "SELECT has_table_privilege('pg_monitor','lindm_schema_compatibility','SELECT'), has_table_privilege('pg_monitor','lindm_schema_compatibility','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')").Scan(&readable, &writable); err != nil {
		t.Fatal(err)
	}
	if !readable || writable {
		t.Fatalf("compatibility table privileges: readable %v writable %v", readable, writable)
	}
}
