// SPDX-License-Identifier: Apache-2.0

//go:build integration

package serverops

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"lindm/db"
	"lindm/internal/testdb"
)

func TestRecoveryMetadataRuntimeDenialAndAuthorityInvalidation(t *testing.T) {
	pool, _ := testdb.Open(t)
	ctx := t.Context()
	if err := db.Check(ctx, pool); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Exercise all real cancellation statements, including the first-run tables;
	// no successful empty mock transaction can hide missing schema or SQL drift.
	if err = invalidateRestoredAuthority(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	// Match the migration ACL regression's existing, non-owner probe role.
	// The fixture intentionally cannot create cluster-wide roles. Limit every
	// grant to its disposable schema, never the shared public schema.
	const role = "pg_monitor"
	var schema string
	if err = pool.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, "GRANT USAGE ON SCHEMA "+pgx.Identifier{schema}.Sanitize()+" TO "+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	// pg_restore --no-acl is followed by broad normal-table grants. Deliberately
	// seed that unsafe metadata state, then assert the production restriction.
	if _, err = pool.Exec(ctx, "GRANT ALL ON ALL TABLES IN SCHEMA "+pgx.Identifier{schema}.Sanitize()+" TO "+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if err = restrictRestoredMetadata(ctx, pool, role); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"goose_db_version", "lindm_schema_compatibility", "server_recovery_state", "first_run_setup"} {
		var selectAllowed, insertAllowed, updateAllowed, deleteAllowed, truncateAllowed, referencesAllowed, triggerAllowed bool
		if err = pool.QueryRow(ctx, "SELECT has_table_privilege($1,$2,'SELECT'),has_table_privilege($1,$2,'INSERT'),has_table_privilege($1,$2,'UPDATE'),has_table_privilege($1,$2,'DELETE'),has_table_privilege($1,$2,'TRUNCATE'),has_table_privilege($1,$2,'REFERENCES'),has_table_privilege($1,$2,'TRIGGER')", role, pgx.Identifier{schema, table}.Sanitize()).Scan(&selectAllowed, &insertAllowed, &updateAllowed, &deleteAllowed, &truncateAllowed, &referencesAllowed, &triggerAllowed); err != nil {
			t.Fatal(err)
		}
		if !selectAllowed || insertAllowed || updateAllowed || deleteAllowed || truncateAllowed || referencesAllowed || triggerAllowed {
			t.Fatalf("incorrect restored metadata ACL on %s", table)
		}
	}
	var accountAllowed, consumedAllowed, expiryAllowed bool
	if err = pool.QueryRow(ctx, "SELECT has_column_privilege($1,$2,'account_id','UPDATE'),has_column_privilege($1,$2,'consumed_at','UPDATE'),has_column_privilege($1,$2,'expires_at','UPDATE')", role, pgx.Identifier{schema, "first_run_setup"}.Sanitize()).Scan(&accountAllowed, &consumedAllowed, &expiryAllowed); err != nil {
		t.Fatal(err)
	}
	if !accountAllowed || !consumedAllowed || expiryAllowed {
		t.Fatal("restore changed special first-run metadata privileges")
	}
}

func TestRecoveryHoldDatabaseGate(t *testing.T) {
	pool, _ := testdb.Open(t)
	ctx := t.Context()
	if err := commitCheckpointHold(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := CheckRestoreHoldPool(ctx, pool); !errors.Is(err, ErrRestoreHold) {
		t.Fatalf("database hold was not enforced: %v", err)
	}
}

func TestBackupMigratorTargetAndProtectedLedgerSequence(t *testing.T) {
	migrator, _ := testdb.Open(t)
	other, _ := testdb.Open(t)
	ctx := t.Context()
	if err := checkBackupDatabaseTarget(ctx, migrator, migrator); err != nil {
		t.Fatal(err)
	}
	if err := checkBackupDatabaseTarget(ctx, migrator, other); err == nil || err.Error() != "operations: backup_migrator_target_mismatch" {
		t.Fatalf("backup admitted a different application schema: %v", err)
	}
	var schema string
	if err := migrator.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	var runtimeAllowed, migratorAllowed bool
	sequence := pgx.Identifier{schema, "goose_db_version_id_seq"}.Sanitize()
	if err := migrator.QueryRow(ctx, "SELECT has_sequence_privilege('pg_monitor',$1,'SELECT'),has_sequence_privilege(current_user,$1,'SELECT')", sequence).Scan(&runtimeAllowed, &migratorAllowed); err != nil {
		t.Fatal(err)
	}
	if runtimeAllowed || !migratorAllowed {
		t.Fatal("backup must use the migrator without exposing the ledger sequence to runtime")
	}
}
