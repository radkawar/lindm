package journal

import (
	"context"
	"fmt"
	"strings"

	"lindm/internal/agent/journal/journaldb"
)

// Only reviewed table definitions may be present. In particular, a prior stamp
// on partially installed newer tables is damage, not permission to migrate.
// Checking SQL also rejects removed constraints, foreign indexes and triggers.
func validateJournalSchema(ctx context.Context, db journaldb.DBTX, version int) error {
	expected := map[string]bool{"executor_state": true}
	if version >= trustSchemaVersion {
		expected["execution_trust"] = true
	}
	if version == schemaVersion {
		for _, name := range serviceTableNames {
			expected[name] = true
		}
	}
	rows, err := db.QueryContext(ctx, `SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL`)
	if err != nil {
		return stateReadError(ctx)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var kind, name, ddl string
		if err := rows.Scan(&kind, &name, &ddl); err != nil {
			return stateReadError(ctx)
		}
		if kind != "table" || !expected[name] || normalizeDDL(ddl) != normalizeDDL(journalTableDDL(name)) {
			return ErrRecoveryHold
		}
		delete(expected, name)
	}
	if err := rows.Err(); err != nil {
		return stateReadError(ctx)
	}
	if len(expected) != 0 {
		return ErrRecoveryHold
	}
	return nil
}

var serviceTableNames = [...]string{"service_actions", "service_resource_floors", "service_action_usage"}

func normalizeDDL(ddl string) string {
	return strings.Join(strings.Fields(strings.TrimSuffix(strings.TrimSpace(ddl), ";")), " ")
}

func journalTableDDL(name string) string {
	// schema.sql contains only whole-line comments and semicolon-delimited DDL.
	var source strings.Builder
	for _, line := range strings.Split(schema, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			source.WriteString(line)
			source.WriteByte('\n')
		}
	}
	for _, statement := range strings.Split(source.String(), ";") {
		statement = strings.TrimSpace(statement)
		if strings.HasPrefix(statement, "CREATE TABLE "+name+" (") {
			return statement
		}
	}
	panic("missing reviewed journal table definition")
}

// Both historical versions migrate directly to schema3 in one transaction.
// Authority and configured-trust bytes/revisions are never rewritten. A current
// schema is validation-only: absent rows/tables must not be repaired.
func (s *Store) migrateSchema(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return stateReadError(ctx)
	}
	defer func() { _ = tx.Rollback() }()
	var version int
	if err := tx.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return stateReadError(ctx)
	}
	if version != priorSchemaVersion && version != trustSchemaVersion && version != schemaVersion {
		return ErrRecoveryHold
	}
	if err := validateJournalSchema(ctx, tx, version); err != nil {
		return err
	}
	q := s.queries.WithTx(tx)
	row, err := q.ReadState(ctx)
	if err != nil {
		return stateReadError(ctx)
	}
	if _, err := s.decodeAuthority(row.Revision, row.State); err != nil {
		return err
	}
	if version >= trustSchemaVersion {
		if _, _, err := s.loadExecutionTrust(ctx, q); err != nil {
			return err
		}
	}
	if version == schemaVersion {
		return nil
	}
	if version == priorSchemaVersion {
		encoded, err := s.encodeTrust(unconfiguredExecutionTrust(s.installationID))
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, executionTrustDDL()); err != nil {
			return stateReadError(ctx)
		}
		if err := q.InitializeExecutionTrust(ctx, encoded); err != nil {
			return stateReadError(ctx)
		}
	}
	for _, name := range serviceTableNames {
		if _, err := tx.ExecContext(ctx, journalTableDDL(name)); err != nil {
			return stateReadError(ctx)
		}
	}
	if err := q.InitializeServiceActionUsage(ctx); err != nil {
		return stateReadError(ctx)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		return stateReadError(ctx)
	}
	if err := tx.Commit(); err != nil {
		return stateReadError(ctx)
	}
	return nil
}
